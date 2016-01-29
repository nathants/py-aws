import boto3
import botocore.exceptions
import datetime
import itertools
import logging
import os
import pager
import pool.thread
import pprint
import random
import re
import shell
import shell.conf
import subprocess
import sys
import time
import util.cached
import util.colors
import util.dicts
import util.exceptions
import util.iter
import util.log
import util.strings
import util.time
from unittest import mock


is_cli = False


util.log.setup(format='%(message)s')


ssh_args = ' -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no '


def _retry(f):
    """
    retry and idempotent fn a few times
    """
    def fn(*a, **kw):
        for i in range(4):
            try:
                return f(*a, **kw)
            except Exception as e:
                if i == 3:
                    raise e
                time.sleep(i + random.random())
    return fn


@util.cached.func
def _resource():
    return boto3.resource('ec2')


@util.cached.func
def _client():
    return boto3.client('ec2')


def _tags(instance):
    return {x['Key']: x['Value'] for x in (instance.tags or {})}


# TODO cache wildcard looks. they are too slow. ping host and lookup for real on miss.
def _ls(tags, state='running', first_n=None, last_n=None):
    if isinstance(state, str):
        assert state in ['running', 'stopped', 'terminated', 'all'], 'no such state: ' + state
        state = [state]
    else:
        for s in state:
            assert s in ['running', 'stopped', 'terminated', 'all'], 'no such state: ' + state
    is_dns_name = tags and tags[0].endswith('.amazonaws.com')
    is_instance_id = tags and re.search(r'i\-[a-zA-Z0-9]{8}', tags[0])
    if tags and not is_dns_name and not is_instance_id and '=' not in tags[0]:
        tags = ('Name=%s' % tags[0],) + tuple(tags[1:])
    filters = [{'Name': 'instance-state-name', 'Values': state}] if state[0] != 'all' else []
    if is_dns_name:
        filters += [{'Name': 'dns-name', 'Values': tags}]
        instances = _resource().instances.filter(Filters=filters)
    elif is_instance_id:
        filters += [{'Name': 'instance-id', 'Values': tags}]
        instances = _resource().instances.filter(Filters=filters)
    elif any('*' in tag for tag in tags):
        instances = _resource().instances.filter(Filters=filters)
        instances = [i for i in instances if _matches(i, tags)]
    else:
        filters += [{'Name': 'tag:%s' % name, 'Values': [value]}
                    for tag in tags
                    for name, value in [tag.split('=')]]
        instances = _resource().instances.filter(Filters=filters)
    instances = sorted(instances, key=_name_group)
    instances = sorted(instances, key=lambda i: i.meta.data['LaunchTime'], reverse=True)
    if first_n:
        instances = instances[:int(first_n)]
    elif last_n:
        instances = instances[-int(last_n):]
    return instances


def _matches(instance, tags):
    for tag in tags:
        assert '=' in tag, 'tags are specified as "<key>=<value>", not: %s' % tag
        k, v = tag.split('=')
        t = _tags(instance).get(k, '').lower()
        v = v.lower()
        if v[0] == v[-1] == '*':
            if v.strip('*') not in t:
                return False
        elif v[0] == '*':
            if not t.endswith(v.strip('*')):
                return False
        elif v[-1] == '*':
            if not t.startswith(v.strip('*')):
                return False
        else:
            if t != v:
                return False
    return True


def _pretty(instance, ip=False, all_tags=False):
    if instance.state['Name'] == 'running':
        color = util.colors.green
    elif instance.state['Name'] == 'pending':
        color = util.colors.cyan
    else:
        color = util.colors.red
    return ' '.join(filter(None, [
        color(_name(instance)),
        instance.instance_type,
        instance.state['Name'],
        instance.instance_id,
        (instance.public_dns_name or '<no-ip>' if ip else None),
        ','.join([x['GroupName'] for x in instance.security_groups]),
        ' '.join('%s=%s' % (k, v)
                 for k, v in sorted(_tags(instance).items(), key=lambda x: x[0])
                 if (all_tags or k not in ['Name', 'creation-date', 'owner', 'launch'])
                 and v),
    ]))

def _name(instance):
    return _tags(instance).get('Name', '<no-name>').replace(' ', '_')


def _name_group(instance):
    return '%s:%s' % (_tags(instance).get('Name', '<no-name>'), instance.instance_id)


def ip(*tags, first_n=None, last_n=None):
    return [i.public_dns_name for i in _ls(tags, 'running', first_n, last_n)]


def ip_private(*tags, first_n=None, last_n=None):
    return [i.private_dns_name for i in _ls(tags, 'running', first_n, last_n)]


def ls(*tags, state='all', first_n=None, last_n=None, ip=False, all_tags=False):
    x = _ls(tags, state, first_n, last_n)
    x = map(lambda y: _pretty(y, ip=ip, all_tags=all_tags), x)
    x = '\n'.join(x)
    print(x, flush=True)


def _remote_cmd(cmd):
    # TODO is hygiene more important than debugability? rm $path
    # return "path=/tmp/$(uuidgen); echo %s | base64 -d > $path; bash $path; code=$?; rm $path; exit $code" % util.strings.b64_encode(cmd)
    return "path=/tmp/$(uuidgen); echo %s | base64 -d > $path; bash $path" % util.strings.b64_encode(cmd)


def ssh(*tags, first_n=None, last_n=None, quiet=False, cmd='', yes=False, max_threads=None, timeout=None, no_tty=False, user='ubuntu', key=None, echo=False):
    """
    tty means that when you ^C to exit, the remote processes are killed. this is usually what you want, ie no lingering `tail -f` instances.
    """
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    if os.path.isfile(cmd):
        with open(cmd) as f:
            cmd = f.read()
    assert (cmd and instances) or len(instances) == 1, 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    if not (quiet and yes):
        for i in instances:
            logging.info(_pretty(i))
    ssh_cmd = ('ssh -A' + (' -i {} '.format(key) if key else '') + (' -tt ' if not no_tty or not cmd else ' -T ') + ssh_args).split()
    if echo:
        logging.info('ec2.ssh running against tags: %s, with cmd: %s', tags, cmd)
    if timeout:
        ssh_cmd = ['timeout', '{}s'.format(timeout)] + ssh_cmd
    make_ssh_cmd = lambda instance: ssh_cmd + [user + '@' + instance.public_dns_name, _remote_cmd(cmd)]
    if is_cli and not yes and not (len(instances) == 1 and not cmd):
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    try:
        if cmd and len(instances) > 1:
            failures = []
            successes = []
            def run(instance, color):
                color = (lambda x: x) if quiet else getattr(util.colors, color)
                # TODO is justify actually stupid?
                name = (_name(instance) + ': ' + instance.public_dns_name + ': ')
                def fn():
                    try:
                        cb = lambda x: print(color(x if quiet else name + x).replace('\r', ''), flush=True)
                        shell.run(*make_ssh_cmd(instance),
                                  callback=cb,
                                  raw_cmd=True,
                                  stream=False,
                                  hide_stderr=quiet)
                    except:
                        failures.append(util.colors.red('failure: ') + instance.public_dns_name)
                    else:
                        successes.append(util.colors.green('success: ') + instance.public_dns_name)
                return fn
            pool.thread.wait(*map(run, instances, itertools.cycle(util.colors._colors)), max_threads=max_threads)
            if not quiet:
                logging.info('\nresults:')
                for msg in successes + failures:
                    logging.info(' ' + msg)
            if failures:
                sys.exit(1)
        elif cmd:
            return shell.run(*make_ssh_cmd(instances[0]), echo=False, stream=True, hide_stderr=quiet, raw_cmd=True)
        else:
            subprocess.check_call(ssh_cmd + [user + '@' + instances[0].public_dns_name])
    except:
        sys.exit(1)


def scp(src, dst, *tags, yes=False, max_threads=0):
    assert tags, 'you must specify some tags'
    assert ':' in src + dst, 'you didnt specify a remote path, which starts with ":"'
    instances = _ls(tags, 'running')
    assert instances, 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    logging.info('targeting:')
    for instance in instances:
        logging.info(' %s', _pretty(instance))
    logging.info('going to scp: %s to %s', src, dst)
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    justify = max(len(i.public_dns_name) for i in instances)
    def run(instance, color):
        if color:
            color = getattr(util.colors, color)
        else:
            color = lambda x: x
        name = (instance.public_dns_name + ': ').ljust(justify + 2)
        def fn():
            host = 'ubuntu@' + instance.public_dns_name
            _src = host + src if src.startswith(':') else src
            _dst = host + dst if dst.startswith(':') else dst
            try:
                shell.run('scp', _src, _dst, callback=lambda x: print(color(name + x), flush=True))
            except:
                failures.append(util.colors.red('failure: ') + instance.public_dns_name)
            else:
                successes.append(util.colors.green('success: ') + instance.public_dns_name)
        return fn
    failures = []
    successes = []
    pool.thread.wait(*map(run, instances, itertools.cycle(util.colors._colors) if len(instances) > 1 else [False]), max_threads=max_threads)
    logging.info('\nresults:')
    for msg in successes + failures:
        logging.info(' ' + msg)
    if failures:
        sys.exit(1)


# TODO when one instance only, dont colorize
# TODO stop using bash -s
def push(src, dst, *tags, first_n=None, last_n=None, name=None, yes=False, max_threads=0):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    logging.info('targeting:')
    for instance in instances:
        logging.info(' %s', _pretty(instance))
    logging.info('going to push:\n%s', util.strings.indent(shell.run('bash', _tar_script(src, name, echo_only=True)), 1))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    script = _tar_script(src, name)
    failures = []
    successes = []
    justify = max(len(i.public_dns_name) for i in instances)
    def run(instance, color):
        if color:
            color = getattr(util.colors, color)
        else:
            color = lambda x: x
        name = (instance.public_dns_name + ': ').ljust(justify + 2)
        def fn():
            try:
                shell.run('bash', script,
                          '|ssh', ssh_args, 'ubuntu@' + instance.public_dns_name,
                          '"mkdir -p', dst, '&& cd', dst, '&& tar xf -"',
                          callback=lambda x: print(color(name + x), flush=True))
            except:
                failures.append(util.colors.red('failure: ') + instance.public_dns_name)
            else:
                successes.append(util.colors.green('success: ') + instance.public_dns_name)
        return fn
    pool.thread.wait(*map(run, instances, itertools.cycle(util.colors._colors) if len(instances) > 1 else [False]), max_threads=max_threads)
    shell.check_call('rm -rf', os.path.dirname(script))
    logging.info('\nresults:')
    for msg in successes + failures:
        logging.info(' ' + msg)
    if failures:
        sys.exit(1)


# TODO stop using bash -s
def pull(src, dst, *tags, first_n=None, last_n=None, name=None, yes=False):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly one instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    instance = instances[0]
    logging.info('targeting:\n %s', _pretty(instance))
    host = instance.public_dns_name
    script = _tar_script(src, name, echo_only=True)
    cmd = ('cat %(script)s |ssh' + ssh_args + 'ubuntu@%(host)s bash -s') % locals()
    logging.info('going to pull:')
    logging.info(util.strings.indent(shell.check_output(cmd), 1))
    shell.check_call('rm -rf', os.path.dirname(script))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    script = _tar_script(src, name)
    cmd = ('cd %(dst)s && cat %(script)s | ssh' + ssh_args + 'ubuntu@%(host)s bash -s | tar xf -') % locals()
    try:
        shell.check_call(cmd)
    except:
        logging.info('failure for: %s %s', _name(instance), instance.public_dns_name)
        sys.exit(1)
    finally:
        shell.check_call('rm -rf', os.path.dirname(script))


def _tar_script(src, name, echo_only=False):
    name = ('-name %s' % name) if name else ''
    script = ('cd %(src)s\n'
              'src=$(pwd)\n'
              'cd $(dirname $src)\n'
              "FILES=$(find -L $(basename $src) -type f %(name)s -o -type l %(name)s| grep -v '\.git')\n"
              'echo $FILES|tr " " "\\n" 1>&2\n'
              + ('' if echo_only else 'tar cfh - $FILES')) % locals()
    with shell.tempdir(cleanup=False):
        with open('script.sh', 'w') as f:
            f.write(script)
        return os.path.abspath('script.sh')


def emacs(path, *tags, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly 1 instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    logging.info(_pretty(instances[0]))
    try:
        shell.check_call("nohup emacsclient /ubuntu@{}:{} > /dev/null &".format(instances[0].public_dns_name, path))
    except:
        sys.exit(1)

def mosh(*tags, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly 1 instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    logging.info(_pretty(instances[0]))
    try:
        shell.check_call('mosh ubuntu@%s' % instances[0].public_dns_name)
    except:
        sys.exit(1)


def stop(*tags, yes=False, first_n=None, last_n=None, wait=False):
    assert tags, 'you cannot stop all things, specify some tags'
    instances = _ls(tags, ['running', 'stopped'], first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to stop the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.stop()
        logging.info('stopped: %s', _pretty(i))
    if wait:
        logging.info('waiting for all to stop')
        _wait_until('stopped', *instances)


def rm(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot stop all things, specify some tags'
    instances = _ls(tags, ['running', 'stopped'], first_n, last_n)
    assert instances, 'didnt find any instances for those tags'
    logging.info('going to terminate the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.terminate()
        logging.info('terminated: %s', _pretty(i))


def _ls_by_ids(*ids):
    return _resource().instances.filter(Filters=[{'Name': 'instance-id', 'Values': ids}])


def _wait_until(state, *instances):
    assert state in ['running', 'stopped']
    _client().get_waiter('instance_' + state).wait(InstanceIds=[i.instance_id for i in instances])


def _wait_for_ssh(*instances):
    logging.info('wait for state=running...')
    _wait_until('running', *instances)
    logging.info('wait for ssh...')
    for _ in range(120):
        timeout = 3 + random.random()
        start = time.time()
        try:
            ssh(*[i.instance_id for i in instances], cmd='whoami > /dev/null', yes=True, quiet=True, timeout=timeout)
            for i in instances:
                i.reload()
            assert len(ip(*[i.instance_id for i in instances])) == len(instances) # eventual consistency is the best, you'd think the waiter would have covered this
            return [i.public_dns_name for i in instances]
        except:
            logging.info('trying ssh...')
            time.sleep(max(0, timeout - (time.time() - start)))
    assert False, 'failed to wait for ssh'


def untag(ls_tags, unset_tags, yes=False, first_n=None, last_n=None):
    assert '=' not in unset_tags, 'no "=", just the name of the tag to unset'
    instances = _ls(tuple(ls_tags.split(',')), 'all', first_n, last_n)
    assert instances, 'didnt find any instances for those tags'
    logging.info('going to untag the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    logging.info('with:')
    for x in unset_tags.split(','):
        logging.info(' ' + x)
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        for t in unset_tags.split(','):
            _retry(i.create_tags)(Tags=[{'Key': t, 'Value': ''}])[0].delete()
            logging.info('untagged: %s', _pretty(i))


def tag(ls_tags, set_tags, yes=False, first_n=None, last_n=None):
    instances = _ls(tuple(ls_tags.split(',')), 'all', first_n, last_n)
    assert instances, 'didnt find any instances for those tags'
    logging.info('going to tag the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    logging.info('with:')
    for x in set_tags.split(','):
        logging.info(' ' + x)
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        for t in set_tags.split(','):
            k, v = t.split('=')
            _retry(i.create_tags)(Tags=[{'Key': k, 'Value': v}])
            logging.info('tagged: %s', _pretty(i))


def wait(*tags, state='running', yes=False, first_n=None, last_n=None, ssh=False):
    assert state in ['running', 'stopped']
    assert tags, 'you cannot wait for all things, specify some tags'
    instances = _ls(tags, 'all', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to wait the following instances to be %s:', 'ssh-able' if ssh else state)
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    if ssh:
        _wait_for_ssh(*instances)
    else:
        _wait_until(state, *instances)
        for i in instances:
            logging.info('%s is %s', _pretty(i), state)


def reboot(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot reboot all things, specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to reboot the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.reboot()
        logging.info('rebooted: %s', _pretty(i))


def _has_wildcard_permission(sg, ip):
    assert '/' not in ip
    for sg_perm in sg.ip_permissions:
        with util.exceptions.ignore(KeyError):
            all_ports = sg_perm['FromPort'] in [0, 1] and sg_perm['ToPort'] == 65535
            matches_ip = any(x['CidrIp'] == ip + '/32' for x in sg_perm['IpRanges'])
            if all_ports and matches_ip:
                return True


def _wildcard_security_groups(ip):
    return [sg for sg in _sgs() if _has_wildcard_permission(sg, ip)]

def sgs():
    for sg in _sgs():
        yield '%s [%s]' % (util.colors.green(sg.group_name), sg.group_id)


def auths(ip):
    for sg in _wildcard_security_groups(ip):
        yield '%s [%s]' % (util.colors.green(sg.group_name), sg.group_id)


def _sgs(names=None):
    sgs = _resource().security_groups.all()
    if names:
        sgs = [x for x in sgs if x.group_name in names]
    return sgs


def authorize(ip, *names, yes=False):
    assert all(x == '.' or x.isdigit() for x in ip), 'bad ip: %s' % ip
    names = [util.strings.rm_color(x) for x in names]
    sgs = _sgs(names)
    logging.info('going to authorize your ip %s to these groups:', util.colors.yellow(ip))
    if names:
        sgs = [x for x in sgs if x.group_name in names]
    for sg in sgs:
        logging.info(' %s [%s]', sg.group_name, sg.group_id)
    if is_cli and not yes:
        logging.info('\nwould you like to authorize access to these groups for your ip %s? y/n\n', util.colors.yellow(ip))
        assert pager.getch() == 'y', 'abort'
    with open('/var/log/ec2_auth_ips.log', 'a') as f:
        f.write(ip + '\n')
    for sg in sgs:
        for proto in ['tcp', 'udp']:
            try:
                sg.authorize_ingress(
                    IpProtocol=proto,
                    FromPort=0,
                    ToPort=65535,
                    CidrIp='%s/32' % ip
                )
                logging.info('authorized: %s %s %s', sg.group_name, sg.group_id, proto)
            except Exception as e:
                logging.info('%s: %s %s %s', re.sub(r'.*\((.*)\).*', r'\1', str(e)), sg.group_name, sg.group_id, proto)


def revoke(ip, *names, yes=False):
    assert all(x == '.' or x.isdigit() for x in ip), 'bad ip: %s' % ip
    sgs = _sgs(names) if names else _wildcard_security_groups(ip)
    assert sgs, 'didnt find any security groups'
    logging.info('your ip %s is currently wildcarded to the following security groups:\n', util.colors.yellow(ip))
    for sg in sgs:
        logging.info(' %s [%s]', sg.group_name, sg.group_id)
    if is_cli and not yes:
        logging.info('\nwould you like to revoke access to these groups for your ip %s? y/n\n', util.colors.yellow(ip))
        assert pager.getch() == 'y', 'abort'
    for sg in sgs:
        for proto in ['tcp', 'udp']:
            try:
                sg.revoke_ingress(
                    IpProtocol=proto,
                    FromPort=0,
                    ToPort=65535,
                    CidrIp='%s/32' % ip
                )
                logging.info('revoked: %s %s %s', sg.group_name, sg.group_id, proto)
            except Exception as e:
                logging.info('%s: %s %s %s', re.sub(r'.*\((.*)\).*', r'\1', str(e)), sg.group_name, sg.group_id, proto)


def amis(*name_fragments):
    name_fragments = ('ubuntu/images/',) + name_fragments
    amis = _resource().images.filter(Owners=['self'])
    amis = sorted(amis, key=lambda x: x.creation_date, reverse=True)
    for ami in amis:
        print('%s %s' % (util.colors.green(ami.image_id), ami.name))


def amis_ubuntu(*name_fragments):
    name_fragments = ('ubuntu/images/',) + name_fragments
    amis = list(_resource().images.filter(Owners=['099720109477'],
                                          Filters=[{'Name': 'name',
                                                    'Values': ['*%s*' % '*'.join(name_fragments)]},
                                                   {'Name': 'architecture',
                                                    'Values': ['x86_64']},
                                                   {'Name': 'virtualization-type',
                                                    'Values': ['hvm']}]))
    for name, xs in util.iter.groupby(amis, key=lambda x: x.name.split('-')[:-1]):
        ami = sorted(xs, key=lambda x: x.creation_date)[-1]
        print('%s %s' % (util.colors.green(ami.image_id), '-'.join(name)))


def keys():
    for key in _resource().key_pairs.all():
        logging.info(key.name)


def vpcs():
    for vpc in _resource().vpcs.all():
        logging.info('%s subnets: %s', _name(vpc), ' '.join([x.id for x in vpc.subnets.all()]))


def _subnet(vpc):
    vpcs = list(_resource().vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': [vpc]}]))
    assert len(vpcs) == 1, vpcs
    subnets = list(vpcs[0].subnets.all())
    assert len(subnets) == 1, subnets
    return subnets[0].id


def _blocks(gigs):
    return [{'DeviceName': '/dev/sda1',
             'Ebs': {'VolumeSize': int(gigs),
                     'VolumeType': 'gp2',
                     'DeleteOnTermination': True}}]


def _create_spot_instances(**opts):
    request_ids = [x['SpotInstanceRequestId'] for x in _client().request_spot_instances(**opts)['SpotInstanceRequests']]
    logging.info("wait for spot request to be filled for ids:\n%s", '\n'.join(request_ids))
    for _ in range(300):
        try:
            # TODO need to check here to see if spot request failed
            # with bad params or something, otherwise hangs forever
            # poll instead of waiter?
            # _client().describe_spot_instance_requests(SpotInstanceRequestIds=request_ids)
            _client().get_waiter('spot_instance_request_fulfilled').wait(SpotInstanceRequestIds=request_ids)
            break
        except botocore.exceptions.WaiterError: # fails when spot-request-id does not exist (yet)
            time.sleep(1 + random.random())
    else:
        raise AssertionError('failed to wait for spot requests')
    instance_ids = [x['InstanceId'] for x in _client().describe_spot_instance_requests(SpotInstanceRequestIds=request_ids)['SpotInstanceRequests']]
    logging.info('request fulfilled with instance-ids:\n%s', '\n'.join(instance_ids))
    logging.info('wait for instances...')
    _client().get_waiter('instance_running').wait(InstanceIds=instance_ids)
    instances = _ls(instance_ids)
    assert len(instances) == opts['InstanceCount'], 'num instances: %s != %s' % (len(instances), opts['InstanceCount'])
    return instances


def _make_spot_opts(spot, **opts):
    spot_opts = {}
    spot_opts['SpotPrice'] = str(float(spot))
    spot_opts['InstanceCount'] = opts['MaxCount']
    specs = ['ImageId', 'KeyName', 'SecurityGroupIds', 'UserData', 'BlockDeviceMappings', 'SubnetId', 'InstanceType']
    spot_opts['LaunchSpecification'] = specs = util.dicts.take(opts, specs)
    spot_opts = util.dicts.update_in(spot_opts, ['LaunchSpecification', 'UserData'], util.strings.b64_encode)
    return spot_opts


def new(name:  'name of the instance',
        *tags: 'tags to set as "<key>=<value>"',
        key:   'key pair name'               = shell.conf.get_or_prompt_pref('key',  __file__, message='key pair name'),
        ami:   'ami id'                      = shell.conf.get_or_prompt_pref('ami',  __file__, message='ami id'),
        sg:    'security group name'         = shell.conf.get_or_prompt_pref('sg',   __file__, message='security group name'),
        type:  'instance type'               = shell.conf.get_or_prompt_pref('type', __file__, message='instance type'),
        vpc:   'vpc name'                    = shell.conf.get_or_prompt_pref('vpc',  __file__, message='vpc name'),
        gigs:  'gb capacity of primary disk' = 16,
        init:  'cloud init command'          = 'date > /tmp/cloudinit.log',
        cmd:   'ssh command'                 = None,
        num:   'number of instances'         = 1,
        spot:  'spot price to bid'           = None,
        tty:   'run cmd in a tty'            = False,
        login: 'login into the instance'     = False):
    assert not (spot and type.startswith('t2.')), 't2.* instances cant use spot pricing'
    if vpc.lower() == 'none':
        vpc = None
    assert not login or num == 1, util.colors.red('you asked to login, but you are starting more than one instance, so its not gonna happen')
    owner = shell.run('whoami')
    for tag in tags:
        assert '=' in tag, 'bad tag, should be key=value, not: %s' % tag
    # TODO being root is not ideal. sudo -u ubuntu ...
    assert not init.startswith('#!'), 'init commands are bash snippets, and should not include a hashbang'
    init = '#!/bin/bash\n' + init
    opts = {}
    opts['UserData'] = init
    opts['ImageId'] = ami
    opts['MinCount'] = num
    opts['MaxCount'] = num
    opts['KeyName'] = key
    opts['SecurityGroupIds'] = [x.id for x in _sgs(names=[sg])]
    opts['InstanceType'] = type
    opts['BlockDeviceMappings'] = _blocks(gigs)
    if vpc:
        opts['SubnetId'] = _subnet(vpc)
    if spot:
        spot_opts = _make_spot_opts(spot, **opts)
        logging.info('request spot instances:\n' + pprint.pformat(util.dicts.drop_in(spot_opts, ['LaunchSpecification', 'UserData'])))
        instances = _create_spot_instances(**spot_opts)
    else:
        logging.info('create instances:\n' + pprint.pformat(util.dicts.drop(opts, ['UserData'])))
        instances = _resource().create_instances(**opts)
    print('instances:', [i.instance_id for i in instances])
    date = str(datetime.datetime.now()).replace(' ', 'T')
    for n, i in enumerate(instances):
        set_tags = [{'Key': 'Name', 'Value': name},
                    {'Key': 'owner', 'Value': owner},
                    {'Key': 'creation-date', 'Value': date}]
        if len(instances) > 1:
            set_tags += [{'Key': 'nth', 'Value': str(n)},
                         {'Key': 'num', 'Value': str(num)}]
        for tag in tags:
            k, v = tag.split('=')
            set_tags.append({'Key': k, 'Value': v})
        _retry(i.create_tags)(Tags=set_tags)
        logging.info('tagged: %s', _pretty(i))
    _wait_for_ssh(*instances)
    if login:
        logging.info('logging in...')
        ssh(instances[0].instance_id, yes=True, quiet=True)
    elif cmd:
        logging.info('running cmd...')
        ssh(*[i.instance_id for i in instances], yes=True, cmd=cmd, no_tty=not tty)
    logging.info('done')
    return [i.instance_id for i in instances]


def _zones():
    return [x['ZoneName'] for x in _client().describe_availability_zones()['AvailabilityZones']]


def spot_price(type, region='us-east-1a', slice=20):
    prices = [_client().describe_spot_price_history(InstanceTypes=[type], AvailabilityZone=zone)['SpotPriceHistory'][:slice] for zone in _zones()]
    prices = list(zip(*prices))
    val = ''
    val += ' '.join(('type', 'time', ' '.join([p['AvailabilityZone'] for p in prices[0]]))) + '\n'
    for pp in prices:
        val += ' '.join((type,
                         str(pp[0]['Timestamp']).split('+')[0].replace(' ', 'T')[:-3],
                         ' '.join(['%.3f' % float(p['SpotPrice']) for p in pp]))) + '\n'
    print(util.strings.align(val))


def start(*tags, yes=False, first_n=None, last_n=None, ssh=False, wait=False):
    assert tags, 'you cannot start all things, specify some tags'
    instances = _ls(tags, 'stopped', first_n, last_n)
    assert instances, 'didnt find any stopped instances for those tags'
    logging.info('going to start the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.start()
        logging.info('started: %s', _pretty(i))
    if ssh:
        assert len(instances) == 1, util.colors.red('you asked to ssh, but you started more than one instance, so its not gonna happen')
        instances[0].wait_until_running()
        try:
            shell.check_call('ssh -A' + ssh_args + 'ubuntu@%s' % _wait_for_ssh(*instances)[0], echo=True)
        except:
            sys.exit(1)
    elif wait:
        logging.info('waiting for all to start')
        for i in instances:
            i.wait_until_running()


def ami(*tags, yes=False, first_n=None, last_n=None, no_wait=False, name=None, description=None, no_append_date=False):
    assert name, 'you must provide a name'
    if not description:
        description = name
    if not no_append_date:
        name += '-' + str(datetime.datetime.utcnow()).replace(' ', 'T').split('.')[0].replace(':', '-') + 'Z'
    assert tags, 'you must specify some tags'
    instances = _ls(tags, ['running', 'stopped'], first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly one instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    instance = instances[0]
    instance.stop()
    _wait_until('stopped', instance)
    logging.info('going to image the following instance:')
    logging.info(' ' + _pretty(instance))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    ami_id = instance.create_image(Name=name, Description=description).image_id
    if not no_wait:
        logging.info('wait for image...')
        _client().get_waiter('image_available').wait(ImageIds=[ami_id])
    return ami_id


def main():
    globals()['is_cli'] = True
    shell.ignore_closed_pipes()
    with util.log.disable('botocore', 'boto3'):
        try:
            stream = util.hacks.override('--stream')
            with (shell.set_stream() if stream else mock.MagicMock()):
                shell.dispatch_commands(globals(), __name__)
        except AssertionError as e:
            if e.args:
                logging.info(util.colors.red(e.args[0]))
            sys.exit(1)
