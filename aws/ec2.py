import argh
import itertools
import mock
import s.log
import logging
import boto3
import datetime
import os
import pager
import pool.thread
import re
import s.cached
import s.colors
import s.exceptions
import s.iter
import s.strings
import shell
import shell.conf
import sys
import time
import time


@s.cached.func
def _ec2():
    return boto3.resource('ec2')


def _tags(instance):
    return {x['Key']: x['Value'] for x in (instance.tags or {})}


def _ls_by_ids(*ids):
    return _ec2().instances.filter(Filters=[{'Name': 'instance-id', 'Values': ids}])


def _ls(tags, state='running', first_n=None, last_n=None):
    if isinstance(state, str):
        assert state in ['running', 'stopped', 'terminated', 'all'], 'no such state: ' + state
    else:
        for s in state:
            assert s in ['running', 'stopped', 'terminated', 'all'], 'no such state: ' + state
    if tags and '=' not in tags[0]:
        tags = ('Name=%s' % tags[0],) + tuple(tags[1:])
    filters = [{'Name': 'instance-state-name', 'Values': [state]}] if state != 'all' else []
    if any('*' in tag for tag in tags):
        instances = _ec2().instances.filter(Filters=filters)
        instances = [i for i in instances if _matches(i, tags)]
    else:
        filters += [{'Name': 'tag:%s' % name, 'Values': [value]}
                    for tag in tags
                    for name, value in [tag.split('=')]]
        instances = _ec2().instances.filter(Filters=filters)
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


def _pretty(instance):
    if instance.state['Name'] == 'running':
        color = s.colors.green
    elif instance.state['Name'] == 'pending':
        color = s.colors.cyan
    else:
        color = s.colors.red
    return ' '.join([
        color(_name(instance)),
        instance.instance_type,
        instance.state['Name'],
        instance.public_dns_name or '<no-ip>',
        ','.join([x['GroupName'] for x in instance.security_groups]),
        ' '.join('%s=%s' % (k, v) for k, v in sorted(_tags(instance).items(), key=lambda x: x[0]) if k != 'Name' and v),
        str(instance.meta.data['LaunchTime'])[:16],
    ])

def _name(instance):
    return _tags(instance).get('Name', '<no-name>')


def _name_group(instance):
    return '%s:%s' % (_tags(instance).get('Name', '<no-name>'), instance.instance_id)


def ip(*tags, first_n=None, last_n=None):
    for i in _ls(tags, 'running', first_n, last_n):
        print(i.public_dns_name, flush=True)


def ls(*tags, state='all', first_n=None, last_n=None):
    x = _ls(tags, state, first_n, last_n)
    x = map(_pretty, x)
    x = '\n'.join(x)
    x = s.strings.align(x)
    print(x, flush=True)


def ssh(*tags, first_n=None, last_n=None, quiet=False, script='', yes=False):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    if os.path.isfile(script):
        with open(script) as f:
            script = f.read()
    assert (script and instances) or len(instances) == 1, 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    for i in instances:
        logging.info(_pretty(i))
    cmd = 'ssh -A -o StrictHostKeyChecking=no ubuntu@%s'
    try:
        if script and len(instances) > 1:
            failures = []
            successes = []
            if not yes:
                logging.info('\nwould you like to proceed? y/n\n')
                assert pager.getch() == 'y', 'abort'
            justify = max(len(i.public_dns_name.split('.')[0]) for i in instances)
            def run(instance, color):
                color = getattr(s.colors, color)
                name = (instance.public_dns_name.split('.')[0] + ': ').ljust(justify + 2)
                def fn():
                    try:
                        shell.run(cmd % instance.public_dns_name, 'bash -s',
                                  stdin=script,
                                  callback=lambda x: print(color(x if quiet else name + x), flush=True))
                    except:
                        failures.append(s.colors.red('failure: ') + instance.public_dns_name)
                    else:
                        successes.append(s.colors.green('success: ') + instance.public_dns_name)
                return fn
            pool.thread.wait(*map(run, instances, itertools.cycle(s.colors._colors)))
            logging.info('\nresults:')
            for msg in successes + failures:
                logging.info(' ' + msg)
            if failures:
                sys.exit(1)
        elif script:
            shell.check_call(cmd % instances[0].public_dns_name, 'bash -s', stdin=script)
        else:
            shell.check_call(cmd % instances[0].public_dns_name)
    except:
        sys.exit(1)


def push(src, dst, *tags, first_n=None, last_n=None, name=None, yes=False):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances), 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    logging.info('targeting:')
    for instance in instances:
        logging.info(' %s', _pretty(instance))
    logging.info('going to push:\n%s', s.strings.indent(shell.run('bash', _tar_script(src, name, echo_only=True)), 1))
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    script = _tar_script(src, name)
    failures = []
    successes = []
    justify = max(len(i.public_dns_name.split('.')[0]) for i in instances)
    def run(instance, color):
        color = getattr(s.colors, color)
        name = (instance.public_dns_name.split('.')[0] + ': ').ljust(justify + 2)
        def fn():
            try:
                shell.run('bash', script,
                          '|ssh -o StrictHostKeyChecking=no ubuntu@' + instance.public_dns_name,
                          '"mkdir -p', dst, '&& cd', dst, '&& tar xf -"',
                          callback=lambda x: print(color(name + x), flush=True))
            except:
                failures.append(s.colors.red('failure: ') + instance.public_dns_name)
            else:
                successes.append(s.colors.green('success: ') + instance.public_dns_name)
        return fn
    pool.thread.wait(*map(run, instances, itertools.cycle(s.colors._colors)))
    shell.check_call('rm -rf', os.path.dirname(script))
    logging.info('\nresults:')
    for msg in successes + failures:
        logging.info(' ' + msg)
    if failures:
        sys.exit(1)


def pull(src, dst, *tags, first_n=None, last_n=None, name=None, yes=False):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly one instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    instance = instances[0]
    logging.info('targeting:\n %s', _pretty(instance))
    host = instance.public_dns_name
    script = _tar_script(src, name, echo_only=True)
    cmd = 'cat %(script)s |ssh -o StrictHostKeyChecking=no ubuntu@%(host)s bash -s' % locals()
    logging.info('going to pull:')
    logging.info(s.strings.indent(shell.check_output(cmd), 1))
    shell.check_call('rm -rf', os.path.dirname(script))
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    script = _tar_script(src, name)
    cmd = 'cd %(dst)s && cat %(script)s | ssh -o StrictHostKeyChecking=no ubuntu@%(host)s bash -s | tar xf -' % locals()
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
    instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to stop the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.stop()
        logging.info('stopped: %s', _pretty(i))
    if wait:
        logging.info('waiting for all to stop')
        for i in instances:
            i.wait_until_stopped()

def rm(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot stop all things, specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to terminate the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.terminate()
        logging.info('terminated: %s', _pretty(i))

def _wait_for_ip(*ids):
    instances = _ls_by_ids(*ids)
    for i in instances:
        i.wait_until_running()
    return [i.public_dns_name for i in instances]


def start(*tags, yes=False, first_n=None, last_n=None, ssh=False, wait=False):
    assert tags, 'you cannot start all things, specify some tags'
    instances = _ls(tags, 'stopped', first_n, last_n)
    assert instances, 'didnt find any stopped instances for those tags'
    logging.info('going to start the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.start()
        logging.info('started: %s', _pretty(i))
    if ssh:
        assert len(instances) == 1, s.colors.red('you asked to ssh, but you started more than one instance, so its not gonna happen')
        try:
            for _ in range(10):
                try:
                    return shell.check_call('ssh -o StrictHostKeyChecking=no -A ubuntu@%s' % _wait_for_ip(instances[0].instance_id)[0], echo=True)
                except:
                    time.sleep(1)
            assert False
        except:
            sys.exit(1)
    elif wait:
        logging.info('waiting for all to start')
        for i in instances:
            i.wait_until_running()


def untag(ls_tags, unset_tags, yes=False, first_n=None, last_n=None):
    assert '=' not in unset_tags, 'no "=", just the name of the tag to unset'
    instances = _ls(tuple(ls_tags.split(',')), 'all', first_n, last_n)
    assert instances, 'didnt find any stopped instances for those tags'
    logging.info('going to untag the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    logging.info('with:')
    for x in unset_tags.split(','):
        logging.info(' ' + x)
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        for t in unset_tags.split(','):
            i.create_tags(Tags=[{'Key': t, 'Value': ''}])[0].delete()
            logging.info('untagged: %s', _pretty(i))


def tag(ls_tags, set_tags, yes=False, first_n=None, last_n=None):
    instances = _ls(tuple(ls_tags.split(',')), 'all', first_n, last_n)
    assert instances, 'didnt find any stopped instances for those tags'
    logging.info('going to tag the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    logging.info('with:')
    for x in set_tags.split(','):
        logging.info(' ' + x)
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        for t in set_tags.split(','):
            k, v = t.split('=')
            i.create_tags(Tags=[{'Key': k, 'Value': v}])
            logging.info('tagged: %s', _pretty(i))


def wait(*tags, state='running', yes=False, first_n=None, last_n=None):
    assert state in ['running', 'stopped']
    assert tags, 'you cannot wait for all things, specify some tags'
    instances = _ls(tags, 'all', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to wait the following instances to be %s:', state)
    for i in instances:
        logging.info(' ' + _pretty(i))
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        getattr(i, 'wait_until_%s' % state)()
        logging.info('%s is %s', _pretty(i), state)


def reboot(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot reboot all things, specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to reboot the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    for i in instances:
        i.reboot()
        logging.info('rebooted: %s', _pretty(i))


def _has_wildcard_permission(sg, ip):
    assert '/' not in ip
    for sg_perm in sg.ip_permissions:
        with s.exceptions.ignore(KeyError):
            all_ports = sg_perm['FromPort'] in [0, 1] and sg_perm['ToPort'] == 65535
            matches_ip = any(x['CidrIp'] == ip + '/32' for x in sg_perm['IpRanges'])
            if all_ports and matches_ip:
                return True


def _wildcard_security_groups(ip):
    return [sg for sg in _sgs() if _has_wildcard_permission(sg, ip)]

def sgs():
    for sg in _sgs():
        yield '%s [%s]' % (s.colors.green(sg.group_name), sg.group_id)


def auths(ip):
    for sg in _wildcard_security_groups(ip):
        yield '%s [%s]' % (s.colors.green(sg.group_name), sg.group_id)


def _sgs(names=None):
    sgs = _ec2().security_groups.all()
    if names:
        sgs = [x for x in sgs if x.group_name in names]
    return sgs


def authorize(ip, *names, yes=False):
    assert all(x == '.' or x.isdigit() for x in ip), 'bad ip: %s' % ip
    names = [s.strings.rm_color(x) for x in names]
    sgs = _sgs(names)
    logging.info('going to authorize your ip %s to these groups:', s.colors.yellow(ip))
    if names:
        sgs = [x for x in sgs if x.group_name in names]
    for sg in sgs:
        logging.info(' %s [%s]', sg.group_name, sg.group_id)
    if not yes:
        logging.info('\nwould you like to authorize access to these groups for your ip %s? y/n\n', s.colors.yellow(ip))
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
    logging.info('your ip %s is currently wildcarded to the following security groups:\n', s.colors.yellow(ip))
    for sg in sgs:
        logging.info(' %s [%s]', sg.group_name, sg.group_id)
    if not yes:
        logging.info('\nwould you like to revoke access to these groups for your ip %s? y/n\n', s.colors.yellow(ip))
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
    amis = list(_ec2().images.filter(Owners=['099720109477'],
                                     Filters=[{'Name': 'name',
                                               'Values': ['*%s*' % '*'.join(name_fragments)]},
                                              {'Name': 'architecture',
                                               'Values': ['x86_64']},
                                              {'Name': 'virtualization-type',
                                               'Values': ['hvm']}]))
    for name, xs in s.iter.groupby(amis, key=lambda x: x.name.split('-')[:-1]):
        ami = sorted(xs, key=lambda x: x.creation_date)[-1]
        logging.info('%s %s', s.colors.green(ami.image_id), '-'.join(name))


def keys():
    for key in _ec2().key_pairs.all():
        logging.info(key.name)


def vpcs():
    for vpc in _ec2().vpcs.all():
        logging.info('%s subnets: %s', _name(vpc), ' '.join([x.id for x in vpc.subnets.all()]))


def _subnet(vpc):
    vpcs = list(_ec2().vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': [vpc]}]))
    assert len(vpcs) == 1, vpcs
    subnets = list(vpcs[0].subnets.all())
    assert len(subnets) == 1, subnets
    return subnets[0].id


def _blocks(gigs):
    return [{'DeviceName': '/dev/sda1',
             'Ebs': {'VolumeSize': int(gigs),
                     'DeleteOnTermination': True}}]


_default_init = """#!/usr/bin/python
import time
open('/tmp/cloudinit.log', 'a').write('init %s' % time.time())
"""

@argh.arg('name', help='name of the instance')
@argh.arg('--key', help='key pair name', default=shell.conf.get_or_prompt_pref('key', __file__, message='key pair name'))
@argh.arg('--ami', help='ami id', default=shell.conf.get_or_prompt_pref('ami', __file__, message='ami id'))
@argh.arg('--sg', help='security group name', default=shell.conf.get_or_prompt_pref('sg', __file__, message='security group name'))
@argh.arg('--type', help='instance type', default=shell.conf.get_or_prompt_pref('type', __file__, message='instance type'))
@argh.arg('--vpc', help='vpc name', default=shell.conf.get_or_prompt_pref('vpc', __file__, message='vpc name'))
@argh.arg('--gigs', help='gb capacity of primary disk', default=16)
@argh.arg('--init', help='cloud init string', default=None)
@argh.arg('--num', help='number of instances', default=1)
@argh.arg('--wait', help='wait for state=running', default=False)
@argh.arg('--ssh', help='ssh into the instance', default=False)
def new(**kw):
    owner = shell.run('whoami')
    instances = _ec2().create_instances(UserData=kw['init'] or _default_init,
                                        ImageId=kw['ami'],
                                        MinCount=kw['num'],
                                        MaxCount=kw['num'],
                                        KeyName=kw['key'],
                                        SecurityGroupIds=[x.id for x in _sgs(names=[kw['sg']])],
                                        InstanceType=kw['type'],
                                        SubnetId=_subnet(kw['vpc']),
                                        BlockDeviceMappings=_blocks(kw['gigs']))
    date = str(datetime.datetime.now())
    for n, i in enumerate(instances):
        tags = [{'Key': 'Name', 'Value': kw['name']},
                {'Key': 'owner', 'Value': owner},
                {'Key': 'nth', 'Value': str(n)},
                {'Key': 'num', 'Value': str(kw['num'])},
                {'Key': 'creation-date', 'Value': date}]
        i.create_tags(Tags=tags)
        logging.info('tagged: %s', _pretty(i))
    if kw['ssh']:
        assert len(instances) == 1, s.colors.red('you asked to ssh, but you started more than one instance, so its not gonna happen')
        try:
            for _ in range(10):
                try:
                    return shell.check_call('ssh -o StrictHostKeyChecking=no -A ubuntu@%s' % _wait_for_ip(instances[0].instance_id)[0], echo=True)
                except:
                    time.sleep(1)
            assert False
        except:
            sys.exit(1)
    elif kw['wait']:
        logging.info('waiting for all to start')
        for i in instances:
            i.wait_until_running()


def main():
    shell.ignore_closed_pipes()
    s.log.setup(format='%(message)s')
    with s.log.disable('botocore', 'boto3'):
        try:
            stream = s.hacks.override('--stream')
            with (shell.set_stream() if stream else mock.MagicMock()):
                shell.dispatch_commands(globals(), __name__)
        except AssertionError as e:
            if e.args:
                logging.info(s.colors.red(e.args[0]))
            sys.exit(1)
