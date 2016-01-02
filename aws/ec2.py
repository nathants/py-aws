import argh
import boto3
import datetime
import itertools
import logging
import mock
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
import traceback
import uuid
import util.cached
import util.colors
import util.dicts
import util.exceptions
import util.iter
import util.log
import util.strings
import util.time


util.log.setup(format='%(message)s')


ssh_args = ' -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no '


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


def _pretty(instance):
    if instance.state['Name'] == 'running':
        color = util.colors.green
    elif instance.state['Name'] == 'pending':
        color = util.colors.cyan
    else:
        color = util.colors.red
    return ' '.join([
        color(_name(instance)),
        instance.instance_type,
        instance.state['Name'],
        instance.instance_id,
        instance.public_dns_name or '<no-ip>',
        ','.join([x['GroupName'] for x in instance.security_groups]),
        ' '.join('%s=%s' % (k, v)
                 for k, v in sorted(_tags(instance).items(), key=lambda x: x[0])
                 if k not in ['Name', 'creation-date']
                 and v),
    ])

def _name(instance):
    return _tags(instance).get('Name', '<no-name>').replace(' ', '_')


def _name_group(instance):
    return '%s:%s' % (_tags(instance).get('Name', '<no-name>'), instance.instance_id)


def ip(*tags, first_n=None, last_n=None):
    for i in _ls(tags, 'running', first_n, last_n):
        print(i.public_dns_name, flush=True)


def ls(*tags, state='all', first_n=None, last_n=None):
    x = _ls(tags, state, first_n, last_n)
    x = map(_pretty, x)
    x = '\n'.join(x)
    x = util.strings.align(x)
    print(x, flush=True)


def _remote_cmd(cmd):
    # TODO is hygiene more important than debugability? rm $path
    # return "path=/tmp/$(uuidgen); echo %s | base64 -d > $path; bash $path; code=$?; rm $path; exit $code" % util.strings.b64_encode(cmd)
    return "path=/tmp/$(uuidgen); echo %s | base64 -d > $path; bash $path" % util.strings.b64_encode(cmd)


def ssh(*tags, first_n=None, last_n=None, quiet=False, cmd='', yes=False, max_threads=None, timeout=None, no_tty=False):
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
    ssh_cmd = ('ssh -A ' + ('-tt' if not no_tty or not cmd else '-T') + ssh_args).split()
    if timeout:
        ssh_cmd = ['timeout', '{}s'.format(timeout)] + ssh_cmd
    if not yes and not (len(instances) == 1 and not cmd):
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
                        shell.run(*(ssh_cmd + ['ubuntu@' + instance.public_dns_name, _remote_cmd(cmd), '2>/dev/null']),
                                  callback=lambda x: print(color(x if quiet else name + x).replace('\r', ''), flush=True),
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
            shell.run(*(ssh_cmd + ['ubuntu@' + instances[0].public_dns_name, _remote_cmd(cmd)]), echo=False, stream=True, hide_stderr=quiet, raw_cmd=True)
        else:
            subprocess.check_call(ssh_cmd + ['ubuntu@' + instances[0].public_dns_name])
    except:
        sys.exit(1)


def _launch_cmd(arg, cmd, no_rm, bucket):
    # TODO how to make this more understandable?
    if callable(cmd):
        _cmd = cmd(str(arg))
    else:
        _cmd = cmd % {'arg': arg}
    upload_logs = 'aws s3 cp ~/nohup.out s3://%(bucket)s/ec2_logs/%(user)s/%(date)s_%(tags)s_%(ip)s >/dev/null 2>&1' % {
        'bucket': bucket,
        'user': os.environ['USER'],
        'date': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
        'ip': '$(curl http://169.254.169.254/latest/meta-data/public-hostname/ 2>/dev/null)',
        'tags': '$(aws ec2 describe-tags --filters "Name=resource-id,Values=$(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)"|python3 -c \'import sys, json; print(",".join(["%(Key)s=%(Value)s" % x for x in json.load(sys.stdin)["Tags"] if x["Key"] != "creation-date"]))\')', # noqa
    }
    return "(%(cmd)s; echo exited $?; %(upload_logs)s; %(shutdown)s) >nohup.out 2>nohup.out </dev/null &" % {
        'cmd': _cmd,
        'upload_logs': upload_logs,
        'shutdown': ('sudo halt'
                     if no_rm else
                     'aws ec2 terminate-instances --instance-ids $(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)'),
    }


@argh.arg('--tag', action='append')
def launch(name:    'name of all instances',
           *args:   'one instance per arg, and that arg is str formatted into cmd, pre_cmd, and tags via %(arg)s',
           pre_cmd: 'optional cmd which runs before cmd is backgrounded' = None,
           cmd:     'cmd which is run in the background' = None,
           tag:     'tag to set as "<key>=<value>' = None,
           no_rm:   'stop instance instead of terminating when done' = False,
           bucket:  's3 bucket to upload logs to' = shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs'),
           # following opts are copied verbatim from ec2.new
           key:     'key pair name'               = shell.conf.get_or_prompt_pref('key',  __file__, message='key pair name'),
           ami:     'ami id'                      = shell.conf.get_or_prompt_pref('ami',  __file__, message='ami id'),
           sg:      'security group name'         = shell.conf.get_or_prompt_pref('sg',   __file__, message='security group name'),
           type:    'instance type'               = shell.conf.get_or_prompt_pref('type', __file__, message='instance type'),
           vpc:     'vpc name'                    = shell.conf.get_or_prompt_pref('vpc',  __file__, message='vpc name'),
           gigs:    'gb capacity of primary disk' = 16):
    instance_ids = new(name,
                       key=key,
                       ami=ami,
                       sg=sg,
                       type=type,
                       vpc=vpc,
                       gigs=gigs,
                       num=len(args))
    errors = []
    launch_id = str(uuid.uuid4())
    logging.info('launch id: %s', launch_id)
    tag = tag or [] + ['launch=%s' % launch_id]
    def run_cmd(instance_id, arg):
        def fn():
            try:
                # TODO callback to prefix output with instance-id, ala `ec2.ssh`
                if pre_cmd:
                    ssh(instance_id, yes=True, cmd=pre_cmd % {'arg': arg})
                ssh(instance_id, no_tty=True, yes=True, cmd=_launch_cmd(arg, cmd, no_rm, bucket))
                instance = _ls([instance_id])[0]
                instance.create_tags(Tags=[{'Key': k, 'Value': v}
                                           for t in tag + ['arg=%s' % arg]
                                           for [k, v] in [(t % {'arg': arg}).split('=')]])
                logging.info('tagged: %s', _pretty(instance))
                logging.info('ran cmd against %s for arg %s', instance_id, arg)
            except:
                errors.append(traceback.format_exc())
        return fn
    pool.thread.wait(*map(run_cmd, instance_ids, args))
    if errors:
        logging.info(util.colors.red('errors:'))
        for e in errors:
            logging.info(e)
        sys.exit(1)


def launch_logs(*tags,
                index=-1,
                bucket=shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs')):
    owner = shell.run('whoami')
    prefix = '%(bucket)s/ec2_logs/%(owner)s/' % locals()
    ks = shell.run("aws s3 ls %(prefix)s" % locals()).splitlines()
    ks = [k.split()[-1] for k in ks]
    ks = [k for k in ks
          if all(t in k for t in tags)]
    k = ks[index]
    shell.call('aws s3 cp s3://%(prefix)s%(k)s - | less -R' % locals())


def scp(src, dst, *tags, yes=False, max_threads=0):
    assert tags, 'you must specify some tags'
    assert ':' in src + dst, 'you didnt specify a remote path, which starts with ":"'
    instances = _ls(tags, 'running')
    assert instances, 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    logging.info('targeting:')
    for instance in instances:
        logging.info(' %s', _pretty(instance))
    logging.info('going to scp: %s to %s', src, dst)
    if not yes:
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
    if not yes:
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
    if not yes:
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
    if not yes:
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
    if not yes:
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
    for _ in range(30):
        timeout = 3 + random.random()
        start = time.time()
        try:
            ssh(*[i.instance_id for i in instances], cmd='whoami > /dev/null', yes=True, quiet=True, timeout=timeout)
            for i in instances:
                i.reload()
            return [i.public_dns_name for i in instances]
        except:
            logging.info('trying ssh...')
            time.sleep(max(0, timeout - (time.time() - start)))
    assert False


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


def wait(*tags, state='running', yes=False, first_n=None, last_n=None, ssh=False):
    assert state in ['running', 'stopped']
    assert tags, 'you cannot wait for all things, specify some tags'
    instances = _ls(tags, 'all', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    logging.info('going to wait the following instances to be %s:', 'ssh-able' if ssh else state)
    for i in instances:
        logging.info(' ' + _pretty(i))
    if not yes:
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
    if not yes:
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
    if not yes:
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
    if not yes:
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
        tty:   'run cmd in a tty'            = False,
        login: 'login into the instance'     = False):
    assert not login or num == 1, util.colors.red('you asked to login, but you are starting more than one instance, so its not gonna happen')
    owner = shell.run('whoami')
    assert not init.startswith('#!'), 'init commands are bash snippets, and should not include a hashbang'
    for tag in tags:
        assert '=' in tag, 'bad tag, should be key=value, not: %s' % tag
    # TODO being root is not ideal. sudo -u ubuntu ...
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
    logging.info('create instances:\n' + pprint.pformat(util.dicts.drop(opts, ['UserData'])))
    instances = _resource().create_instances(**opts)
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
        i.create_tags(Tags=set_tags)
        logging.info('tagged: %s', _pretty(i))
    _wait_for_ssh(*instances)
    if login:
        logging.info('logging in via login...')
        ssh(instances[0].instance_id, yes=True, quiet=True)
    elif cmd:
        logging.info('running cmd...')
        ssh(*[i.instance_id for i in instances], yes=True, cmd=cmd, no_tty=not tty)
    logging.info('done')
    return [i.instance_id for i in instances]


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


def main():
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
