import argh
import boto3
import json
import contextlib
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


ssh_args = ' -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no '


def _now():
    return str(datetime.datetime.utcnow().isoformat()) + 'Z'


def _retry(f):
    """
    retry and idempotent fn a few times
    """
    def fn(*a, **kw):
        for i in itertools.count():
            try:
                return f(*a, **kw)
            except:
                if i == 6:
                    raise
                time.sleep(i + random.random())
    return fn


def _resource():
    return boto3.resource('ec2')


def _client():
    return boto3.client('ec2')


@contextlib.contextmanager
def _region(name):
    session = boto3.DEFAULT_SESSION
    boto3.setup_default_session(region_name=name)
    try:
        yield
    finally:
        boto3.DEFAULT_SESSION = session


def _tags(instance):
    return {x['Key']: x['Value'] for x in (instance.tags or {})}


@_retry
def _ls(tags, state='running', first_n=None, last_n=None):
    if isinstance(state, str):
        assert state in ['running', 'pending', 'stopped', 'terminated', 'all'], 'no such state: ' + state
        state = [state]
    else:
        for s in state:
            assert s in ['running', 'pending', 'stopped', 'terminated', 'all'], 'no such state: ' + s
    is_dns_name = tags and tags[0].endswith('.amazonaws.com')
    is_sg_id = tags and tags[0].startswith('sg-')
    is_priv_dns_name = tags and tags[0].endswith('.ec2.internal')
    is_ipv4 = tags and all(x.isdigit() or x == '.' for x in tags[0])
    is_priv_ipv4 = tags and all(x.isdigit() or x == '.' for x in tags[0]) and tags[0].startswith('10.')
    is_instance_id = tags and re.search(r'i\-[a-zA-Z0-9]{8}', tags[0])
    if tags and not is_dns_name and not is_sg_id and not is_instance_id and not is_ipv4 and not is_priv_ipv4 and not is_priv_dns_name and '=' not in tags[0]:
        tags = ('Name=%s' % tags[0],) + tuple(tags[1:])
    instances = []
    if not tags:
        filters = [{'Name': 'instance-state-name', 'Values': state}] if state[0] != 'all' else []
        instances += list(_resource().instances.filter(Filters=filters))
    else:
        for tags_chunk in util.iter.chunk(tags, 195): # 200 boto api limit
            filters = [{'Name': 'instance-state-name', 'Values': state}] if state[0] != 'all' else []
            if is_dns_name:
                filters += [{'Name': 'dns-name', 'Values': tags_chunk}]
                instances += list(_resource().instances.filter(Filters=filters))
            elif is_priv_dns_name:
                filters += [{'Name': 'private-dns-name', 'Values': tags_chunk}]
                instances += list(_resource().instances.filter(Filters=filters))
            elif is_priv_ipv4:
                filters += [{'Name': 'private-ip-address', 'Values': tags_chunk}]
                instances += list(_resource().instances.filter(Filters=filters))
            elif is_ipv4:
                filters += [{'Name': 'ip-address', 'Values': tags_chunk}]
                instances += list(_resource().instances.filter(Filters=filters))
            elif is_instance_id:
                filters += [{'Name': 'instance-id', 'Values': tags_chunk}]
                instances += list(_resource().instances.filter(Filters=filters))
            elif is_sg_id:
                filters += [{'Name': 'group-id', 'Values': tags_chunk}, # ec2 classic
                            {'Name': 'instance.group-id', 'Values': tags_chunk}] # ec2 modern
                instances += list(_resource().instances.filter(Filters=filters))
            elif any('*' in tag for tag in tags_chunk):
                instances += [i for i in _resource().instances.filter(Filters=filters) if _matches(i, tags_chunk)]
            else:
                filters += [{'Name': 'tag:%s' % name, 'Values': [value]}
                            for tag in tags_chunk
                            for name, value in [tag.split('=')]]
                instances += list(_resource().instances.filter(Filters=filters))
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
    @_retry
    def f():
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
            ('spot' if instance.spot_instance_request_id else 'ondemand'),
            instance.placement['AvailabilityZone'],
            (instance.public_dns_name or '<no-ip>' if ip else None),
            ','.join([x['GroupName'] for x in instance.security_groups]),
            ' '.join('%s=%s' % (k, v)
                     for k, v in sorted(_tags(instance).items(), key=lambda x: x[0])
                     if (all_tags or k not in ['Name', 'creation-date', 'owner', 'launch'])
                     and v),
        ]))
    return f()


def _name(instance):
    return _tags(instance).get('Name', '<no-name>').replace(' ', '_')


def _name_group(instance):
    return '%s:%s' % (_tags(instance).get('Name', '<no-name>'), instance.instance_id)


def ip(*tags, first_n=None, last_n=None):
    return [i.public_dns_name for i in _ls(tags, 'running', first_n, last_n)]


def ip_private(*tags, first_n=None, last_n=None):
    return [i.private_dns_name for i in _ls(tags, 'running', first_n, last_n)]


def ipv4_private(*tags, first_n=None, last_n=None):
    return [i.private_ip_address for i in _ls(tags, 'running', first_n, last_n)]


def ls(*tags, state='all', first_n=None, last_n=None, all_tags=False):
    x = _ls(tags, state, first_n, last_n)
    x = map(lambda y: _pretty(y, all_tags=all_tags), x)
    x = '\n'.join(x)
    if not x:
        sys.exit(1)
    else:
        print(x, flush=True)


def _remote_cmd(cmd, address):
    return 'fail_msg="failed to run cmd on address: %s"; mkdir -p ~/.cmds || echo $fail_msg; path=~/.cmds/$(uuidgen); echo %s | base64 -d > $path || echo $fail_msg; bash $path; code=$?; if [ $code != 0 ]; then echo $fail_msg; exit $code; fi' % (address, util.strings.b64_encode(cmd)) # noqa


def ssh(
        *tags,
        first_n=None,
        last_n=None,
        quiet: 'less output' = False,
        cmd: 'cmd to run on remote host, can also be a file which will be read' ='',
        yes: 'no prompt to proceed' = False,
        max_threads: 'max ssh connections' = 20,
        timeout: 'seconds before ssh cmd considered failed' = None,
        no_tty: 'when backgrounding a process, you dont want a tty' = False,
        user: 'specify ssh user' = 'ubuntu',
        key: 'speficy ssh key' = None,
        echo: 'echo some info about what was run on which hosts' = False,
        prefixed: 'when running against a single host, should streaming output be prefixed with name and ip' = False,
        failure_message: 'error message to print for a failed host' = '{name} {ip} {ipv4_private} failed'):
    """
    tty means that when you ^C to exit, the remote processes are killed. this is usually what you want, ie no lingering `tail -f` instances.
    no_tty is the opposite, which is good for backgrounding or nohuping processes.
    """
    assert tags, 'you must specify some tags'
    @_retry
    def f():
        x = _ls(tags, 'running', first_n, last_n)
        assert x, 'didnt find any instances'
        return x
    instances = f()
    if os.path.exists(cmd):
        with open(cmd) as f:
            cmd = f.read()
    if cmd and 'set -e' not in cmd:
        if cmd.startswith('#!'):
            lines = cmd.splitlines()
            lines.insert(1, 'set -e')
            cmd = '\n'.join(lines)
        else:
            cmd = 'set -e\n' + cmd
    assert (cmd and instances) or len(instances) == 1, 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    if not (quiet and yes):
        for i in instances:
            logging.info(_pretty(i))
    ssh_cmd = ('ssh -A' + (' -i {} '.format(key) if key else '') + (' -tt ' if not no_tty or not cmd else ' -T ') + ssh_args).split()
    if echo:
        logging.info('ec2.ssh running against tags: %s, with cmd: %s', tags, cmd)
    if timeout:
        ssh_cmd = ['timeout', '{}s'.format(timeout)] + ssh_cmd
    make_ssh_cmd = lambda instance: ssh_cmd + [user + '@' + instance.public_dns_name, _remote_cmd(cmd, instance.public_dns_name)]
    if is_cli and not yes and not (len(instances) == 1 and not cmd):
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    # TODO have a --stream-only to not accumulate lines for return, here, or in shell.run
    try:
        if cmd and len(instances) > 1:
            failures = []
            successes = []
            results = []
            def run(instance):
                def fn():
                    try:
                        shell.run(*make_ssh_cmd(instance),
                                  callback=_make_callback(instance, quiet, results),
                                  echo=False,
                                  raw_cmd=True,
                                  stream=False,
                                  hide_stderr=quiet)
                    except:
                        if failure_message:
                            print(failure_message.format(ip=instance.public_dns_name,
                                                         ipv4_private=instance.private_ip_address,
                                                         name=_name(instance)),
                                  flush=True)
                        failures.append(util.colors.red('failure: ') + _name(instance) + ': ' + instance.public_dns_name)
                    else:
                        successes.append(util.colors.green('success: ') + _name(instance) + ': ' + instance.public_dns_name)
                return fn
            pool.thread.wait(*map(run, instances), max_threads=max_threads)
            if not quiet:
                logging.info('\nresults:')
                for msg in successes + failures:
                    logging.info(' ' + msg)
                logging.info('\ntotals:')
                logging.info(util.colors.green(' successes: ') + str(len(successes)))
                logging.info(util.colors.red(' failures: ') + str(len(failures)))
            if failures:
                sys.exit(1)
            else:
                return results
        elif cmd:
            return shell.run(*make_ssh_cmd(instances[0]),
                             echo=False,
                             stream=not prefixed,
                             hide_stderr=quiet,
                             raw_cmd=True,
                             callback=_make_callback(instances[0], quiet) if prefixed else None)
        else:
            subprocess.check_call(ssh_cmd + [user + '@' + instances[0].public_dns_name])
    except:
        sys.exit(1)


def _make_callback(instance, quiet, append=None):
    name = _name(instance) + ': ' + instance.public_dns_name + ': '
    def f(x):
        val = (x if quiet else name + x).replace('\r', '')
        if append:
            append.append(val)
        print(val, flush=True)
    return f


def scp(src, dst, *tags, yes=False, max_threads=0, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    assert ':' in src + dst, 'you didnt specify a remote path, which starts with ":"'
    instances = _ls(tags, 'running', first_n=first_n, last_n=last_n)
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
                shell.run('scp', ssh_args, _src, _dst, callback=lambda x: print(color(name + x), flush=True))
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
              "FILES=$(find -L $(basename $src) -type f %(name)s -o -type l %(name)s)\n"
              'echo $FILES|tr " " "\\n"|grep -v \.git 1>&2\n'
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
        _wait_for_state('stopped', *instances)


def rm(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot stop all things, specify some tags'
    instances = _ls(tags, ['running', 'stopped', 'pending'], first_n, last_n)
    assert instances, 'didnt find any instances for those tags'
    logging.info('going to terminate the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    if {'pending'} & {i.state['Name'] for i in instances}:
        logging.info('wait for pending instances to be running')
        _wait_for_state('running', *instances)
    for i in instances:
        i.terminate()
        logging.info('terminated: %s', _pretty(i))


def _ls_by_ids(*ids):
    return _resource().instances.filter(Filters=[{'Name': 'instance-id', 'Values': ids}])


def _wait_for_state(state, *instances_or_instance_ids):
    assert state in ['running', 'stopped']
    ids = [getattr(i, 'instance_id', i) for i in instances_or_instance_ids]
    for i in range(300):
        try:
            new_instances = _ls(ids, state=state)
            assert len(ids) == len(new_instances), '%s != %s' % (len(ids), (new_instances))
            return new_instances
        except:
            time.sleep(10 + 5 * random.random())
    assert False, 'failed to wait for %(state)s for instances %(ids)s' % locals()


def _wait_for_ssh(*instances):
    logging.info('wait for ssh...')
    for _ in range(200):
        running = _ls([i.id for i in instances], state='running')
        start = time.time()
        try:
            assert len(running) == len(instances)
            ssh(*[i.instance_id for i in running], cmd='whoami > /dev/null', yes=True, quiet=True, timeout=5)
            return [i.public_dns_name for i in instances]
        except KeyboardInterrupt:
            raise
        except:
            time.sleep(max(0, 5 - (time.time() - start)))
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
        _wait_for_state(state, *instances)
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
        yield '%s %s' % (sg.group_name, sg.group_id)


def sg_id(name):
    xs = [x for x in _sgs() if x.group_name == name]
    assert len(xs) == 1, 'didnt find exactly one match: %s' % xs
    return xs[0].group_id


def sg_name(id):
    xs = [x for x in _sgs() if x.group_id == id]
    assert len(xs) == 1, 'didnt find exactly one match: %s' % xs
    return xs[0].group_name


def auths(ip):
    for sg in _wildcard_security_groups(ip):
        yield '%s [%s]' % (util.colors.green(sg.group_name), sg.group_id)


@_retry
def _sgs(names=None):
    sgs = list(_resource().security_groups.all())
    if names:
        sgs = [x
               for x in sgs
               if x.group_name in names
               or x.group_id in names]
    return sgs


def authorize(ip, *names, yes=False):
    assert all(x == '.' or x.isdigit() for x in ip), 'bad ip: %s' % ip
    names = [util.strings.rm_color(x) for x in names]
    sgs = _sgs(names)
    assert sgs, 'didnt find any security groups'
    logging.info('going to authorize your ip %s to these groups:', util.colors.yellow(ip))
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


def deauthorize(ip, *names, yes=False):
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

def amis_fuzzy(*name_fragments):
    amis = _resource().images.filter(Owners=['self'],
                                     Filters=[{'Name': 'name',
                                               'Values': ['*%s*' % '*'.join(name_fragments)]},
                                              {'Name': 'state',
                                               'Values': ['available']}])
    amis = sorted(amis, key=lambda x: x.creation_date, reverse=True)
    for ami in amis:
        print('%s %s' % (util.colors.green(ami.image_id), ami.name))


def amis(name):
    amis = _resource().images.filter(Owners=['self'],
                                     Filters=[{'Name': 'name',
                                               'Values': ['*%s*' % name]},
                                              {'Name': 'state',
                                               'Values': ['available']}])
    amis = [x for x in amis
            if x.name.split('__')[0] == name]
    amis = sorted(amis, key=lambda x: x.creation_date, reverse=True)
    for ami in amis:
        print(' '.join([util.colors.green(ami.image_id)] + ami.name.split('__')))


# TODO something better
ubuntus = {'xenial', 'trusty'}
ubuntus_hvm_ssd = {'xenial': 'ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server',
                   'trusty': 'ubuntu/images/hvm-ssd/ubuntu-trusty-14.04-amd64-server'}
ubuntus_pv = {'xenial': 'ubuntu/images/ebs-ssd/ubuntu-xenial-16.04-amd64-server',
              'trusty': 'ubuntu/images/ebs-ssd/ubuntu-trusty-14.04-amd64-server'}


def amis_ubuntu(*name_fragments):
    name_fragments = ('ubuntu/images/',) + name_fragments
    amis = list(_resource().images.filter(Owners=['099720109477'],
                                          Filters=[{'Name': 'name',
                                                    'Values': ['*%s*' % '*'.join(name_fragments)]},
                                                   {'Name': 'architecture',
                                                    'Values': ['x86_64']},
                                                   # {'Name': 'virtualization-type',
                                                   #  'Values': ['hvm']}
                                                   ]))
    vals = []
    for name, xs in util.iter.groupby(amis, key=lambda x: x.name.split('-')[:-1]):
        ami = sorted(xs, key=lambda x: x.creation_date)[-1]
        vals.append('%s %s' % (ami.image_id, '-'.join(name)))
    return vals


def keys():
    for key in _resource().key_pairs.all():
        logging.info(key.name)


def vpcs():
    for vpc in _resource().vpcs.all():
        logging.info('%s subnets: %s', _name(vpc), ' '.join([x.id for x in vpc.subnets.all()]))


def _subnet(vpc, zone):
    vpcs = list(_resource().vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': [vpc]}]))
    assert len(vpcs) == 1, 'no vpc named: %s' % vpc
    if zone:
        subnets = [x for x in vpcs[0].subnets.all() if x.availability_zone == zone]
    else:
        subnets = list(vpcs[0].subnets.all())[:1]
    assert len(subnets) == 1, 'no subnet for vpc=%(vpc)s zone=%(zone)s' % locals()
    return subnets[0].id


def _blocks(gigs):
    return [{'DeviceName': '/dev/sda1',
             'Ebs': {'VolumeSize': int(gigs),
                     'VolumeType': 'gp2',
                     'DeleteOnTermination': True}}]


def _tear_down_spot_instances(request_ids):
    _client().cancel_spot_instance_requests(SpotInstanceRequestIds=request_ids)
    logging.info('cancelled spot requests:\n%s', '\n'.join(request_ids))
    xs = _client().describe_spot_instance_requests(SpotInstanceRequestIds=request_ids)['SpotInstanceRequests']
    xs = [x.get('InstanceId') for x in xs]
    xs = [x for x in xs if x]
    if xs:
        rm(*xs, yes=True)


def _create_spot_instances(**opts):
    request_ids = [x['SpotInstanceRequestId'] for x in _client().request_spot_instances(**opts)['SpotInstanceRequests']]
    logging.info("wait for spot request to be filled for ids:\n%s", '\n'.join(request_ids))
    last = None
    try:
        for _ in range(300):
            xs = _retry(_client().describe_spot_instance_requests)(SpotInstanceRequestIds=request_ids)['SpotInstanceRequests']
            states = [x['State'] for x in xs]
            if {'cancelled', 'closed', 'failed'} & set(states):
                for kind in ['Fault', 'Status']:
                    for msg in {x.get(kind, {}).get('Message') for x in xs}:
                        if msg:
                            logging.info(kind.lower() + ': %s', msg)
                raise AssertionError('some requests failed')
            elif {'active'} == set(states) and all(x.get('InstanceId') for x in xs):
                break
            else:
                current = len([x for x in states if x == 'open'])
                if current != last:
                    logging.info('waiting for %s requests', current)
                    last = current
                time.sleep(4 + random.random())
        else:
            raise AssertionError('failed to wait for spot requests')
    except:
        _tear_down_spot_instances(request_ids)
        raise
    else:
        instance_ids = [x['InstanceId'] for x in xs]
        instances = _ls(instance_ids, state='all')
        return instances


def _make_spot_opts(spot, opts):
    spot_opts = {}
    spot_opts['SpotPrice'] = str(float(spot))
    spot_opts['InstanceCount'] = opts['MaxCount']
    spot_opts['LaunchSpecification'] = util.dicts.drop(opts, ['MaxCount', 'MinCount'])
    spot_opts = util.dicts.update_in(spot_opts, ['LaunchSpecification', 'UserData'], util.strings.b64_encode)
    return spot_opts


def new(name:  'name of the instance',
        *tags: 'tags to set as "<key>=<value>"',
        key:   'key pair name'               = shell.conf.get_or_prompt_pref('key',  __file__, message='key pair name'),
        ami:   'ami id'                      = shell.conf.get_or_prompt_pref('ami',  __file__, message='ami id'),
        sg:    'security group name'         = shell.conf.get_or_prompt_pref('sg',   __file__, message='security group name'),
        type:  'instance type'               = shell.conf.get_or_prompt_pref('type', __file__, message='instance type'),
        vpc:   'vpc name'                    = shell.conf.get_or_prompt_pref('vpc',  __file__, message='vpc name'),
        role:  'ec2 iam role'                = None,
        zone:  'ec2 availability zone'       = None,
        gigs:  'gb capacity of primary disk' = 8,
        init:  'cloud init command'          = 'date > /tmp/cloudinit.log',
        data:  'arbitrary user-data'         = None,
        cmd:   'ssh command'                 = None,
        num:   'number of instances'         = 1,
        spot:  'spot price to bid'           = None,
        tty:   'run cmd in a tty'            = False,
        no_wait: 'do not wait for ssh'       = False,
        login: 'login into the instance'     = False):
    if spot:
        spot = float(spot)
    num = int(num)
    assert not (spot and type.startswith('t2.')), 't2.* instances cant use spot pricing'
    if vpc.lower() == 'none':
        vpc = None
    assert not login or num == 1, util.colors.red('you asked to login, but you are starting more than one instance, so its not gonna happen')
    owner = shell.run('whoami')
    for tag in tags:
        assert '=' in tag, 'bad tag, should be key=value, not: %s' % tag
    if data: # you can have either data or init, not both
        init = '#raw-data\n' + data
    else:
        assert not init.startswith('#!'), 'init commands are bash snippets, and should not include a hashbang'
        init = '#!/bin/bash\npath=/tmp/$(uuidgen); echo %s | base64 -d > $path; sudo -u ubuntu bash $path' % util.strings.b64_encode(init)
    if ami in ubuntus:
        distro = ami
        images = ubuntus_pv if type.split('.')[0] in ['t1', 'm1'] else ubuntus_hvm_ssd
        ami, _ = [x for x in amis_ubuntu() if images[distro] in x][0].split()
        logging.info('using ami ubuntu:%s %s', distro, ami)
    else:
        ami = ami.strip()
        logging.info('using ami: %s', ami)
    opts = {}
    opts['UserData'] = init
    opts['ImageId'] = ami
    opts['MinCount'] = num
    opts['MaxCount'] = num
    opts['KeyName'] = key
    opts['SecurityGroupIds'] = [x.id for x in _sgs(names=[sg])]
    opts['InstanceType'] = type
    opts['BlockDeviceMappings'] = _blocks(gigs)
    if role:
        opts['IamInstanceProfile'] = {'Name': role}

    # TODO something like this, but a generator. when spinning up lots of
    # instances, returns them as they become available, retrying failed
    # ones and returning those later. excepts if is ultimately unable to
    # spin up everybody.

    # TODO is this like a threadpool of ec2? with an as_completed iterator?

    # TODO do a more surgical retry. dont rm all and start over. keep
    # the good ones, and start over for only as many new ones as we
    # need to fulfill the originally requested number.

    for _ in range(5):
        if spot and zone is None:
            zone, _, _ = cheapest_zone(type, kind='vpc' if vpc else 'classic')
        if zone:
            opts['Placement'] = {'AvailabilityZone': zone}
        if vpc:
            opts['SubnetId'] = _subnet(vpc, zone)
            logging.info('using vpc: %s', vpc)
        else:
            logging.info('using ec2-classic')

        if spot:
            spot_opts = _make_spot_opts(spot, opts)
            logging.info('request spot instances:\n' + pprint.pformat(util.dicts.drop_in(spot_opts, ['LaunchSpecification', 'UserData'])))
            # TODO improve the wait-for-spot-fullfillment logic inside _create_spot_instances()
            # TODO currently this can error, which is not so good. compared to _resource().create_instances().
            try:
                instances = _create_spot_instances(**spot_opts)
            except KeyboardInterrupt:
                raise
            except:
                logging.error('failed to create spot instances, retrying...')
                continue
        else:
            logging.info('create instances:\n' + pprint.pformat(util.dicts.drop(opts, ['UserData'])))
            instances = _resource().create_instances(**opts)
        logging.info('instances:\n%s', '\n'.join([i.instance_id for i in instances]))
        if no_wait:
            break
        else:
            try:
                _wait_for_ssh(*instances)
                break
            except KeyboardInterrupt:
                rm(*[i.instance_id for i in instances], yes=True)
                raise
            except:
                rm(*[i.instance_id for i in instances], yes=True)
                logging.exception('failed to spinup and then wait for ssh on instances, retrying...')
    else:
        assert False, 'failed to spinup and then wait for ssh on instances after 5 tries. aborting.'
    date = _now()
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
    if login:
        logging.info('logging in...')
        ssh(instances[0].instance_id, yes=True, quiet=True)
    elif cmd:
        if os.path.exists(cmd):
            logging.info('reading cmd from: %s', os.path.abspath(cmd))
            with open(cmd) as f:
                cmd = f.read()
        logging.info('running cmd...')
        ssh(*[i.instance_id for i in instances], yes=True, cmd=cmd, no_tty=not tty)
    logging.info('done')
    return [i.instance_id for i in instances]


def regions():
    return [x['RegionName'] for x in _client().describe_regions()['Regions']]


def zones():
    return [x['ZoneName'] for x in _client().describe_availability_zones()['AvailabilityZones']]


def max_spot_price(type, kind=None):
    kinds = [('classic', 'Linux/UNIX'),
             ('vpc', 'Linux/UNIX (Amazon VPC)')]
    return json.dumps({zone: {name: max(float(x['SpotPrice'])
                                        for x in _client().describe_spot_price_history(
                                            InstanceTypes=[type],
                                            ProductDescriptions=[_kind],
                                            AvailabilityZone=zone)['SpotPriceHistory'] or [{'SpotPrice': 100.0}])
                              for name, _kind in kinds
                              if kind is None or name == kind}
                       for zone in zones()})


def cheapest_zone(type, kind=None):
    res = json.loads(max_spot_price(type, kind))
    res = [(zone, _kind, price)
           for zone, xs in res.items()
           for _kind, price in xs.items()
           if kind is None or kind == _kind]
    zone, kind, price = res[0]
    logging.info('cheapest price: %s', price)
    return [zone, kind, price]


def start(*tags, yes=False, first_n=None, last_n=None, login=False, wait=False):
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
    if login:
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
    assert '__' not in name, 'you cannot use "__" in a name'
    if not description:
        description = name
    if not no_append_date:
        name += '__' + str(datetime.datetime.utcnow()).replace(' ', 'T').split('.')[0].replace(':', '-') + 'Z'
    assert tags, 'you must specify some tags'
    instances = _ls(tags, ['running', 'stopped'], first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly one instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    instance = instances[0]
    instance.stop()
    _wait_for_state('stopped', instance)
    logging.info('going to image the following instance:')
    logging.info(' ' + _pretty(instance))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    ami_id = instance.create_image(Name=name, Description=description).image_id
    if not no_wait:
        logging.info('wait for image...')
        # TODO this appears to wait way longer than necessary. instead, wait until ami-id appears in amis(name)
        # TODO these waiters are useless. remove.
        _client().get_waiter('image_available').wait(ImageIds=[ami_id])
    return ami_id


def user_data(*tags, first_n=None, last_n=None, yes=False):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'all', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly one instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    instance = instances[0]
    logging.info('going to read user-data from the following instance:')
    logging.info(' ' + _pretty(instance))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    hashbang, *data = util.strings.b64_decode(instance.describe_attribute(InstanceId=instance.instance_id, Attribute='userData')['UserData']['Value']).splitlines()
    logging.info('type: %s', hashbang)
    return '\n'.join(data)


def copy_image(source_region, image_id):
    assert source_region != _client()._client_config.region_name, 'your source region is the same region as the current region: %s' % source_region
    with _region(source_region):
        image = _resource().Image(image_id)
    ami_id = _client().copy_image(SourceRegion=source_region,
                                  SourceImageId=image_id,
                                  Name=image.name,
                                  Description=image.description)['ImageId']
    logging.info('wait for image to be available: %s', ami_id)
    _client().get_waiter('image_available').wait(ImageIds=[ami_id])


def snapshot(*tags, first_n=None, last_n=None, yes=False):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n=first_n, last_n=last_n)
    assert instances, 'didnt find any instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    logging.info('going to snapshot ebs from the following instances:')
    for instance in instances:
        logging.info(' ' + _pretty(instance))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    vals = []
    now = _now()
    for instance in instances:
        volumes = [x
                   for x in instance.volumes.all()
                   if ['/dev/sda1'] == [y['Device'] for y in x.attachments]]
        assert len(volumes) == 1, 'more than 1 volume, not sure what to snapshot'
        volume = volumes[0]
        snapshot = volume.create_snapshot(Description=_name(instance) + '::' + instance.instance_id + '::' + now)
        logging.info('instance: %s, device: /dev/sda1, size: %sG, snapshot: %s', _name(instance), volume.size, snapshot.id)
        vals.append(snapshot.id)
    return vals


def snapshots(regex=None, min_date=None, make_ami=False, yes=False):
    results = []
    next_token = ''
    while True:
        resp = _client().describe_snapshots(OwnerIds=['self'], NextToken=next_token)
        results.extend(resp['Snapshots'])
        next_token = resp.get('NextToken')
        if not next_token:
            break
    results = [x for x in results if 3 == len(x['Description'].split('::'))]
    results = [{'name': x['Description'].split('::')[0],
                'instance_id': x['Description'].split('::')[1],
                'date': x['Description'].split('::')[2],
                'state': x['State'],
                'progress': x['Progress'],
                'id': x['SnapshotId'],
                'volume': x['VolumeId'],
                'size': x['VolumeSize']}
               for x in results]
    if regex:
        results = [x for x in results if re.search(regex, x['name'])]
    if min_date:
        results = [x for x in results if min_date <= x['date']]
    results = util.iter.groupby(results, lambda x: x['instance_id'])
    results = [(k, sorted(v, key=lambda x: x['date'], reverse=True)) for k, v in results]
    results = sorted(results, key=lambda x: x[1][0]['date'].split(':')[:-1], reverse=True)
    results = sorted(results, key=lambda x: x[1][0]['name'])
    res = ''
    for k, vs in results:
        v = vs[0]
        res += ' '.join([
            '{%s' % v['name'],
            '{[%s]' % v['instance_id'],
            '{[%s]' % v['id'],
            '{[progress: %s]' % v['progress'] if v['state'] != 'completed' else '{[completed]',
            '{[%s]' % v['date'],
            '{[%sGB]' % v['size'],
            '{[versions: %s]' % len(vs)]) + '\n'
    res = util.strings.align(res, '{').splitlines()
    if make_ami:
        logging.info('\n'.join(res))
        if is_cli and not yes:
            logging.info('\nwould you like to proceed? y/n\n')
            assert pager.getch() == 'y', 'abort'
        for k, vs in results:
            v = vs[0]
            block = _blocks(v['size'])[0]
            block['Ebs']['SnapshotId'] = v['id']
            name = '%s__%s' % (v['name'], v['date'].replace(':', '_'))
            id = _client().register_image(
                Name=name,
                Architecture='x86_64',
                RootDeviceName=block['DeviceName'],
                VirtualizationType='hvm',
                BlockDeviceMappings=[block],
                # SriovNetSupport='simple', # probably want this in the future, enhanced io for current gen in vpc
            )['ImageId']
            print(name, id)
    else:
        return res

def num_volumes(*tags, first_n=None, last_n=None, yes=False):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n=first_n, last_n=last_n)
    assert instances, 'didnt find any instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    for instance in instances:
        print(len(list(instance.volumes.all())), _pretty(instance))


def roles():
    client = boto3.client('iam')
    for role in client.list_roles()['Roles']:
        if role['AssumeRolePolicyDocument']['Statement'] == [{'Action': 'sts:AssumeRole', 'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}}]:
            print(role['RoleName'])


def main():
    globals()['is_cli'] = True
    shell.ignore_closed_pipes()
    util.log.setup(format='%(message)s')
    with util.log.disable('botocore', 'boto3'):
        try:
            stream = util.hacks.override('--stream')
            with (shell.set_stream() if stream else mock.MagicMock()):
                with _region(os.environ.get('region')):
                    shell.dispatch_commands(globals(), __name__)
        except AssertionError as e:
            if e.args:
                logging.info(util.colors.red(e.args[0]))
            sys.exit(1)
