import boto3
import uuid
import collections
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

# TODO update error messages like "didnt find any BLAH: WHAT_I_FOUND" to also
# include what we are looking for, and what args we queried with. when ec2 is
# imported and called directly, like from emr.py, the errors are not helpful.

is_cli = False


ssh_args = ' -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no '


def _now():
    return str(datetime.datetime.utcnow().isoformat()) + 'Z'


def _retry(f):
    """
    retry an idempotent fn a few times
    """
    def fn(*a, **kw):
        for i in itertools.count():
            try:
                return f(*a, **kw)
            except Exception as e:
                if i == 6:
                    raise
                logging.info('retrying: %s.%s, because of: %s', f.__module__, f.__name__, e)
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
        state = state.lower()
        assert state in ['running', 'pending', 'stopped', 'terminated', 'all'], 'no such state: ' + state
        state = [state]
    else:
        state = [s.lower() for s in state]
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
                filters += [{'Name': 'instance.group-id', 'Values': tags_chunk}] # ec2 modern
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


def id(*tags, first_n=None, last_n=None):
    vals = _ls(tags, 'running', first_n, last_n)
    vals = sorted(vals, key=lambda x: x.instance_id)
    vals = [i.instance_id for i in vals]
    if not vals:
        sys.exit(1)
    else:
        return vals


def ip(*tags, first_n=None, last_n=None):
    vals = _ls(tags, 'running', first_n, last_n)
    vals = sorted(vals, key=lambda x: x.instance_id)
    vals = [i.public_dns_name for i in vals]
    if not vals:
        sys.exit(1)
    else:
        return vals


def ipv4(*tags, first_n=None, last_n=None):
    vals = _ls(tags, 'running', first_n, last_n)
    vals = sorted(vals, key=lambda x: x.instance_id)
    vals = [i.public_ip_address for i in vals]
    if not vals:
        sys.exit(1)
    else:
        return vals


def ip_private(*tags, first_n=None, last_n=None):
    vals = _ls(tags, 'running', first_n, last_n)
    vals = sorted(vals, key=lambda x: x.instance_id)
    vals = [i.private_dns_name for i in vals]
    if not vals:
        sys.exit(1)
    else:
        return vals


def ipv4_private(*tags, first_n=None, last_n=None):
    vals = _ls(tags, 'running', first_n, last_n)
    vals = sorted(vals, key=lambda x: x.instance_id)
    vals = [i.private_ip_address for i in vals]
    if not vals:
        sys.exit(1)
    else:
        return vals


def ls(*tags, state='all', first_n=None, last_n=None, all_tags=False):
    xs = _ls(tags, state, first_n, last_n)
    xs = list(map(lambda y: _pretty(y, all_tags=all_tags), xs))
    if not xs:
        sys.exit(1)
    else:
        return xs


def _remote_cmd(cmd, stdin, instance_id):
    return 'fail_msg="failed to run cmd on instance: %s"; mkdir -p ~/.cmds || echo $fail_msg; path=~/.cmds/$(uuidgen); input=$path.input; echo %s | base64 -d > $path || echo $fail_msg; echo %s | base64 -d > $input || echo $fail_msg; cat $input | bash $path; code=$?; if [ $code != 0 ]; then echo $fail_msg; exit $code; fi' % (instance_id, util.strings.b64_encode(cmd), util.strings.b64_encode(stdin)) # noqa

class _instance:
    def __init__(self, ip):
        self.instance_id = ip
        self.public_dns_name = ip
        self.private_ip_address = ip
        self.tags = [{'Key': 'Name', 'Value': ip}]

def ssh(
        *tags,
        first_n=None,
        last_n=None,
        stdin: 'stdin value to be provided to remote cmd' = '',
        quiet: 'less output' = False,
        no_stream: 'dont stream to stderr, only output to stdout' = False,
        stream_only: 'dont accumulate output for stdout, only stream to stderr' = False,
        cmd: 'cmd to run on remote host, can also be a file which will be read' ='',
        yes: 'no prompt to proceed' = False,
        max_threads: 'max ssh connections' = 20,
        timeout: 'seconds before ssh cmd considered failed' = None,
        no_tty: 'when backgrounding a process, you dont want a tty' = False,
        user: 'specify ssh user' = 'ubuntu',
        key: 'speficy ssh key' = None,
        echo: 'echo some info about what was run on which hosts' = False,
        batch_mode: 'operate like there are many instances, even if only one' = False,
        prefixed: 'when running against a single host, should streaming output be prefixed with name and ip' = False,
        error_message: 'error message to print for a failed host, something like: {id} {name} {ip} {ipv4_private} failed' = ''):
    # tty means that when you ^C to exit, the remote processes are killed. this is usually what you want, ie no lingering `tail -f` instances.
    # no_tty is the opposite, which is good for backgrounding processes, for example: `ec2 ssh $host -nyc 'bash cmd.sh </dev/null &>cmd.log &'
    # TODO backgrounding appears to succeed, but ec2 ssh never exits, when targeting more than 1 host?
    assert tags, 'you must specify some tags'
    if hasattr(tags[0], 'instance_id'):
        instances = tags
    elif tags[0].endswith('.com') or tags[0].count('.') == 3 and tags[0].replace('.', '').isdigit() and not tags[0].startswith('10.'):
        instances = [_instance(tag) for tag in tags]
    else:
        instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find any instances'
    if os.path.exists(cmd):
        with open(cmd) as f:
            cmd = f.read()
    if cmd == '-':
        cmd = sys.stdin.read()
    if cmd and 'set -e' not in cmd:
        if cmd.startswith('#!'):
            lines = cmd.splitlines()
            lines.insert(1, 'set -e')
            cmd = '\n'.join(lines)
        else:
            cmd = 'set -e\n' + cmd
    if not isinstance(instances[0], _instance):
        assert (cmd and instances) or len(instances) == 1, 'didnt find instances:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    if not (quiet and yes):
        if not isinstance(instances[0], _instance):
            for i in instances:
                logging.info(_pretty(i))
        else:
            for i in instances:
                logging.info(i.instance_id)
    ssh_cmd = ('ssh -A' + (' -i {} '.format(key) if key else '') + (' -tt ' if not no_tty or not cmd else ' -T ') + ssh_args).split()
    if echo:
        logging.info('ec2.ssh running against tags: %s, with cmd: %s', tags, cmd)
    if timeout:
        ssh_cmd = ['timeout', '{}s'.format(timeout)] + ssh_cmd
    make_ssh_cmd = lambda instance: ssh_cmd + [user + '@' + instance.public_dns_name, _remote_cmd(cmd, stdin, instance.instance_id)]
    if is_cli and not yes and not (len(instances) == 1 and not cmd):
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    try:
        if cmd and len(instances) > 1 or batch_mode:
            failures = []
            successes = []
            results = None if stream_only else []
            def run(instance):
                def fn():
                    try:
                        shell.run(*make_ssh_cmd(instance),
                                  callback=_make_callback(instance, quiet, results, no_stream),
                                  stream_only=stream_only,
                                  echo=False,
                                  raw_cmd=True,
                                  stream=False,
                                  hide_stderr=quiet)
                    except:
                        if error_message:
                            print(error_message.format(id=instance.instance_id,
                                                       ip=instance.public_dns_name,
                                                       ipv4_private=instance.private_ip_address,
                                                       name=_name(instance)),
                                  flush=True)
                        msg = util.colors.red('failure: ') + _name(instance) + ': ' + instance.instance_id
                        failures.append(msg)
                    else:
                        msg = util.colors.green('success: ') + _name(instance) + ': ' + instance.instance_id
                        successes.append(msg)
                    if not quiet:
                        logging.info(msg)
                return fn
            pool.thread.wait(*map(run, instances), max_threads=max_threads)
            # TODO would be really nice to see these results, plus unknowns:, when ^C to exit early
            if not quiet:
                logging.info('\nresults:')
                for msg in successes + failures:
                    logging.info(' ' + msg)
                logging.info('\ntotals:')
                logging.info(util.colors.green(' successes: ') + str(len(successes)))
                logging.info(util.colors.red(' failures: ') + str(len(failures)))
            for result in results:
                print(result)
            assert not failures
        elif cmd:
            return shell.run(*make_ssh_cmd(instances[0]),
                             echo=False,
                             stream=not prefixed and not no_stream,
                             stream_only=stream_only,
                             hide_stderr=quiet,
                             raw_cmd=True,
                             callback=_make_callback(instances[0], quiet, None, no_stream) if prefixed else None)
        else:
            subprocess.check_call(ssh_cmd + [user + '@' + instances[0].public_dns_name])
    except:
        raise


def _make_callback(instance, quiet, append=None, no_stream=False):
    name = _name(instance) + ': ' + instance.public_dns_name + ': '
    def f(x):
        val = (x if quiet else name + x).replace('\r', '')
        if append is not None:
            append.append(val)
        if not no_stream:
            logging.info(val)
    return f


def scp(src, dst, *tags, yes=False, max_threads=0, first_n=None, last_n=None, user='ubuntu'):
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
            host = user + '@' + instance.public_dns_name
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
def push(src, dst, *tags, first_n=None, last_n=None, name=None, yes=False, max_threads=0, user='ubuntu'):
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
                          '|ssh', ssh_args, user + '@' + instance.public_dns_name,
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
    _retry(_client().stop_instances)(InstanceIds=[i.instance_id for i in instances])
    if wait:
        logging.info('waiting for all to stop')
        _wait_for_state('stopped', *instances)


def rm(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot rm all things, specify some tags'
    assert tags != ('*',), 'you cannot rm all things'
    instances = _ls(tags, ['running', 'stopped', 'pending'], first_n, last_n)
    assert instances, 'didnt find any instances for those tags'
    logging.info('going to terminate the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    _retry(_client().terminate_instances)(InstanceIds=[i.instance_id for i in instances])


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


def wait_for_ssh(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot wait for all things, specify some tags'
    instances = _ls(tags, ['running', 'pending'], first_n, last_n)
    assert instances, 'didnt find any instances for those tags'
    logging.info('going to wait for ssh on the following instances:')
    for i in instances:
        logging.info(' ' + _pretty(i))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    _wait_for_ssh(*instances)


def _wait_for_ssh(*instances, seconds=0):
    logging.info('wait for ssh...')
    true_start = time.time()
    for _ in range(200):
        running = _ls([i.id for i in instances], state='running')
        start = time.time()
        try:
            running_ids = ' '.join([i.instance_id for i in running])
            res = shell.run('ec2 ssh', running_ids, '--batch-mode -t 10 -yc "whoami>/dev/null" 2>&1', warn=True)
            ready_ids = [x.split()[-1]
                         for x in res['stdout'].splitlines()
                         if x.startswith('success: ')]
            num_ready = len(ready_ids)
            num_not_ready = len(instances) - num_ready
            logging.info('waiting for %s nodes', num_not_ready)
            if seconds and time.time() - true_start > seconds and num_not_ready:
                logging.info('waited for %s seconds, %s ready, %s not ready and will be terminated', seconds, num_ready, num_not_ready)
                not_ready_ids = [i.instance_id
                                 for i in instances
                                 if i.instance_id not in set(ready_ids)]
                if not_ready_ids:
                    rm(*not_ready_ids, yes=True)
                num_not_ready = 0
            if num_not_ready == 0:
                if ready_ids:
                    return ready_ids
                else:
                    break # fail
        except KeyboardInterrupt:
            raise
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
    _retry(_client().create_tags)(
        Resources=[i.instance_id for i in instances],
        Tags=[{'Key': k, 'Value': v} for t in set_tags.split(',') for k, v in [t.split('=')]]
    )


def wait(*tags, state='running', yes=False, first_n=None, last_n=None, ssh=False):
    state = state.lower()
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
    _client().reboot_instances(InstanceIds=[i.instance_id for i in instances])


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


def sg_dump(sort: 'id | 0 | 32' = 'id', check_num_instances=False):
    logging.info('source num-instances destination protocol:from-port:to-port')
    vals = []
    for sg in _sgs():
            src = '%s:%s' % (sg.group_id, getattr(sg, 'group_name', None) or getattr(sg, 'description', '<no-name>'))
            src = src.replace(' ', '_')
            if check_num_instances:
                num = len(_ls([sg.group_id], state='running'))
            else:
                num = '?'
            for key in ['ip_permissions_egress', 'ip_permissions']:
                for x in getattr(sg, key):
                    for dst in [cidr['CidrIp'] for cidr in x['IpRanges']] + ['%s:%s' % (group['GroupId'], group.get('GroupName', '<no-name>')) for group in x['UserIdGroupPairs']]:
                        dst = dst.replace(' ', '_')
                        vals.append(
                            '{} {} {} {}'.format(src, num, dst, ' %(IpProtocol)s:%(FromPort)s:%(ToPort)s' % x
                                                                if 'FromPort' in x else
                                                                ' Any:Any:Any').replace(':-1', ':Any'))
    if sort != 'id':
        assert sort in ['0', '32']
        if sort == '0':
            vals = sorted(vals, key=lambda x: x.split()[2].endswith('/32'), reverse=True)
            vals = sorted(vals, key=lambda x: x.split()[2].endswith('/0'), reverse=True)
        else:
            vals = sorted(vals, key=lambda x: x.split()[2].endswith('/0'), reverse=True)
            vals = sorted(vals, key=lambda x: x.split()[2].endswith('/32'), reverse=True)
    if check_num_instances:
        vals = sorted(vals, key=lambda x: int(x.split()[1]), reverse=True)
    for val in vals:
        print(val)


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
        f.write(ip + ' ' + ','.join(names) + '\n')
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


def amis_all(id_only=False):
    amis = _resource().images.filter(Owners=['self'],
                                     Filters=[{'Name': 'state',
                                               'Values': ['available']}])
    amis = sorted(amis, key=lambda x: x.creation_date, reverse=True)
    if id_only:
        return [ami.image_id for ami in amis]
    else:
        def f(ami):
            try:
                name, date = ami.name.split('__')
            except ValueError:
                return
            else:
                description = ami.description or '-' if ami.description != name else '-'
                tag = '%(Key)s=%(Value)s' % ami.tags[0] if ami.tags else '-'
                try:
                    return ' '.join([name, ami.image_id, date, description, tag])
                except:
                    print([name, ami.image_id, date, description, tag], '???')
        logging.info('id date description tag')
        xs = [f(ami) for ami in amis]
        return [x for x in xs if x]


def amis(name, *tags, id_only=False, most_recent=False):
    assert len(tags) in [0, 1], 'only one tag currently supported'
    if tags:
        tag_filter = [{'Name': 'tag:' + tags[0].split('=')[0], 'Values': [tags[0].split('=')[1]]}]
    else:
        tag_filter = []
    amis = _resource().images.filter(Owners=['self'],
                                     Filters=[{'Name': 'name',
                                               'Values': ['*%s*' % name]},
                                              {'Name': 'state',
                                               'Values': ['available']}] + tag_filter)
    amis = [x for x in amis if x.name.split('__')[0] == name]
    if not amis:
        logging.info('no amis matched name: %s %s', name, tags[0] if tags else '')
        sys.exit(1)
    amis = sorted(amis, key=lambda x: x.creation_date, reverse=True)
    if most_recent:
        amis = amis[:1]
    if id_only:
        return [ami.image_id for ami in amis]
    else:
        def f(ami):
            name, date = ami.name.split('__')
            description = ami.description if ami.description != name else '-'
            tag = '%(Key)s=%(Value)s' % ami.tags[0] if ami.tags else '-'
            return ' '.join([ami.image_id, date, description, tag])
        logging.info('id date description tag')
        return [f(ami) for ami in amis]


# TODO something better
ubuntus = {'xenial', 'trusty'}
ubuntus_hvm_ssd = {'xenial': 'ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server',
                   'trusty': 'ubuntu/images/hvm-ssd/ubuntu-trusty-14.04-amd64-server'}
ubuntus_pv = {'xenial': 'ubuntu/images/ebs-ssd/ubuntu-xenial-16.04-amd64-server',
              'trusty': 'ubuntu/images/ebs-ssd/ubuntu-trusty-14.04-amd64-server'}


def amis_ubuntu(*name_fragments, ena=False, sriov=False):
    name_fragments = ('ubuntu/images',) + name_fragments
    filters = [{'Name': 'name',
                'Values': ['*%s*' % '*'.join(name_fragments)]},
               {'Name': 'architecture',
                'Values': ['x86_64']}]
    if ena:
        filters.append({'Name': 'ena-support',
                        'Values': ['true']})
    if sriov:
        filters.append({'Name': 'sriov-net-support',
                        'Values': ['simple']})
    amis = list(_retry(_resource().images.filter)(Owners=['099720109477'],
                                                  Filters=filters))
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


def _blocks(gigs, gigs_st1=None):
    blocks = [{'DeviceName': '/dev/sda1',
               'Ebs': {'VolumeSize': int(gigs),
                       'VolumeType': 'gp2',
                       'DeleteOnTermination': True}}]
    if gigs_st1:
        blocks.append({'DeviceName': '/dev/sda2',
                       'Ebs': {'VolumeSize': int(gigs_st1),
                               'VolumeType': 'st1',
                               'DeleteOnTermination': True}})
    return blocks


def _tear_down_spot_instances(request_ids):
    _client().cancel_spot_instance_requests(SpotInstanceRequestIds=request_ids)
    logging.info('cancelled spot requests:\n%s', '\n'.join(request_ids))
    xs = _client().describe_spot_instance_requests(SpotInstanceRequestIds=request_ids)['SpotInstanceRequests']
    xs = [x.get('InstanceId') for x in xs]
    xs = [x for x in xs if x]
    if xs:
        rm(*xs, yes=True)


# TODO have a max seconds before returning whatever came up and terminating the
# rest, just like wait-for-ssh
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
        for _ in range(5):
            instances = _ls(instance_ids, state='all')
            if len(instances) == len(instance_ids):
                return instances
            time.sleep(5)
        raise Exception('failed to get the right number of instances')


def _make_spot_opts(spot, opts):
    spot_opts = {}
    spot_opts['SpotPrice'] = str(float(spot))
    spot_opts['InstanceCount'] = opts['MaxCount']
    spot_opts['LaunchSpecification'] = util.dicts.drop(opts, ['MaxCount', 'MinCount'])
    spot_opts = util.dicts.update_in(spot_opts, ['LaunchSpecification', 'UserData'], util.strings.b64_encode)
    return spot_opts


# TODO consider having instances tag themselves with cloud-init, so we never
# get unnamed instances.
_default_init = 'date > /tmp/cloudinit.log'


_st1_init = """
set -e
(
 echo g # Create a new empty GPT partition table
 echo n # Add a new partition
 echo 1 # Partition number
 echo   # First sector (Accept default: 1)
 echo   # Last sector (Accept default: varies)
 echo w # Write changes
) | sudo fdisk /dev/xvdb
sleep 2
yes|sudo mkfs -t ext4 /dev/xvdb
sudo mkdir -p /mnt
sudo mount -a
sudo chown -R ubuntu:ubuntu /mnt
"""


_nvme_init = """
(
 echo g # Create a new empty GPT partition table
 echo n # Add a new partition
 echo 1 # Partition number
 echo   # First sector (Accept default: 1)
 echo   # Last sector (Accept default: varies)
 echo w # Write changes
) | sudo fdisk /dev/nvme0n1
sleep 2
sudo mkfs -t ext4 /dev/nvme0n1p1
sudo mkdir -p /mnt
sudo mount -o discard /dev/nvme0n1p1 /mnt
sudo chown -R ubuntu:ubuntu /mnt
"""

# TODO switch to spot fleets for creating spot instances
# TODO switch to TagSpecifications in create_instances() and create_spot_fleet() so we can set tags at creation time
def new(name:  'name of the instance',
        *tags: 'tags to set as "<key>=<value>"',
        key:   'key pair name'               = shell.conf.get_or_prompt_pref('key',  __file__, message='key pair name'),
        ami:   'ami id'                      = shell.conf.get_or_prompt_pref('ami',  __file__, message='ami id'),
        sg:    'security group name'         = shell.conf.get_or_prompt_pref('sg',   __file__, message='security group name'),
        type:  'instance type'               = shell.conf.get_or_prompt_pref('type', __file__, message='instance type'),
        vpc:   'vpc name'                    = shell.conf.get_or_prompt_pref('vpc',  __file__, message='vpc name'),
        subnet: 'subnet id'                = None,
        role:  'ec2 iam role'                = None,
        zone:  'ec2 availability zone'       = None,
        gigs:  'gb capacity of primary gp2 disk' = 8,
        gigs_st1:  'gb capacity of secondary st1 disk' = 0,
        init:  'cloud init command'          = _default_init,
        data:  'arbitrary user-data'         = None,
        cmd:   'ssh command'                 = None,
        num:   'number of instances'         = 1,
        spot:  'spot price to bid'           = None,
        spot_days: 'how many days to check for spot prices when determining the cheapest zone' = 2,
        tty:   'run cmd in a tty'            = False,
        no_wait: 'do not wait for ssh'       = False,
        seconds: ('how many seconds to wait for ssh before '
                  'continuing with however many instances '
                  'became available and terminating the rest') = 0,
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
        if gigs_st1 and init == _default_init:
            init = _st1_init
        elif type.startswith('i3.') and init == _default_init:
            init = _nvme_init
        assert not init.startswith('#!'), 'init commands are bash snippets, and should not include a hashbang'
        init = '#!/bin/bash\npath=/tmp/$(uuidgen); echo %s | base64 -d > $path; sudo -u ubuntu bash -e $path /var/log/cloud_init_script.log 2>&1' % util.strings.b64_encode(init)
    if ami in ubuntus:
        distro = ami
        images = ubuntus_pv if type.split('.')[0] in ['t1', 'm1'] else ubuntus_hvm_ssd
        ami, _ = [x for x in amis_ubuntu() if images[distro] in x][0].split()
        logging.info('using ami ubuntu:%s %s', distro, ami)
    elif ami.startswith('ami-'):
        ami = ami.strip()
        logging.info('using ami: %s', ami)
    else:
        ami_name = ami
        ami = amis(ami, id_only=True, most_recent=True)[0]
        logging.info('using most recent ami for name: %s %s', ami_name, ami)
    opts = {}
    opts['UserData'] = init
    opts['ImageId'] = ami
    opts['MinCount'] = num
    opts['MaxCount'] = num
    opts['KeyName'] = key
    opts['SecurityGroupIds'] = [x.id for x in _sgs(names=[sg])]
    opts['InstanceType'] = type
    opts['BlockDeviceMappings'] = _blocks(gigs, gigs_st1)
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

    if spot and zone is None:
        zone, _, = cheapest_zone(type, kind='vpc' if vpc else 'classic', days=spot_days)
    for _ in range(5):
        if zone:
            opts['Placement'] = {'AvailabilityZone': zone}
        if vpc:
            if subnet is not None:
                opts['SubnetId'] = subnet
            else:
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
                logging.exception('failed to create spot instances, retrying...')
                continue
        else:
            logging.info('create instances:\n' + pprint.pformat(util.dicts.drop(opts, ['UserData'])))
            instances = _resource().create_instances(**opts)
        logging.info('instances:\n%s', '\n'.join([i.instance_id for i in instances]))
        _retry(_client().create_tags)(
            Resources=[i.instance_id for i in instances],
            Tags=[{'Key': 'Name', 'Value': name},
                  {'Key': 'owner', 'Value': owner},
                  {'Key': 'creation-date', 'Value': _now()},
                  {'Key': 'num', 'Value': str(num)}] + [{'Key': k, 'Value': v}
                                                        for tag in tags
                                                        for k, v in [tag.split('=')]])
        if no_wait:
            break
        else:
            try:
                ready_ids = _wait_for_ssh(*instances, seconds=seconds)
                break
            except KeyboardInterrupt:
                try:
                    rm(*[i.instance_id for i in instances], yes=True)
                except AssertionError:
                    pass # when $seconds, and no instances where ready, everything has already been terminated, and rm fails an assert
                raise
            except:
                try:
                    rm(*[i.instance_id for i in instances], yes=True)
                except AssertionError:
                    pass # when $seconds, and no instances where ready, everything has already been terminated, and rm fails an assert
                logging.exception('failed to spinup and then wait for ssh on instances, retrying...')
    else:
        assert False, 'failed to spinup and then wait for ssh on instances after 5 tries. aborting.'
    ready_instances = _ls(ready_ids, state='running')
    if login:
        logging.info('logging in...')
        ssh(ready_instances[0].instance_id, yes=True, quiet=True)
    elif cmd:
        if os.path.exists(cmd):
            logging.info('reading cmd from: %s', os.path.abspath(cmd))
            with open(cmd) as f:
                cmd = f.read()
        logging.info('running cmd...')
        ssh(*[i.instance_id for i in ready_instances], yes=True, cmd=cmd, no_tty=not tty)
    logging.info('done')
    return [i.instance_id for i in ready_instances]

# TODO this can probably be cached for some time period
def regions():
    return [x['RegionName'] for x in _client().describe_regions()['Regions']]

# TODO this can probably be cached for some time period
def zones():
    return [x['ZoneName'] for x in _client().describe_availability_zones()['AvailabilityZones']]


_kinds = {'classic': 'Linux/UNIX',
          'vpc': 'Linux/UNIX (Amazon VPC)'}

_kinds_reverse = {v: k for k, v in _kinds.items()}


def _chunk_by_day(days=7):
    now_end = datetime.datetime.utcnow().replace(second=0, microsecond=0)
    now_start = now_end.replace(hour=0, minute=0)
    start = now_start - datetime.timedelta(days=days)
    f = lambda x: x.isoformat() + 'Z'
    for i in range(days):
        s = start + datetime.timedelta(days=i)
        e = start + datetime.timedelta(days=i + 1)
        yield [f(s), f(e)]
    yield [f(now_start), f(now_end)]


def _spot_price_cache_path(type, kind, start, end):
    start = start.split('T')[0]
    end = end.split('T')[0]
    return '/tmp/cache.py-aws.spot-price.%(type)s.%(kind)s.%(start)s.%(end)s.json' % locals()


def _spot_price_history(type, kind, days=7):
    # TODO this could be more clever. currently, it only reads cached
    # data if the oldests requested day is already cached, otherwise
    # it refetches everything. this is simpler, but more ideal would
    # be to load a large chunk of cached days in the middle of a date
    # range, and then make two fetches, for dates before and after the
    # cached range. the assumption is that when used frequently, there
    # will always be cached historical data, and so this model will be
    # fine.

    # TODO may even be worth reverting to older, simpler behavior,
    # which is cache free, but way simpler. it could also be slightly
    # faster by gather all zone data in a single request cycle,
    # instead of separate cycles.
    # https://github.com/nathants/py-aws/blob/83bf766/aws/ec2.py#L1040

    assert kind in _kinds
    dates = list(_chunk_by_day(days))
    cacheable_dates = dates[:-1] # everything but the latest is a 24hr period
    cached_dates = []
    for start, end in cacheable_dates:
        if os.path.exists(_spot_price_cache_path(type, kind, start, end)):
            cached_dates.append([start, end])
        else:
            break
    uncached_dates = dates[len(cached_dates):]
    logging.debug('dates:\n %s', '\n '.join(map(str, dates)))
    logging.debug('cacheable:\n %s', '\n '.join(map(str, cacheable_dates)))
    logging.debug('cached dates:\n %s', '\n '.join(map(str, cached_dates)))
    logging.debug('uncached dates:\n %s', '\n '.join(map(str, uncached_dates)))
    if cached_dates:
        logging.debug('spot prices cached:   %s to %s.', cached_dates[0][0], cached_dates[-1][1])
        logging.debug('spot prices uncached: %s to %s', uncached_dates[0][0], uncached_dates[-1][1])
    else:
        logging.debug('spot prices uncached')
    cached_data = []
    for start, end in cached_dates:
        try:
            logging.debug('read cached data for %s %s %s %s', type, kind, start, end)
            with open(_spot_price_cache_path(type, kind, start, end)) as f:
                cached_data.extend(json.load(f))
        except (IOError, ValueError):
            logging.debug('failed to load spot price cache, refetching everything')
            cached_data = []
            uncached_dates = dates
            break
    start = uncached_dates[0][0]
    end = uncached_dates[-1][1]
    data = list(_get_spot_price(type, kind, start, end))
    for k, v in util.iter.groupby(data, lambda x: x['date'].split('T')[0]):
        start = datetime.datetime.strptime(k, "%Y-%m-%d")
        end = (start + datetime.timedelta(days=1)).isoformat() + 'Z'
        start = start.isoformat() + 'Z'
        if any([start, end] == x for x in cacheable_dates) and not any([start, end] == x for x in cached_dates):
            with open(_spot_price_cache_path(type, kind, start, end), 'w') as f:
                json.dump(v, f)
            logging.debug('write cache data for %s %s %s %s', type, kind, start, end)
    # TODO add some cache data gc. cleanup say, older than 90 days?
    # files aren't that big, but boxes that dont reboot will
    # eventually will /tmp.
    return cached_data + data


def _get_spot_price(type, kind, start, end):
    token = ''
    logging.info('get spot prices: %s %s from %s to %s', type, kind, start, end)
    assert start < end
    total = 0
    while True:
        res = _client().describe_spot_price_history(
            NextToken=token,
            StartTime=start,
            EndTime=end,
            InstanceTypes=[type],
            ProductDescriptions=[_kinds[kind]])
        result = [{'zone': x['AvailabilityZone'],
                   'price': x['SpotPrice'],
                   'date': x['Timestamp'].isoformat().split('+')[0] + 'Z'}
                  for x in res['SpotPriceHistory']]
        total += len(result)
        yield from result
        if res['NextToken']:
            logging.info('check next token for more results. total so far: %s', total)
            token = res['NextToken']
        else:
            break

def max_spot_price(type, kind: 'classic|vpc' = 'classic', days=7):
    if type.split('.')[0] in ['i3', 'm4', 'c4', 'r4', 'x1', 't2']:
        kind = 'vpc'
    vals = _spot_price_history(type, kind, days)
    results = []
    for zone, xs in util.iter.groupby(vals, lambda x: x['zone']):
        if zone.startswith(_current_region()):
            results.append([zone, max([x['price'] for x in xs])])
    results = sorted(results, key=lambda x: float(x[1]))
    return [' '.join(x) for x in results]


def cheapest_zone(type, kind: 'classic | vpc' = 'classic', days=7):
    zone, price = max_spot_price(type, kind, days)[0].split()
    logging.info('cheapest price: %s', price)
    return [zone, price]


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
    _retry(_client().start_instances)(InstanceIds=[i.instance_id for i in instances])
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


def ami(*tags, yes=False, first_n=None, last_n=None, no_wait=False, name=None, description=None, no_append_date=False, tag=None):
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
    if instance.state['Name'] == 'running':
        logging.info('going to image the following instance:')
        logging.info(' ' + _pretty(instance))
        if is_cli and not yes:
            logging.info('\nwould you like to proceed? y/n\n')
            assert pager.getch() == 'y', 'abort'
        instance.stop()
        _wait_for_state('stopped', instance)
    image = instance.create_image(Name=name, Description=description)
    if tag:
        key, value = tag.split('=')
        image.create_tags(Tags=[{'Key': key, 'Value': value}])
    ami_id = image.image_id
    if not no_wait:
        logging.info('wait for image...')
        # TODO this appears to wait way longer than necessary. instead, wait until ami-id appears in amis(name)
        # TODO these waiters are useless. remove.
        _client().get_waiter('image_available').wait(ImageIds=[ami_id])
    return ami_id


def spot_requests(*ids, state: 'open | active | closed | cancelled | failed' = None):
    resp = _client().describe_spot_instance_requests(
        SpotInstanceRequestIds=ids,
        Filters=([{'Name': 'state', 'Values': [state]}] if state else [])
    )['SpotInstanceRequests']
    return [{'instance-id': r.get('InstanceId'),
             'id': r['SpotInstanceRequestId'],
             'date': r['CreateTime'].isoformat()[:-6],
             'state': r['State'],
             'status': r['Status']['Code'],
             'type': r['LaunchSpecification']['InstanceType'],
             'ami': r['LaunchSpecification']['ImageId']}
            for r in sorted(resp, key=lambda x: x['CreateTime'], reverse=True)]


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


def _current_region():
    return _client()._client_config.region_name


def copy_image(source_region, image_id):
    assert source_region != _current_region(), 'your source region is the same region as the current region: %s' % source_region
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
            name = '%s__%s__%s' % (v['name'], v['instance_id'], v['date'].replace(':', '_'))
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


def graphs(*tags,
           period: 'data sample window in seconds' = 60,
           duration: '1H|2D'='24H',
           metric_type: 'cpu|disk|network' = 'cpu'):
    # ec2 metrics http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ec2-metricscollected.html
    # all available metrics: aws cloudwatch list-metrics --namespace "AWS/EC2" --dimensions Name=InstanceId,Value=$(ec2 ls -s running|head -n1|awk '{print $4}') | jq .Metrics[].MetricName -r|sort|grep -v status -i
    assert duration[-1] in ['H', 'D'], 'duration is something like 3H or 1D, not: %s' % duration
    assert duration[:-1].isdigit(), 'duration is something like 3H or 1D, not: %s' % duration
    if duration[-1] == 'H':
        duration = 'T' + duration
    metrics = [
        'CPUUtilization',
        'DiskReadBytes',
        'DiskReadOps',
        # 'DiskWriteBytes', # wat. they are always zero?
        # 'DiskWriteOps', # wat. they are always zero?
        'NetworkIn',
        'NetworkOut',
        'NetworkPacketsIn',
        'NetworkPacketsOut',
    ]
    region = _current_region()
    instance_ids = [i.instance_id for i in _ls(tags, state='running')]
    for metric in metrics:
        if metric_type in metric.lower():
            url = ""
            url += "https://console.aws.amazon.com/cloudwatch/home?region={region}#metricsV2:graph=~(metrics~(".format(**locals())
            instance_id = instance_ids[0]
            url += "~(~'AWS*2fEC2~'{metric}~'InstanceId~'{instance_id}~(period~{period}))".format(**locals())
            for instance_id in instance_ids[1:]:
                url += "~(~'...~'{instance_id}~(period~{period}))".format(**locals())
            url += ")~region~'{region}~start~'-P{duration}~end~'P0D);namespace=AWS/EC2;dimensions=InstanceId".format(**locals())
            try:
                subprocess.check_call(['xdg-open', url]) # ubuntu
            except:
                subprocess.check_call(['open', url]) # macos


def scheduled_events():
    logging.info('instance-name instance-id event:date,...')
    xs = _client().describe_instance_status()['InstanceStatuses']
    xs = [x for x in xs if x.get('Events')]
    xs = [' '.join([_name(_ls([x['InstanceId']])[0]),
                    x['InstanceId'],
                    ','.join([y['Code'] + ':' +
                              y['NotBefore'].isoformat().split('T')[0]
                              for y in x['Events']])])
          for x in xs]
    if xs:
        return xs
    else:
        sys.exit(1)


def reserved_usage():
    # note: assumes all m1, m2, m3 et all are in ec2 classic, and all m4 et all are in vpc.
    reserved = _client().describe_reserved_instances(Filters=[{'Name': 'state', 'Values': ['active']}])['ReservedInstances']
    assert all(x['Scope'] == 'Region' for x in reserved), 'only scope=region supported'
    reserved = [{'kind': _kinds_reverse[x['ProductDescription']],
                 'type': x['InstanceType'],
                 'num': x['InstanceCount']}
                for x in reserved]
    reserved = collections.Counter(x['type'] for x in reserved for _ in range(x['num']))
    actual = collections.Counter([y.instance_type for y in _ls([], state='running')])
    usage = {k: reserved[k] - actual[k] for k in reserved}
    logging.info('positive number means some reservations are unused')
    logging.info('negative number means there are instances which could be reserved')
    return json.dumps(usage, indent=4)


def _stderr_file(arg_num):
    return 'nohup.%(arg_num)s.stderr' % locals()


def _stdout_file(arg_num):
    return 'nohup.%(arg_num)s.stdout' % locals()


def _cmd(cmd, arg_num, worker_num):
    cmd = cmd.format(worker_num=worker_num)
    stdout = _stdout_file(arg_num)
    stderr = _stderr_file(arg_num)
    stdin = 'stdin.%s' % arg_num
    return 'set +e; rm -f nohup.* stdin.*; cat - > %(stdin)s; (echo "cat %(stdin)s | (%(cmd)s)" 1>&2; cat %(stdin)s | (%(cmd)s); echo exited: $? 1>&2;) > %(stdout)s 2> %(stderr)s </dev/null &' % locals()


# TODO should print an eta based on rate of args and total args
def pmap(instance_ids: 'comma separated ec2 instance ids to run cmds on',
         args: 'comma separated strings which will be supplied as stdin to cmd',
         cmd: '{worker_num} can be used as a unique integer id per worker',
         retries: 'how many times to retry each arg' = 10,
         retry_sleep: 'seconds to sleep before retrying' = 30):
    args = args.split(',')
    instance_ids = instance_ids.split(',')
    if instance_ids[0].endswith('.com') or instance_ids[0].count('.') == 3 and instance_ids[0].replace('.', '').isdigit():
        instances = [_instance(tag) for tag in instance_ids]
    else:
        instances = list(_ls(instance_ids, state='running'))
    assert len(instances) == len(instance_ids)
    nums = {instance: i for i, instance in enumerate(instances)}
    active = {}
    results = {}
    numbered_args = list(reversed(list(enumerate(args))))
    retried = collections.Counter()
    session = str(uuid.uuid4()).split('-')[-1]
    # process every arg
    while numbered_args or active:
        assert len(active) <= len(instances)
        # start jobs on available instances
        def start(x):
            instance, (arg_num, arg) = x
            ssh(instance,
                cmd=_cmd(cmd, arg_num, nums[instance]),
                no_tty=True,
                yes=True,
                quiet=True,
                stdin=arg)
            active[instance] = (arg_num, arg)
            logging.info('started: arg_num: %s, instance: %s, session: %s', arg_num, instance.instance_id, session)
        random.shuffle(instances)
        to_start = [(i, numbered_args.pop())
                    for i in instances
                    if i not in active
                    and numbered_args]
        list(pool.thread.map(start, to_start))
        # check for completed jobs and handle outputs
        def check(x):
            instance, (arg_num, arg) = x
            res = _retry(ssh)(
                instance,
                cmd='tail -n1 %s' % _stderr_file(arg_num),
                quiet=True,
                no_stream=True,
                yes=True,
            )
            if res.startswith('exited: '):
                code = res.split()[-1]
                if code == '0':
                    logging.info('success: arg_num: %s, instance: %s, session: %s', arg_num, instance.instance_id, session)
                    results[arg_num] = _retry(ssh)(
                        instance,
                        cmd='cat %s' % _stdout_file(arg_num),
                        quiet=True,
                        no_stream=True,
                        yes=True,
                    )
                    del active[instance]
                else:
                    retried[arg_num] += 1
                    assert retried[arg_num] < retries, 'error: arg_num: %s, instance: %s, retried: %s, session: %s' % (arg_num, instance.instance_id, retries, session)
                    logging.info('retrying: arg_num: %s, instance: %s, retried: %s, session: %s', arg_num, instance.instance_id, retried[arg_num], session)
                    numbered_args.append((arg_num, arg))
                    time.sleep(retry_sleep)

        list(pool.thread.map(check, list(active.items())))
    assert len(results) == len(args), 'mismatch result sizes'
    return [results[arg_num] for arg_num, _ in enumerate(args)]


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
