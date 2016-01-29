import aws.ec2
import os
import datetime
import time
import random
import json
import argh
import logging
import pool.thread
import shell
import shell.conf
import sys
import traceback
import uuid
import util.colors
import util.iter
import util.log
from unittest import mock


is_cli = False


def _cmd(arg, cmd, no_rm, bucket):
    _cmd = cmd % {'arg': arg}
    kw = {'bucket': bucket,
          'user': shell.run('whoami'),
          'date': shell.run('date -u +%Y-%m-%dT%H:%M:%SZ'),
          'ip': '$(curl http://169.254.169.254/latest/meta-data/public-hostname/ 2>/dev/null)',
          'tags': '$(aws ec2 describe-tags --filters "Name=resource-id,Values=$(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)"|python3 -c \'import sys, json; print(",".join(["%(Key)s=%(Value)s" % x for x in json.load(sys.stdin)["Tags"] if x["Key"] != "creation-date"]).replace("_", "-"))\')'} # noqa
    upload_log = 'aws s3 cp ~/nohup.out s3://%(bucket)s/ec2_logs/%(user)s/%(date)s_%(tags)s_%(ip)s/nohup.out >/dev/null 2>&1' % kw
    upload_log_tail = 'tail -n 1000 ~/nohup.out > ~/nohup.out.tail; aws s3 cp ~/nohup.out.tail s3://%(bucket)s/ec2_logs/%(user)s/%(date)s_%(tags)s_%(ip)s/nohup.out.tail >/dev/null 2>&1' % kw
    shutdown = ('sudo halt'
                if no_rm else
                'aws ec2 terminate-instances --instance-ids $(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)')
    return "(echo %(_cmd)s; %(_cmd)s; echo exited $?; %(upload_log)s; %(upload_log_tail)s; %(shutdown)s) >nohup.out 2>nohup.out </dev/null &" % locals()


@argh.arg('--tag', action='append')
def new(name:    'name of all instances',
        *args:   'one instance per arg, and that arg is str formatted into cmd, pre_cmd, and tags via %(arg)s',
        pre_cmd: 'optional cmd which runs before cmd is backgrounded' = None,
        cmd:     'cmd which is run in the background' = None,
        tag:     'tag to set as "<key>=<value>' = None,
        no_rm:   'stop instance instead of terminating when done' = False,
        bucket:  's3 bucket to upload logs to' = shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs'),
        # following opts are copied verbatim from ec2.new
        spot:    'spot price to bid'           = None,
        key:     'key pair name'               = shell.conf.get_or_prompt_pref('key',  aws.ec2.__file__, message='key pair name'),
        ami:     'ami id'                      = shell.conf.get_or_prompt_pref('ami',  aws.ec2.__file__, message='ami id'),
        sg:      'security group name'         = shell.conf.get_or_prompt_pref('sg',   aws.ec2.__file__, message='security group name'),
        type:    'instance type'               = shell.conf.get_or_prompt_pref('type', aws.ec2.__file__, message='instance type'),
        vpc:     'vpc name'                    = shell.conf.get_or_prompt_pref('vpc',  aws.ec2.__file__, message='vpc name'),
        gigs:    'gb capacity of primary disk' = 16):
    for arg in args:
        assert ' ' not in arg, 'args cannot have spaces: %s' % arg
    if os.path.isfile(pre_cmd):
        logging.info('reading pre_cmd from file: %s', os.path.abspath(pre_cmd))
        pre_cmd = shell.run('cat', pre_cmd)
    if os.path.isfile(cmd):
        logging.info('reading cmd from file: %s', os.path.abspath(cmd))
        cmd = shell.run('cat', cmd)
    launch_id = str(uuid.uuid4())
    logging.info('launch=%s', launch_id)
    data = json.dumps({'name': name,
                       'args': args,
                       'pre_cmd': pre_cmd,
                       'cmd': cmd,
                       'tag': tag,
                       'no_rm': no_rm,
                       'bucket': bucket,
                       'spot': spot,
                       'type': type,
                       'vpc': vpc,
                       'gigs': gigs})
    user = shell.run('whoami')
    shell.run('aws s3 cp - s3://%(bucket)s/ec2_logs/%(user)s/launch=%(launch_id)s.json' % locals(), stdin=data)
    instance_ids = aws.ec2.new(name,
                               spot=spot,
                               key=key,
                               ami=ami,
                               sg=sg,
                               type=type,
                               vpc=vpc,
                               gigs=gigs,
                               num=len(args))
    errors = []
    tag = (tag or []) + ['launch=%s' % launch_id]
    def run_cmd(instance_id, arg):
        def fn():
            try:
                if pre_cmd:
                    aws.ec2.ssh(instance_id, yes=True, cmd=pre_cmd % {'arg': arg}, prefixed=True)
                aws.ec2.ssh(instance_id, no_tty=True, yes=True, cmd=_cmd(arg, cmd, no_rm, bucket), prefixed=True)
                instance = aws.ec2._ls([instance_id])[0]
                aws.ec2._retry(instance.create_tags)(Tags=[{'Key': k, 'Value': v}
                                                           for t in tag + ['arg=%s' % arg]
                                                           for [k, v] in [t.split('=')]])
                logging.info('tagged: %s', aws.ec2._pretty(instance))
                logging.info('ran cmd against %s for arg %s', instance_id, arg)
            except:
                errors.append(traceback.format_exc())
        return fn
    pool.thread.wait(*map(run_cmd, instance_ids, args))
    try:
        if errors:
            logging.info(util.colors.red('errors:'))
            for e in errors:
                logging.info(e)
            sys.exit(1)
    finally:
        return 'launch=%s' % launch_id


def wait(*tags):
    """
    wait for all args to finish, and exit 0 only if all logged "exited 0".
    """
    data = json.loads(params(*tags))
    args = data['args']
    num = len(args)
    assert num == len(args), 'num != args, %s != %s' % (num, len(args))
    while True:
        instances = aws.ec2._ls(tags, state=['running', 'pending'])
        logging.info('%s num running: %s', str(datetime.datetime.utcnow()).replace(' ', 'T').split('.')[0], len(instances))
        if not instances:
            break
        time.sleep(5 + 5 * random.random())
    vals = status(*tags)
    logging.info('\n'.join(vals))
    for v in vals:
        if v.endswith('failed'):
            sys.exit(1)


def restart_failed(*tags):
    """
    restart any arg which is not running and has not logged "exited 0".
    """
    args_to_restart = []
    for val in status(*tags):
        arg, state = val.split()
        if state == 'failed':
            logging.info('going to restart failed arg=%s', arg)
        elif state == 'missing':
            logging.info('going to restart missing arg=%s', arg)
    if args_to_restart:
        logging.info('restarting:')
        for arg in args_to_restart:
            logging.info(' %s', arg)
        # return new(data['name'], *args_to_restart, **util.dicts.drop(data, ['name', 'args']))
    else:
        logging.info('nothing to restart')


def params(*tags,
           bucket: 's3 bucket to upload logs to' = shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs')):
    launch_id = [x for x in tags if x.startswith('launch=')][0].split('launch=')[-1]
    user = shell.run('whoami')
    return json.dumps(json.loads(shell.run('aws s3 cp s3://%(bucket)s/ec2_logs/%(user)s/launch=%(launch_id)s.json -' % locals())), indent=4)


def status(*tags):
    """
    show all instances, and their state, ie running|done|failed|missing.
    """
    data = json.loads(params(*tags))
    with util.log.disable(''):
        results = [x.split(':') for x in logs(*tags, cmd='tail -n1', tail_only=True)]
    fail_args = [arg.split('arg=')[-1] for arg, _, exit in results if exit != 'exited 0']
    done_args = [arg.split('arg=')[-1] for arg, _, exit in results if exit == 'exited 0']
    running_args = [aws.ec2_tag(i)['arg'] for i in aws.ec2._ls(tags, state='running')]
    vals = []
    for arg in sorted(data['args']):
        if arg in fail_args:
            vals.append('arg=%s failed' % arg)
        elif arg in done_args:
            vals.append('arg=%s done' % arg)
        elif arg in running_args:
            vals.append('arg=%s running' % arg)
        else:
            vals.append('arg=%s missing' % arg)
    return vals


def ls_logs(owner=None,
            bucket=shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs'),
            name_only=False):
    owner = owner or shell.run('whoami')
    prefix = '%(bucket)s/ec2_logs/%(owner)s/' % locals()
    keys = shell.run("aws s3 ls %(prefix)s --recursive" % locals()).splitlines()
    keys = [key for key in keys if 'launch=' in key]
    keys = [key for key in keys if key.endswith('nohup.out')]
    keys = [key.split('/')[-2].split('_') for key in keys]
    keys = [key for key in keys if len(key) == 3]
    keys = [{'date': date,
             'tags': {key: v
                      for x in tags.split(',')
                      if '=' in x
                      for key, v in [x.split('=')]},
             'ip': ip}
            for date, tags, ip in keys]
    keys = util.iter.groupby(keys, lambda x: x['tags']['launch'])
    keys = sorted(keys, key=lambda x: x[1][0]['date']) # TODO date should be identical for all launchees, currently is distinct.
    for launch, xs in keys:
        print(xs[0]['tags']['Name'],
              'launch=' + launch,
              'date=' + xs[0]['date'])
        if not name_only:
            print('', *['%(k)s=%(v)s' % locals()
                        for k, v in xs[0]['tags'].items()
                        if k not in ['Name', 'arg', 'launch', 'nth', 'num']])
            args = sorted([x['tags']['arg'] for x in xs])
            for arg in args:
                print(' ', 'arg=' + arg)
            print('')


def log(*tags,
        index=-1,
        bucket=shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs'),
        tail_only=False):
    assert tags, 'you must provide some tags'
    owner = shell.run('whoami')
    prefix = '%(bucket)s/ec2_logs/%(owner)s/' % locals()
    keys = shell.run("aws s3 ls %(prefix)s --recursive" % locals()).splitlines()
    keys = [key.split()[-1] for key in keys]
    keys = [key for key in keys if key.endswith('nohup.out.tail' if tail_only else 'nohup.out')]
    keys = [key for key in keys if all(t in key for t in tags)]
    key = keys[index]
    shell.call('aws s3 cp s3://%(bucket)s/%(key)s -' % locals())


def logs(*tags,
         cmd='tail -n 1',
         max_threads=10,
         bucket=shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs'),
         tail_only=False):
    assert tags, 'you must provide some tags'
    owner = shell.run('whoami')
    prefix = '%(bucket)s/ec2_logs/%(owner)s/' % locals()
    keys = shell.run("aws s3 ls %(prefix)s --recursive" % locals()).splitlines()
    keys = [key for key in keys if key.endswith('nohup.out.tail' if tail_only else 'nohup.out')]
    keys = [key.split()[-1] for key in keys]
    keys = [key for key in keys if all(t in key for t in tags)]
    fail = False
    vals = []
    def f(key, cmd, bucket):
        date, tags, ip = key.split('/')[-2].split('_')
        arg = [x for x in tags.split(',') if x.startswith('arg=')][0]
        try:
            val = '%s:exited 0:%s' % (arg, shell.run(('aws s3 cp s3://%(bucket)s/%(key)s - |' + cmd) % locals()))
        except AssertionError:
            val = '%s:exited 1:' % arg
            fail = True
        logging.info(val)
        vals.append(val)
    pool.thread.wait(*[(f, [key, cmd, bucket]) for key in keys], max_threads=max_threads)
    if fail:
        sys.exit(1)
    else:
        return sorted(vals)


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
