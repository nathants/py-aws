import aws.ec2
import argh
import logging
import os
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


# TODO something like `launch restart <instance-id>` would be
# really handy. good reason to switch to cloud-init? because it's ec2
# meta-data and accessible out of band?

# TODO something like `launch wait launch=xxx

def _launch_cmd(arg, cmd, no_rm, bucket):
    # TODO how to make this more understandable?
    if callable(cmd):
        _cmd = cmd(str(arg))
    else:
        _cmd = cmd % {'arg': arg}
    kw = {'bucket': bucket,
          'user': os.environ['USER'],
          'date': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
          'ip': '$(curl http://169.254.169.254/latest/meta-data/public-hostname/ 2>/dev/null)',
          'tags': '$(aws ec2 describe-tags --filters "Name=resource-id,Values=$(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)"|python3 -c \'import sys, json; print(",".join(["%(Key)s=%(Value)s" % x for x in json.load(sys.stdin)["Tags"] if x["Key"] != "creation-date"]).replace("_", "-"))\')'} # noqa
    upload_log = 'aws s3 cp ~/nohup.out s3://%(bucket)s/ec2_logs/%(user)s/%(date)s_%(tags)s_%(ip)s/nohup.out >/dev/null 2>&1' % kw
    upload_log_tail = 'tail -n 1000 ~/nohup.out > ~/nohup.out.tail; aws s3 cp ~/nohup.out.tail s3://%(bucket)s/ec2_logs/%(user)s/%(date)s_%(tags)s_%(ip)s/nohup.out.tail >/dev/null 2>&1' % kw
    shutdown = ('sudo halt'
                if no_rm else
                'aws ec2 terminate-instances --instance-ids $(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)')
    return "(set -x; %(_cmd)s; set +x; echo exited $?; %(upload_log)s; %(upload_log_tail)s; %(shutdown)s) >nohup.out 2>nohup.out </dev/null &" % locals()


@argh.arg('--tag', action='append')
def launch(name:    'name of all instances',
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
           gigs:    'gb capacity of primary disk' = 8):
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
    launch_id = str(uuid.uuid4())
    tag = (tag or []) + ['launch=%s' % launch_id]
    def run_cmd(instance_id, arg):
        def fn():
            try:
                # TODO callback to prefix output with instance-id, ala `ec2.ssh`
                if pre_cmd:
                    aws.ec2.ssh(instance_id, yes=True, cmd=pre_cmd % {'arg': arg})
                aws.ec2.ssh(instance_id, no_tty=True, yes=True, cmd=_launch_cmd(arg, cmd, no_rm, bucket))
                instance = aws.ec2._ls([instance_id])[0]
                aws.ec2._retry(instance.create_tags)(Tags=[{'Key': k, 'Value': v}
                                                           for t in tag + ['arg=%s' % arg]
                                                           for [k, v] in [(t % {'arg': arg}).split('=')]])
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
        logging.info('launch id: %s', launch_id)


def launch_ls_logs(owner=None,
                   bucket=shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs')):
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
        print('\n' +
              'Name=' + xs[0]['tags']['Name'],
              'launch=' + launch,
              'date=' + xs[0]['date'])
        print(*['%(k)s=%(v)s' % locals()
                for k, v in xs[0]['tags'].items()
                if k not in ['Name', 'arg', 'launch', 'nth', 'num']])
        args = sorted([x['tags']['arg'] for x in xs])
        for arg in args:
            print('', 'arg=' + arg)


def launch_log(*tags,
               index=-1,
               bucket=shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs'),
               tail_only=False):
    owner = shell.run('whoami')
    prefix = '%(bucket)s/ec2_logs/%(owner)s/' % locals()
    keys = shell.run("aws s3 ls %(prefix)s --recursive" % locals()).splitlines()
    keys = [key.split()[-1] for key in keys]
    keys = [key for key in keys if key.endswith('nohup.out.tail' if tail_only else 'nohup.out')]
    keys = [key for key in keys if all(t in key for t in tags)]
    key = keys[index]
    shell.call('aws s3 cp s3://%(bucket)s/%(key)s -' % locals())


def launch_logs(*tags,
                cmd='tail -n 1',
                max_threads=10,
                bucket=shell.conf.get_or_prompt_pref('ec2_logs_bucket',  __file__, message='bucket for ec2_logs'),
                tail_only=False):
    owner = shell.run('whoami')
    prefix = '%(bucket)s/ec2_logs/%(owner)s/' % locals()
    keys = shell.run("aws s3 ls %(prefix)s --recursive" % locals()).splitlines()
    keys = [key for key in keys if key.endswith('nohup.out.tail' if tail_only else 'nohup.out')]
    keys = [key.split()[-1] for key in keys]
    keys = [key for key in keys if all(t in key for t in tags)]
    fail = False
    def f(key, cmd, bucket):
        date, tags, ip = key.split('/')[-2].split('_')
        arg = [x for x in tags.split(',') if x.startswith('arg=')][0]
        try:
            print('[%s exit 0]' % arg, shell.run(('aws s3 cp s3://%(bucket)s/%(key)s - |' + cmd) % locals()))
        except AssertionError:
            print('[%s exit 1]' % arg)
            fail = True
    pool.thread.wait(*[(f, [key, cmd, bucket]) for key in keys], max_threads=max_threads)
    if fail:
        sys.exit(1)


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
