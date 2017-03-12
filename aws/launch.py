import aws.ec2
import pager
import re
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
from util.iter import chunk
from unittest import mock


# TODO logs dir should be an arg, not an implicit thing with helper fns


is_cli = False


def _tagify(old):
    new = (old
           .replace('|', '-')
           .replace(',', '-')
           .replace(' ', '-')
           .replace('/', '-'))
    if new != old:
        logging.info("tagified label: '%s' -> '%s'", old, new)
    return new


def _retry(cmd):
    return 'max_tries=7; sleep_seconds=1; for i in $(seq 1 $max_tries); do (%s) && break || echo retrying; sleep $sleep_seconds; [ $i = $max_tries ] && echo all retries failed && exit 1 || true; done' % cmd


def _cmd(arg, cmd, no_rm, bucket):
    _cmd = cmd % {'arg': arg}
    kw = {'bucket': bucket,
          'date': shell.run('date -u +%Y-%m-%dT%H:%M:%SZ'),
          'label': '$(aws ec2 describe-tags --filters "Name=resource-id,Values=$(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)"|python3 -c \'import sys, json; print({x["Key"]: x["Value"] for x in json.load(sys.stdin)["Tags"]}["label"])\')', # noqa
          'launch': '$(aws ec2 describe-tags --filters "Name=resource-id,Values=$(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)"|python3 -c \'import sys, json; print({x["Key"]: x["Value"] for x in json.load(sys.stdin)["Tags"]}["launch"])\')'} # noqa
    path = 's3://%(bucket)s/launch_logs/launch=%(launch)s/label=%(label)s' % kw
    upload_log = _retry('aws s3 cp ~/nohup.out %(path)s/nohup.out >/dev/null 2>&1' % locals())
    upload_log_tail = _retry('tail -n 100 ~/nohup.out > ~/nohup.out.tail; aws s3 cp ~/nohup.out.tail %(path)s/nohup.out.tail >/dev/null 2>&1' % locals())
    upload_status = _retry('echo "" | aws s3 cp - %(path)s/exited=$(tail -n1 ~/nohup.out|grep exited|awk \'{print $2}\') >/dev/null 2>&1' % locals())
    shutdown = ('' if no_rm else _retry('aws ec2 terminate-instances --instance-ids $(curl http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)'))
    return "(echo %(_cmd)s; %(_cmd)s; echo exited $?; %(upload_log)s; %(upload_log_tail)s; %(upload_status)s; %(shutdown)s) >nohup.out 2>&1 </dev/null &" % locals()


@argh.arg('--tag', action='append')
@argh.arg('--arg', action='append')
@argh.arg('--label', action='append')
def new(name:    'name of all instances',
        arg:     'one instance per arg, and that arg is str formatted into cmd, pre_cmd, and tags as "arg"' = None,
        label:   'one label per arg, to use as ec2 tag since arg is often inapproriate, defaults to arg if not provided' = None,
        pre_cmd: 'optional cmd which runs before cmd is backgrounded. will be retried on failure. format with %(arg)s.' = None,
        cmd:     'cmd which is run in the background. format with %(arg)s.' = None,
        tag:     'tag to set as "<key>=<value>' = None,
        no_rm:   'stop instance instead of terminating when done' = False,
        chunk_size: 'how many args to launch at once' = 50,
        bucket:  's3 bucket to upload logs to' = shell.conf.get_or_prompt_pref('launch_logs_bucket',  __file__, message='bucket for launch_logs'),
        spot:    'spot price to bid'           = None,
        key:     'key pair name'               = shell.conf.get_or_prompt_pref('key',  aws.ec2.__file__, message='key pair name'),
        ami:     'ami id'                      = shell.conf.get_or_prompt_pref('ami',  aws.ec2.__file__, message='ami id'),
        sg:      'security group name'         = shell.conf.get_or_prompt_pref('sg',   aws.ec2.__file__, message='security group name'),
        type:    'instance type'               = shell.conf.get_or_prompt_pref('type', aws.ec2.__file__, message='instance type'),
        vpc:     'vpc name'                    = shell.conf.get_or_prompt_pref('vpc',  aws.ec2.__file__, message='vpc name'),
        zone:    'ec2 availability zone'       = None,
        role:    'ec2 iam role'                = None,
        gigs:    'gb capacity of primary disk' = 8):
    optional = ['no_rm', 'zone', 'spot', 'tag', 'pre_cmd', 'label']
    for k, v in locals().items():
        assert v is not None or k in optional, 'required flag missing: --' + k.replace('_', '-')
    tags, args, labels = tuple(tag or ()), tuple(arg or ()), tuple(label or ())
    args = [str(a) for a in args]
    if labels:
        assert len(args) == len(labels), 'there must be an equal number of args and labels, %s != %s' % (len(args), len(labels))
    else:
        labels = args
    labels = [_tagify(x) for x in labels]
    for tag in tags:
        assert '=' in tag, 'tags should be "<key>=<value>", not: %s' % tag
    for label, arg in zip(labels, args):
        if label == arg:
            logging.info('going to launch arg: %s', arg)
        else:
            logging.info('going to launch label: %s, arg: %s', label, arg)
    if pre_cmd and os.path.exists(pre_cmd):
        logging.info('reading pre_cmd from file: %s', os.path.abspath(pre_cmd))
        with open(pre_cmd) as f:
            pre_cmd = f.read()
    if os.path.exists(cmd):
        logging.info('reading cmd from file: %s', os.path.abspath(cmd))
        with open(cmd) as f:
            cmd = f.read()
    for _ in range(10):
        launch = str(uuid.uuid4())
        path = 's3://%(bucket)s/launch_logs/launch=%(launch)s' % locals()
        try:
            shell.run('aws s3 ls', path)
        except:
            break
    else:
        assert False, 'failed to generate a unique launch id. clean up: s3://%(bucket)s/launch_logs/' % locals()
    logging.info('launch=%s', launch)
    data = json.dumps({'name': name,
                       'args': args,
                       'labels': labels,
                       'pre_cmd': pre_cmd,
                       'cmd': cmd,
                       'tags': tags,
                       'no_rm': no_rm,
                       'bucket': bucket,
                       'spot': spot,
                       'key': key,
                       'ami': ami,
                       'sg': sg,
                       'type': type,
                       'vpc': vpc,
                       'gigs': gigs})
    if 'AWS_LAUNCH_RUN_LOCAL' in os.environ:
        for arg in args:
            with shell.tempdir(), shell.set_stream():
                shell.run(pre_cmd % {'arg': arg})
                shell.run(cmd % {'arg': arg})
    else:
        shell.run('aws s3 cp - s3://%(bucket)s/launch_logs/launch=%(launch)s/params.json' % locals(), stdin=data)
        tags += ('launch=%s' % launch,)
        for i, (args_chunk, labels_chunk) in enumerate(zip(chunk(args, chunk_size), chunk(labels, chunk_size))):
            logging.info('launching chunk %s of %s, chunk size: %s', i + 1, len(args) // chunk_size + 1, chunk_size)
            instance_ids = aws.ec2.new(name,
                                       role=role,
                                       spot=spot,
                                       key=key,
                                       ami=ami,
                                       sg=sg,
                                       type=type,
                                       vpc=vpc,
                                       zone=zone,
                                       gigs=gigs,
                                       num=len(args_chunk))
            errors = []
            def run_cmd(instance_id, arg, label):
                def fn():
                    try:
                        if pre_cmd:
                            aws.ec2._retry(aws.ec2.ssh)(instance_id, yes=True, cmd=pre_cmd % {'arg': arg}, prefixed=True)
                        aws.ec2.ssh(instance_id, no_tty=True, yes=True, cmd=_cmd(arg, cmd, no_rm, bucket), prefixed=True)
                        instance = aws.ec2._ls([instance_id])[0]
                        aws.ec2._retry(instance.create_tags)(Tags=[{'Key': k, 'Value': v}
                                                                   for tag in tags + ('label=%s' % label, 'chunk=%s' % i)
                                                                   for [k, v] in [tag.split('=', 1)]])
                        logging.info('tagged: %s', aws.ec2._pretty(instance))
                        logging.info('ran cmd against %s for label %s', instance_id, label)
                    except:
                        errors.append(traceback.format_exc())
                return fn
            pool.thread.wait(*map(run_cmd, instance_ids, args_chunk, labels_chunk), max_threads=10)
            if errors:
                logging.info(util.colors.red('errors:'))
                for e in errors:
                    logging.info(e)
                sys.exit(1)
        return 'launch=%s' % launch


def wait(launch):
    """
    wait for all args to finish, and exit 0 only if all logged "exited 0".
    """
    if 'AWS_LAUNCH_RUN_LOCAL' not in os.environ:
        launch = launch.replace('launch=', '')
        logging.info('wait for launch=%s', launch)
        while True:
            instances = aws.ec2._ls(['launch=%s' % launch], state=['running', 'pending'])
            logging.info('%s num running: %s', str(datetime.datetime.utcnow()).replace(' ', 'T').split('.')[0], len(instances))
            if not instances:
                break
            time.sleep(5 + 10 * random.random())
        vals = status(launch)
        logging.info('\n'.join(vals))
        for v in vals:
            if not v.startswith('done'):
                sys.exit(1)


def from_params(params_path):
    with open(params_path) as f:
        data = json.load(f)
    return new(name=data['name'],
               arg=data['args'],
               label=data['labels'],
               tag=data['tags'],
               **util.dicts.drop(data, ['name', 'args', 'labels', 'tags']))


def retry(launch, cmd=None, yes=False, everything=False):
    """
    retry any arg which is not running and has not logged "exited 0".
    """
    launch = launch.replace('launch=', '')
    text = params(launch)
    data = json.loads(text)
    if cmd:
        new_data = json.loads(shell.run(cmd, stdin=text))
        for k in data:
            if data[k] != new_data[k]:
                logging.info('\nold: %s', json.dumps({k: data[k]}))
                logging.info('new: %s', json.dumps({k: new_data[k]}))
        if not yes:
            logging.info('\nwould you like to proceed? y/n\n')
            assert pager.getch() == 'y', 'abort'
        data = new_data
    labels_to_restart = []
    for val in status(launch):
        state, label = val.split()
        label = label.split('label=', 1)[-1]
        if state == 'failed':
            logging.info('going to retry failed label=%s', label)
            labels_to_restart.append(label)
        elif state == 'missing':
            logging.info('going to retry missing label=%s', label)
            labels_to_restart.append(label)
        elif everything:
            logging.info('going to retry label=%s', label)
            labels_to_restart.append(label)
    if labels_to_restart:
        if not yes:
            logging.info('\nwould you like to proceed? y/n\n')
            assert pager.getch() == 'y', 'abort'
        logging.info('restarting:')
        for label in labels_to_restart:
            logging.info(' %s', label)
        args_to_restart = [arg
                           for arg, label in zip(data['args'], data['labels'])
                           if label in labels_to_restart]
        return new(name=data['name'],
                   arg=args_to_restart,
                   label=labels_to_restart,
                   tag=data['tags'],
                   **util.dicts.drop(data, ['name', 'args', 'labels', 'tags']))
    else:
        logging.info('nothing to retry')


def params(launch,
           bucket: 's3 bucket to upload logs to' = shell.conf.get_or_prompt_pref('launch_logs_bucket',  __file__, message='bucket for launch_logs')):
    launch = launch.replace('launch=', '')
    return json.dumps(json.loads(shell.run('aws s3 cp s3://%(bucket)s/launch_logs/launch=%(launch)s/params.json -' % locals())), indent=4)


def status(launch,
           bucket: 's3 bucket to upload logs to' = shell.conf.get_or_prompt_pref('launch_logs_bucket',  __file__, message='bucket for launch_logs')):
    """
    show all instances, and their state, ie running|done|failed|missing.
    """
    launch = launch.replace('launch=', '')
    data = json.loads(params(launch))
    results = shell.run("aws s3 ls %(bucket)s/launch_logs/launch=%(launch)s/ --recursive|awk '{print $NF}'| grep exited=" % locals()).splitlines()
    results = [(x.split('/')[-2], x.split('exited=')[-1]) for x in results]
    fail_labels = [label.split('label=', 1)[-1] for label, exit in results if exit != '0']
    done_labels = [label.split('label=', 1)[-1] for label, exit in results if exit == '0']
    running_labels = [aws.ec2._tags(i)['label'] for i in aws.ec2._ls(['launch=%s' % launch], state='running')]
    vals = []
    for label in sorted(data['labels']):
        if label in fail_labels:
            vals.append('failed label=%s' % label)
        elif label in done_labels:
            vals.append('done label=%s' % label)
        elif label in running_labels:
            vals.append('running label=%s' % label)
        else:
            vals.append('missing label=%s' % label)
    for k, v in util.iter.groupby(vals, key=lambda x: x.split()[0]):
        logging.info('num %s: %s', k, len(v))
    return sorted(vals, key=lambda x: x.split()[0], reverse=True)


def log(launch,
        label,
        bucket=shell.conf.get_or_prompt_pref('launch_logs_bucket',  __file__, message='bucket for launch_logs'),
        tail_only=False):
    launch = launch.replace('launch=', '')
    label = label.replace('label=', '')
    prefix = '%(bucket)s/launch_logs/launch=%(launch)s/label=%(label)s' % locals()
    suffix = '.tail' if tail_only else ''
    key = 's3://%(prefix)s/nohup.out%(suffix)s' % locals()
    shell.call('aws s3 cp %(key)s -' % locals())


def logs(launch,
         cmd='tail -n 1',
         max_threads=10,
         bucket=shell.conf.get_or_prompt_pref('launch_logs_bucket',  __file__, message='bucket for launch_logs'),
         tail_only=False):
    launch = launch.replace('launch=', '')
    prefix = 's3://%(bucket)s/launch_logs/launch=%(launch)s' % locals()
    labels = shell.run("aws s3 ls %(prefix)s/ |grep PRE |awk '{print $NF}'| tr -d /" % locals()).splitlines()
    suffix = '.tail' if tail_only else ''
    keys = [prefix + '/' + label + '/nohup.out' + suffix for label in labels]
    fail = False
    vals = []
    def f(key, label, cmd, bucket):
        try:
            return '%s::exited 0::%s' % (label, shell.run(('aws s3 cp %(key)s - |' + cmd) % locals()))
        except AssertionError:
            fail = True
            return '%s::exited 1::' % label
    for val in pool.thread.as_completed(*[(f, [key, label, cmd, bucket]) for key, label in zip(keys, labels)], max_threads=max_threads):
        print(val)
    if fail:
        sys.exit(1)


def main():
    globals()['is_cli'] = True
    shell.ignore_closed_pipes()
    util.log.setup(format='%(message)s')
    with util.log.disable('botocore', 'boto3'):
        try:
            stream = util.hacks.override('--stream')
            with (shell.set_stream() if stream else mock.MagicMock()):
                shell.dispatch_commands(globals(), __name__)
        except AssertionError as e:
            if e.args:
                logging.info(util.colors.red(e.args[0]))
            sys.exit(1)
