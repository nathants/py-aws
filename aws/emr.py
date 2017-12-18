import boto3
import contextlib
import logging
import os
import shell
import shell.conf
import sys
import uuid
import util.colors
import util.log
from unittest import mock
import aws.ec2

is_cli = False


def _resource():
    return boto3.resource('emr')


def _client():
    return boto3.client('emr')


@contextlib.contextmanager
def _region(name):
    session = boto3.DEFAULT_SESSION
    boto3.setup_default_session(region_name=name)
    try:
        yield
    finally:
        boto3.DEFAULT_SESSION = session


def ls(state: 'use "all" to see everything' = 'running'):
    kw = {}
    if state.lower() != 'all':
        assert state.upper() in ['STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING', 'TERMINATING', 'TERMINATED', 'TERMINATED_WITH_ERRORS']
        kw['ClusterStates'] = [state.upper()]
    logging.info('name id instance-hours state creation-date')
    for resp in _client().get_paginator('list_clusters').paginate(**kw):
        for cluster in resp['Clusters']:
            yield ' '.join(map(str, [
                cluster['Name'],
                cluster['Id'],
                cluster['NormalizedInstanceHours'],
                cluster['Status']['State'],
                cluster['Status']['Timeline']['CreationDateTime'],
            ]))


def instances(cluster_id):
    ids = []
    for resp in _client().get_paginator('list_instances').paginate(
        ClusterId=cluster_id,
        InstanceGroupTypes=['MASTER', 'CORE'],
    ):
        for instance in resp['Instances']:
            ids.append(instance['Ec2InstanceId'])
    return aws.ec2.ls(*ids)


def master_instance_id(cluster_id):
    try:
        return _client().list_instances(ClusterId=cluster_id, InstanceGroupTypes=['MASTER'])['Instances'][0]['Ec2InstanceId']
    except IndexError:
        raise AssertionError('no master instance for cluster')


def emacs(path, cluster_id):
    try:
        instance = aws.ec2._ls([master_instance_id(cluster_id)])[0]
        shell.check_call("nohup emacsclient /hadoop@{}:{} > /dev/null &".format(instance.public_dns_name, path))
    except:
        sys.exit(1)


def ssh(cluster_id):
    aws.ec2.ssh(master_instance_id(cluster_id), user='hadoop')


def scp(src, dst, cluster_id):
    aws.ec2.scp(src, dst, master_instance_id(cluster_id), user='hadoop', yes=True)


def push(src, dst, cluster_id):
    aws.ec2.push(src, dst, master_instance_id(cluster_id), user='hadoop', yes=True)


def pull(src, dst, cluster_id):
    aws.ec2.pull(src, dst, master_instance_id(cluster_id), user='hadoop', yes=True)


def describe(cluster_id):
    resp = _client().describe_cluster(
        ClusterId=cluster_id
    )
    __import__('pprint').pprint(resp)


def rm(*cluster_ids):
    resp = _client().terminate_job_flows(
        JobFlowIds=cluster_ids
    )
    __import__('pprint').pprint(resp)


def wait(cluster_id, state='running'):
    _client().get_waiter('cluster_%s' % state).wait(ClusterId=cluster_id)


def add_step(cluster_id, name, *args):
    _client().add_job_flow_steps(
        JobFlowId=cluster_id,
        Steps=[{'Name': name,
                'ActionOnFailure': 'TERMINATE_CLUSTER',
                'HadoopJarStep': {'Jar': 'command-runner.jar',
                                  'Args': args}}]
    )


def new(name,
        *tags,
        application='hive',
        auto_shutdown=False,
        release_label='emr-5.10.0',
        master_type='m3.xlarge',
        slave_type='m3.xlarge',
        slave_count=10,
        spot: 'spot bid, if 0 use on-demand instead of spot' = '.15',
        spot_days: 'how many days to check for spot prices when determining the cheapest zone' = 2,
        key=shell.conf.get_or_prompt_pref('key',  __file__, message='key pair name'),
        sg_master=shell.conf.get_or_prompt_pref('sg_master',  __file__, message='security group master node'),
        sg_slave=shell.conf.get_or_prompt_pref('sg_slave',  __file__, message='security group slave nodes'),
        vpc: 'vpc name' = shell.conf.get_or_prompt_pref('vpc',  __file__, message='vpc name'),
        subnet: 'subnet id' = None,
        job_flow_role='EMR_EC2_DefaultRole',
        service_role='EMR_DefaultRole'):
    assert master_type.split('.')[0] in ['m3', 'i3'], 'must use non-vpc types, this function is not setup to deal with ebs or vpc right now'
    assert slave_type.split('.')[0] in ['m3', 'i3'], 'must use non-vpc types, this function is not setup to deal with ebs or vpc right now'
    for tag in tags:
        assert '=' in tag, 'bad tag, should be key=value, not: %s' % tag
    if not sg_master.startswith('sg-'):
        sg_master = aws.ec2.sg_id(sg_master)
    if not sg_slave.startswith('sg-'):
        sg_slave = aws.ec2.sg_id(sg_slave)
    owner = shell.run('whoami')
    instance_groups = [{'Name': 'Master',
                        'InstanceRole': 'MASTER',
                        'InstanceType': master_type,
                        'InstanceCount': 1},
                       {'Name': 'Core',
                        'InstanceRole': 'CORE',
                        'InstanceType': slave_type,
                        'InstanceCount': slave_count}]
    instances = {'InstanceGroups': instance_groups,
                 'Ec2KeyName': key,
                 'TerminationProtected': False,
                 'EmrManagedMasterSecurityGroup': sg_master,
                 'EmrManagedSlaveSecurityGroup': sg_slave,
                 'KeepJobFlowAliveWhenNoSteps': not auto_shutdown}
    if spot == '0':
        for i in instance_groups:
            i['Market'] = 'ON_DEMAND'
    else:
        for i in instance_groups:
            i['Market'] = 'SPOT'
            i['BidPrice'] = spot
        zone, _ = aws.ec2.cheapest_zone(slave_type, days=spot_days)
        logging.info('using zone: %s', zone)
        if not vpc and not subnet:
            instances['Placement'] = {'AvailabilityZone': zone}
        elif subnet:
            instances['Ec2SubnetId'] = subnet
        else:
            instances['Ec2SubnetId'] = aws.ec2._subnet(vpc, zone)
    set_tags = [
        {'Key': 'owner', 'Value': owner},
        {'Key': 'Name', 'Value': "emr-{}-cluster".format(name)},
        {'Key': 'group', 'Value': 'emr'}
    ]
    for tag in tags:
        k, v = tag.split('=')
        assert k not in ['owner', 'Name', 'group'], "reserved tag, the tag {} is set by the system".format(k)
        set_tags.append({'Key': k, 'Value': v})
    resp = _client().run_job_flow(Name=name,
                                  ReleaseLabel=release_label,
                                  Instances=instances,
                                  Applications=[{'Name': application.capitalize()}],
                                  VisibleToAllUsers=True,
                                  JobFlowRole=job_flow_role,
                                  ServiceRole=service_role,
                                  Tags=set_tags)
    cluster_id = resp['JobFlowId']
    return cluster_id


def add_script(cluster_id, schema_file, script_file):
    schema_path = 's3://shareablee-hive/tmp/scripts/%s' % uuid.uuid4()
    script_path = 's3://shareablee-hive/tmp/scripts/%s' % uuid.uuid4()
    shell.run('aws s3 cp', schema_file, schema_path)
    shell.run('aws s3 cp', script_file, script_path)
    add_step(cluster_id, 'copy schema', 'aws', 's3', 'cp', schema_path, '/tmp/schema.hql')
    add_step(cluster_id, 'copy script', 'aws', 's3', 'cp', script_path, '/tmp/script.hql')
    add_step(cluster_id, 'run script', 'hive', '-i', '/tmp/schema.hql', '-f', '/tmp/script.hql')


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
