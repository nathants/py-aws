import boto3
import argh
import logging
import os
import pprint
import shell
import shell.conf
import sys
import util.cached
import util.colors
import util.dicts
import util.exceptions
import util.iter
import util.log
import util.strings
import util.time
from unittest import mock
from aws.ec2 import _region, _pretty, _ls


is_cli = False


def _client_classic():
    return boto3.client('elb')


def _client():
    return boto3.client('elbv2')


@argh.arg('name', nargs='?', default=None)
def ls_classic(name):
    if name:
        for state, instances in util.iter.groupby(_client_classic().describe_instance_health(LoadBalancerName=name)['InstanceStates'], key=lambda x: x['State']):
            print(state)
            for i in instances:
                print('', _pretty(_ls([i['InstanceId']])[0]))
            print('')
        elb = _client_classic().describe_load_balancers(LoadBalancerNames=[name])['LoadBalancerDescriptions'][0]
        pprint.pprint(util.dicts.take(elb, ['AvailabilityZones', 'HealthCheck']), width=1)
    else:
        for x in _client_classic().describe_load_balancers()['LoadBalancerDescriptions']:
            print(x['LoadBalancerName'])


def ls():
    for x in _client().describe_load_balancers()['LoadBalancers']:
        print(x)


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
