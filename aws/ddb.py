import boto3
import json
import contextlib
import logging
import os
import shell
import sys
import util.colors
import util.log
import util.time
from unittest import mock


is_cli = False


def _resource():
    return boto3.resource('dynamodb')


def _client():
    return boto3.client('dynamodb')


@contextlib.contextmanager
def _region(name):
    session = boto3.DEFAULT_SESSION
    boto3.setup_default_session(region_name=name)
    try:
        yield
    finally:
        boto3.DEFAULT_SESSION = session


def delete_table(name):
    """
    delete tables
    """
    _client().delete_table(TableName=name)


def ls_tables():
    """
    list tables
    """
    return _client().list_tables()['TableNames']


def describe_table(name, verbose=False):
    """
    describe table
    """
    table = _client().describe_table(TableName=name)['Table']
    table['CreationDateTime'] = table['CreationDateTime'].isoformat()
    if verbose:
        return json.dumps(table)
    else:
        attrs = {x['AttributeName']: x['AttributeType'] for x in table['AttributeDefinitions']}
        return ' '.join([':'.join([x['AttributeName'],
                                   attrs[x['AttributeName']].lower(),
                                   x['KeyType'].lower()])
                         for x in table['KeySchema']])


def create_table(name, *columns, read: 'capacity' = 5, write: 'capacity' = 5):
    """
    create table
    decribe columns like: $name:s|n|b:hash|range
    example: user_name:s:hash
    """
    resp = _client().create_table(
        AttributeDefinitions=[
            {'AttributeName': attr_name,
             'AttributeType': attr_type.upper()}
            for column in columns
            for attr_name, attr_type, _ in [column.split(':')]],
        TableName=name,
        KeySchema=[
            {'AttributeName': attr_name,
             'KeyType': key_type.upper()}
            for column in columns
            for attr_name, _, key_type in [column.split(':')]],
        ProvisionedThroughput={
            'ReadCapacityUnits': read,
            'WriteCapacityUnits': write
        },
    )


def get(table, *keys):
    """
    get item
    describe keys like: $name:$value:s|n|b
    example: user_name:john:s
    """
    items = _client().get_item(
        TableName=table,
        Key={name: {type.upper(): value}
             for key in keys
             for name, value, type in [key.split(':')]}
    )
    try:
        return json.dumps(items['Item'])
    except KeyError:
        sys.exit(1)


def scan(table, max=1000, size=100):
    resp = _client().get_paginator('scan').paginate(
        TableName=table,
        PaginationConfig={
            'MaxItems': max,
            'PageSize': size,
        }
    )
    for items in resp:
        for item in items['Items']:
            yield json.dumps(item)


def delete(table, *keys):
    """
    delete item
    describe keys like: $name:$value:s|n|b
    example: user_name:john:s
    """
    return json.dumps(_client().delete_item(
        TableName=table,
        Key={name: {type.upper(): value}
             for key in keys
             for name, value, type in [key.split(':')]}
    ))


def put(table, *vals):
    """
    put item
    describe vals like: $name:$value:s|n|b
    example: user_name:john:s
    """
    _client().put_item(
        TableName=table,
        Item={name: {type.upper(): value}
              for val in vals
              for name, value, type in [val.split(':')]}
    )


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
