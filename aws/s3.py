import aws.ec2
import argh
import tzlocal
import boto3
import logging
import os
import pprint
import shell
import shell.conf
import sys
import util.colors
import util.iter
import util.log
from unittest import mock
from aws.ec2 import _retry


is_cli = False


def _resource():
    return boto3.resource('s3')


def _client():
    return boto3.client('s3')


@argh.arg('s3_url', nargs='?', default=None)
def ls(s3_url,
       recursive=False,
       exit_codes: 'exit 1 if there are no results' = True):
    """
    list bucket contents
    """
    if not s3_url:
        for bucket in _retry(_client().list_buckets)()['Buckets']:
            yield '%s %s [%s]' % (str(bucket['CreationDate'].astimezone(tzlocal.get_localzone()))[:-6],
                                  bucket['Name'],
                                  _client().get_bucket_location(Bucket=bucket['Name'])['LocationConstraint'])
    else:
        bucket, *prefix = s3_url.split('s3://')[-1].split('/')
        kw = {'Bucket': bucket,
              'Prefix': '/'.join(prefix),
              'Delimiter': '' if recursive else '/'}
        results = False
        while True:
            resp = _retry(_client().list_objects_v2)(**kw)
            logging.debug(pprint.pformat(resp))
            for pre in resp.get('CommonPrefixes', []):
                results = True
                yield 'PRE %s' % pre['Prefix']
            for key in resp.get('Contents', []):
                results = True
                yield '%s %s %s %s' % (str(key['LastModified'].astimezone(tzlocal.get_localzone()))[:-6],
                                       key['Size'],
                                       key['Key'],
                                       key['StorageClass'])
            if resp['IsTruncated']:
                kw['ContinuationToken'] = resp['NextContinuationToken']
            else:
                break
        if not results and exit_codes:
            sys.exit(1)


@argh.arg('s3_url', nargs='?', default=None)
def ls_versions(s3_url,
                recursive=False,
                latest: 'only show the latest version of a key' = False,
                version_id: 'include version-ids as the last column of output'=False,
                exit_codes: 'exit 1 if there are no results' = True):
    """
    list bucket contents, including versions of keys
    """
    if not s3_url:
        for bucket in _retry(_client().list_buckets)()['Buckets']:
            yield '%s %s' % (str(bucket['CreationDate'].astimezone(tzlocal.get_localzone()))[:-6],
                             bucket['Name'])
    else:
        bucket, *prefix = s3_url.split('s3://')[-1].split('/')
        kw = {'Bucket': bucket,
              'Prefix': '/'.join(prefix),
              'Delimiter': '' if recursive else '/'}
        results = False
        while True:
            resp = _retry(_client().list_object_versions)(**kw)
            logging.debug(pprint.pformat(resp))
            for pre in resp.get('CommonPrefixes', []):
                results = True
                yield 'PRE %s' % pre['Prefix']
            for version in resp.get('Versions', []):
                if not latest or version['IsLatest']:
                    results = True
                    yield '%s %s %s %s %s %s' % (
                        str(version['LastModified'].astimezone(tzlocal.get_localzone()))[:-6],
                        version['Size'],
                        version['Key'],
                        version['StorageClass'],
                        'LATEST' if version['IsLatest'] else 'HISTORICAL',
                        version['VersionId'] if version_id else '',
                    )
            for delete in resp.get('DeleteMarkers', []):
                if not latest or delete['IsLatest']:
                    results = True
                    yield '%s %s %s %s %s %s' % (
                        str(delete['LastModified'].astimezone(tzlocal.get_localzone()))[:-6],
                        '-',
                        delete['Key'],
                        '-',
                        'DELETED' if delete['IsLatest'] else 'HISTORICAL-DELETE',
                        delete['VersionId'] if version_id else '',
                    )
            if resp['IsTruncated']:
                if 'NextKeyMarker' in resp:
                    kw['KeyMarker'] = resp['NextKeyMarker']
                if 'NextVersionIdMarker' in resp:
                    kw['VersionIdMarker'] = resp['NextVersionIdMarker']
            else:
                break
        if not results and exit_codes:
            sys.exit(1)


def rm(s3_url, recursive=False):
    """
    simple delete. functionally identical to the aws cli. for versioned buckets, leaves a delete marker, just like aws cli.
    """
    if not s3_url.startswith('s3://'):
        logging.info('urls must start with s3://')
        sys.exit(1)
    bucket, *key = s3_url.split('s3://')[-1].split('/')
    if recursive:
        keys = ls(s3_url, recursive=True, exit_codes=False)
        results = False
        keys = (key for key in keys if not key.strip().startswith('PRE'))
        keys = (key.split() for key in keys) # note: s3 keys with spaces in them will break
        keys = (key for _, _, _, key, _ in keys)
        for keys_chunk in util.iter.ichunk(keys, 1000): # 1000 is s3 api delete-objects limit
            resp = _retry(_client().delete_objects)(
                Bucket=bucket,
                Delete={'Objects': [{'Key': key}
                                    for key in keys_chunk]}
            )
            logging.debug(pprint.pformat(resp))
            for key in resp['Deleted']:
                results = True
                yield 'rm s3://%s/%s %s' % (bucket, key['Key'], 'VERSIONED-DELETE' if key.get('DeleteMarker') else 'PERMANENT-DELETE')
        if not results:
            logging.info('no such keys')
            sys.exit(1)
    else:
        try:
            res = [r for r in ls(s3_url) if not r.strip().startswith('PRE')]
        except SystemExit:
            logging.info('no such key')
            raise
        else:
            if len(res) != 1:
                logging.info('didnt find exactly one key, found:')
                for r in res:
                    logging.info(' %s', r)
                sys.exit(1)
            else:
                resp = _retry(_client().delete_objects)(
                    Bucket=bucket,
                    Delete={'Objects': [{'Key': '/'.join(key)}]}
                )
                logging.debug(pprint.pformat(resp))
                yield 'rm s3://%s/%s %s' % (bucket, resp['Deleted'][0]['Key'], 'VERSIONED-DELETE' if resp['Deleted'][0].get('DeleteMarker') else 'PERMANENT-DELETE')


def rm_version(s3_url: "s3://bucket/prefix/key::version_id", recursive=False):
    """
    delete a specific object version
    """
    if not s3_url.startswith('s3://'):
        logging.info('urls must start with s3://')
        sys.exit(1)
    if not len(s3_url.split('::')) == 2:
        logging.info('you must specify a version-id like: s3://bucket/prefix/key::version_id')
        sys.exit(1)
    bucket, *key = s3_url.split('s3://')[-1].split('/')
    key = '/'.join(key)
    key, version_id = key.split('::')
    resp = _retry(_client().delete_objects)(
        Bucket=bucket,
        Delete={'Objects': [{'Key': key, 'VersionId': version_id}]}
    )
    logging.debug(pprint.pformat(resp))
    for key in resp['Deleted']:
        yield 'rm s3://%s/%s PERMANENT-DELETE %s' % (bucket, key['Key'], key['VersionId'])


def rm_versions(s3_url, recursive=False):
    """
    delete all versions, including LATEST.
    """
    if not s3_url.startswith('s3://'):
        logging.info('urls must start with s3://')
        sys.exit(1)
    bucket, *_ = s3_url.split('s3://')[-1].split('/')
    if recursive:
        results = False
        keys = ls_versions(s3_url, recursive=True, exit_codes=False, version_id=True)
        keys = (key for key in keys if not key.strip().startswith('PRE'))
        keys = (key.split() for key in keys) # note: s3 keys with spaces in them will break
        keys = ((key, version_id) for _, _, _, key, _, _, version_id in keys)
        for keys_chunk in util.iter.ichunk(keys, 1000): # 1000 is s3 api delete-objects limit
            resp = _retry(_client().delete_objects)(
                Bucket=bucket,
                Delete={'Objects': [{'Key': key,
                                     'VersionId': version_id}
                                    for key, version_id in keys_chunk]}
            )
            logging.debug(pprint.pformat(resp))
            for key in resp['Deleted']:
                results = True
                yield 'rm s3://%s/%s PERMANENT-DELETE %s' % (bucket, key['Key'], key['VersionId'])
        if not results:
            logging.info('no such keys')
            sys.exit(1)
    else:
        try:
            res = [r for r in ls_versions(s3_url, version_id=True) if not r.strip().startswith('PRE')]
        except SystemExit:
            logging.info('no such key')
            raise
        else:
            keys = {r.split()[-4] for r in res} # note: s3 keys with spaces in them will break
            if len(keys) != 1:
                logging.info('didnt find exactly one key, found:')
                for k in keys:
                    logging.info(' %s', k)
                sys.exit(1)
            else:
                for keys_chunk in util.iter.ichunk(res, 1000): # 1000 is s3 api delete-objects limit
                    keys_chunk = (k.split() for k in keys_chunk) # note: s3 keys with spaces in them will break
                    keys_chunk = ((key, version_id) for _, _, _, key, _, _, version_id in keys_chunk)
                    resp = _retry(_client().delete_objects)(
                        Bucket=bucket,
                        Delete={'Objects': [{'Key': key,
                                             'VersionId': version_id}
                                            for key, version_id in keys_chunk]}
                    )
                    logging.debug(pprint.pformat(resp))
                    for key in resp['Deleted']:
                        yield 'rm s3://%s/%s PERMANENT-DELETE %s' % (bucket, key['Key'], key['VersionId'])


def cleanup_versions(s3_url, recursive=False):
    """
    delete all versions except for LATEST. this includes things which have been DELETED.
    """
    if not s3_url.startswith('s3://'):
        logging.info('urls must start with s3://')
        sys.exit(1)
    bucket, *key = s3_url.split('s3://')[-1].split('/')
    if recursive:
        results = False
        keys = ls_versions(s3_url, recursive=True, exit_codes=False, version_id=True)
        keys = (key for key in keys if not key.strip().startswith('PRE'))
        keys = (key.split() for key in keys) # note: s3 keys with spaces in them will break
        keys = ((key, version_id) for _, _, _, key, _, kind, version_id in keys if kind != 'LATEST')
        for keys_chunk in util.iter.ichunk(keys, 1000): # 1000 is s3 api delete-objects limit
            resp = _retry(_client().delete_objects)(
                Bucket=bucket,
                Delete={'Objects': [{'Key': key,
                                     'VersionId': version_id}
                                    for key, version_id in keys_chunk]}
            )
            logging.debug(pprint.pformat(resp))
            for key in resp['Deleted']:
                results = True
                yield 'rm s3://%s/%s PERMANENT-DELETE %s' % (bucket, key['Key'], key['VersionId'])
        if not results:
            logging.info('no such keys')
            sys.exit(1)
    else:
        try:
            res = [r for r in ls_versions(s3_url, version_id=True) if not r.strip().startswith('PRE')]
        except SystemExit:
            logging.info('no such key')
            raise
        else:
            keys = {r.split()[-4] for r in res} # note: s3 keys with spaces in them will break
            if len(keys) != 1:
                logging.info('didnt find exactly one key, found:')
                for k in keys:
                    logging.info(' %s', k)
                sys.exit(1)
            else:
                results = False
                for keys_chunk in util.iter.ichunk(res, 1000): # 1000 is s3 api delete-objects limit
                    keys_chunk = (k.split() for k in keys_chunk) # note: s3 keys with spaces in them will break
                    keys_chunk = ((key, version_id) for _, _, _, key, _, kind, version_id in keys_chunk if kind != 'LATEST')
                    resp = _retry(_client().delete_objects)(
                        Bucket=bucket,
                        Delete={'Objects': [{'Key': key,
                                             'VersionId': version_id}
                                            for key, version_id in keys_chunk]}
                    )
                    logging.debug(pprint.pformat(resp))
                    for key in resp['Deleted']:
                        results = True
                        yield 'rm s3://%s/%s PERMANENT-DELETE %s' % (bucket, key['Key'], key['VersionId'])
                if not results:
                    logging.info('no such keys')
                    sys.exit(1)


def main():
    globals()['is_cli'] = True
    shell.ignore_closed_pipes()
    util.log.setup(format='%(message)s')
    with util.log.disable('botocore', 'boto3'):
        try:
            stream = util.hacks.override('--stream')
            with (shell.set_stream() if stream else mock.MagicMock()):
                with aws.ec2._region(os.environ.get('region')):
                    shell.dispatch_commands(globals(), __name__)
        except AssertionError as e:
            if e.args:
                logging.debug(util.colors.red(e.args[0]))
            sys.exit(1)
