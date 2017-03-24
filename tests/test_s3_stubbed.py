import uuid
import pytest
import shell
import os
os.environ['s3_stubbed_session'] = str(uuid.uuid4())

import aws.s3_stubbed as s3
from shell import run

preamble = 'python3 -c "from aws.s3_stubbed import main; main()"'

def test_basic():
    with shell.tempdir():
        with open('input.txt', 'w') as f:
            f.write('123')
        run(preamble, 'cp input.txt s3://bucket/dir/file.txt')
        run('echo asdf |', preamble, 'cp - s3://bucket/dir/stdin.txt')
        assert run(preamble, 'ls s3://bucket').splitlines() == ['bucket/dir/file.txt',
                                                                'bucket/dir/stdin.txt']
        assert run(preamble, 'cp s3://bucket/dir/file.txt -') == "123"
        assert run(preamble, 'cp s3://bucket/dir/stdin.txt -') == "asdf"
        run(preamble, 'cp s3://bucket/dir/file.txt file.downloaded')
        with open('file.downloaded') as f:
            assert f.read() == "123"
        run(preamble, 'cp s3://bucket/dir/stdin.txt stdin.downloaded')
        with open('stdin.downloaded') as f:
            assert f.read() == "asdf\n"

def test_prefixes():
    assert ["", "a", "a/b", "a/b/c"] == s3._prefixes('a/b/c/d.csv')
