import uuid
import pytest
import shell
import os
os.environ['s3_stubbed_session'] = str(uuid.uuid4())

import aws.s3_stubbed as s3
from shell import run

preamble = 'python3 -c "from aws.s3_stubbed import main; main()"'

def rm_whitespace(x):
    return '\n'.join([y.strip()
                      for y in x.splitlines()
                      if y.strip()])

def test_basic():
    with shell.tempdir():
        with open('input.txt', 'w') as f:
            f.write('123')
        run(preamble, 'cp input.txt s3://bucket/basic/dir/file.txt')
        run('echo asdf |', preamble, 'cp - s3://bucket/basic/dir/stdin.txt')
        assert run(preamble, 'ls s3://bucket/ --recursive').splitlines() == [
            '_ _ _ basic/dir/file.txt',
            '_ _ _ basic/dir/stdin.txt']
        assert run(preamble, 'cp s3://bucket/basic/dir/file.txt -') == "123"
        assert run(preamble, 'cp s3://bucket/basic/dir/stdin.txt -') == "asdf"
        run(preamble, 'cp s3://bucket/basic/dir/file.txt file.downloaded')
        with open('file.downloaded') as f:
            assert f.read() == "123"
        run(preamble, 'cp s3://bucket/basic/dir/stdin.txt stdin.downloaded')
        with open('stdin.downloaded') as f:
            assert f.read() == "asdf\n"

def test_listing():
    run('echo |', preamble, 'cp - s3://bucket/listing/dir1/key1.txt')
    run('echo |', preamble, 'cp - s3://bucket/listing/dir1/dir2/key2.txt')
    assert run(preamble, 'ls bucket/listing/dir1/ke') == rm_whitespace("""
        _ _ _ key1.txt
    """)
    assert rm_whitespace(run(preamble, 'ls bucket/listing/dir1/')) == rm_whitespace("""
          PRE dir2/
        _ _ _ key1.txt
    """)
    assert rm_whitespace(run(preamble, 'ls bucket/listing/d')) == rm_whitespace("""
          PRE dir1/
    """)
    assert rm_whitespace(run(preamble, 'ls bucket/listing/d --recursive')) == rm_whitespace("""
        _ _ _ listing/dir1/dir2/key2.txt
        _ _ _ listing/dir1/key1.txt
    """)
    with pytest.raises(AssertionError):
        run(preamble, 'ls bucket/fake/')

def test_prefixes():
    assert ["", "a/", "a/b/", "a/b/c/"] == s3._prefixes('a/b/c/d.csv')
