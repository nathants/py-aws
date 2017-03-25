import sys
import os
import hashlib

tmpdir = None

def _hash(x):
    return hashlib.sha1(bytes(x, 'utf-8')).hexdigest()

def _cache_path(key):
    return '%s/%s' % (tmpdir, _hash(key))

def _cache_path_prefix(key):
    return '%s/s3_stubbed_cache.%s.index' % (tmpdir, _hash(key))

def _prefixes(key):
    xs = key.split('/')
    xs = xs[:-1]
    xs = ['/'.join(xs[:i]) + '/' for i, _ in enumerate(xs, 1)]
    return [""] + xs

def ls(url, recursive=False):
    orig_url = url = url.split('s3://')[-1]
    try:
        with open(_cache_path_prefix(url)) as f:
            xs = f.read().splitlines()
    except FileNotFoundError:
        try:
            url = os.path.dirname(url) + '/'
            with open(_cache_path_prefix(url)) as f:
                xs = [x for x in f.read().splitlines() if x.startswith(orig_url)]
        except FileNotFoundError:
            sys.exit(1)
    if recursive:
        xs = ['_ _ _ %s' % '/'.join(x.split('/')[1:]) for x in xs]
    else:
        xs = [x.split(url)[-1].lstrip('/') for x in xs]
        xs = {'  PRE %s/' % x.split('/')[0]
              if '/' in x else
              '_ _ _ %s' % x
              for x in xs}
    return sorted(xs)

def cp(src, dst, recursive=False):
    if recursive:
        if src.startswith('s3://'):
            bucket, *parts = src.split('s3://')[-1].rstrip('/').split('/')
            prefix = '/'.join(parts)
            for x in ls(src, recursive=True):
                key = x.split()[-1]
                path = os.path.join(dst, key.split(os.path.dirname(prefix) if dst == '.' else prefix)[-1].lstrip(' /'))
                # print(key, path)
                os.makedirs(os.path.dirname(path), 0o777, True)
                cp('s3://' + os.path.join(bucket, key), path)
        elif dst.startswith('s3://'):
            for dirpath, dirs, files in os.walk(src):
                path = dirpath.split(src)[-1].lstrip('/')
                for file in files:
                    cp(os.path.join(dirpath, file), os.path.join(dst, path, file))
    elif src.startswith('s3://'):
        src = src.split('s3://')[1]
        try:
            with open(_cache_path(src)) as f:
                x = f.read()
        except FileNotFoundError:
            sys.exit(1)
        if dst == '-':
            print(x)
        else:
            with open(dst, 'w') as f:
                f.write(x)
    elif dst.startswith('s3://'):
        if src == '-':
            x = sys.stdin.read()
        else:
            with open(src) as f:
                x = f.read()
        dst = dst.split('s3://')[1]
        with open(_cache_path(dst), 'w') as f:
            f.write(x)
        for prefix in _prefixes(dst):
            with open(_cache_path_prefix(prefix), 'a') as f:
                f.write(dst + '\n')
    else:
        print('something needs s3://')
        sys.exit(1)

def clear_storage():
    assert tmpdir and tmpdir.startswith('/tmp/')
    print('$ rm -rf', tmpdir)
    os.system('rm -rf %s' % tmpdir)

def main():
    try:
        globals()['tmpdir'] = '/tmp/s3_stubbed_session_%s' % os.environ['s3_stubbed_session']
        if not os.path.exists(tmpdir):
            os.mkdir(tmpdir)
    except KeyError:
        print('must set env var: s3_stubbed_session')
        sys.exit(1)
    else:
        print('using: s3_stubbed', file=sys.stderr)
        if len(sys.argv) < 2:
            print('usage: aws s3 cp|ls|rm')
            sys.exit(1)
        else:
            cmd = sys.argv[1]
            if cmd == 'cp':
                if len(sys.argv) < 4:
                    print('usage: aws s3 cp SRC DST [--recursive]')
                    sys.exit(1)
                else:
                    cp(sys.argv[2], sys.argv[3], len(sys.argv) > 4 and sys.argv[4] == '--recursive')
            elif cmd == 'ls':
                if len(sys.argv) < 3:
                    print('usage: aws s3 ls URL [--recursive]')
                    sys.exit(1)
                else:
                    for x in ls(sys.argv[2], len(sys.argv) > 3 and sys.argv[3] == '--recursive'):
                        print(x)
            elif cmd == 'rm':
                print('rm not implemented')
            else:
                sys.exit(1)
