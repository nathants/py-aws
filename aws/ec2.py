import s.cached
import s.iter
import s.strings
import time
import re
import s.colors
import pager
import sys
import s.exceptions
import shell
import boto3


def _align(text):
    rows = list(map(str.split, text.splitlines()))
    sizes = [max(map(len, row)) for row in zip(*rows)]
    rows = [[col.ljust(size) for size, col in zip(sizes, cols)] for cols in rows]
    return '\n'.join(map(' '.join, rows))


@s.cached.func
def _ec2():
    return boto3.resource('ec2')


def _tags(instance):
    return {x['Key']: x['Value'] for x in (instance.tags or {})}


def _ls_by_ids(*ids):
    return _ec2().instances.filter(Filters=[{'Name': 'instance-id', 'Values': ids}])


def _ls(tags, state='running', first_n=None, last_n=None):
    if tags and '=' not in tags[0]:
        tags = ('Name=%s' % tags[0],) + tags[1:]
    filters = [{'Name': 'instance-state-name', 'Values': [state]}] if state != 'all' else []
    if any('*' in tag for tag in tags):
        instances = _ec2().instances.filter(Filters=filters)
        instances = [i for i in instances if _matches(i, tags)]
    else:
        filters += [{'Name': 'tag:%s' % name, 'Values': [value]}
                    for tag in tags
                    for name, value in [tag.split('=')]]
        instances = _ec2().instances.filter(Filters=filters)
    instances = sorted(instances, key=_name_group)
    if first_n:
        instances = instances[:int(first_n)]
    elif last_n:
        instances = instances[-int(last_n):]
    return instances


def _matches(instance, tags):
    for tag in tags:
        assert '=' in tag, 'tags are specified as "<key>=<value>", not: %s' % tag
        k, v = tag.split('=')
        t = _tags(instance).get(k, '').lower()
        v = v.lower()
        if v[0] == v[-1] == '*':
            if v.strip('*') not in t:
                return False
        elif v[0] == '*':
            if not t.endswith(v.strip('*')):
                return False
        elif v[-1] == '*':
            if not t.startswith(v.strip('*')):
                return False
        else:
            if t != v:
                return False
    return True


def _pretty(instance):
    if instance.state['Name'] == 'running':
        color = s.colors.green
    elif instance.state['Name'] == 'pending':
        color = s.colors.cyan
    else:
        color = s.colors.red
    return ' '.join([
        color(_name(instance)),
        instance.instance_id,
        instance.instance_type,
        instance.state['Name'],
        ','.join([x['GroupName'] for x in instance.security_groups]),
        instance.public_dns_name or '<no-ip>',
        instance.private_dns_name or '<no-ip>',
        ','.join('%s=%s' % (k, v) for k, v in _tags(instance).items() if k != 'Name' and v),
    ])

def _name(instance):
    return _tags(instance).get('Name', '<no-name>')


def _name_group(instance):
    return '%s:%s' % (_tags(instance).get('Name', '<no-name>'), instance.instance_id)


def ips(*tags, first_n=None, last_n=None):
    for i in _ls(tags, 'running', first_n, last_n):
        print(i.public_dns_name)


def ls(*tags, state='all', first_n=None, last_n=None):
    x = _ls(tags, state, first_n, last_n)
    x = map(_pretty, x)
    x = '\n'.join(x)
    x = _align(x)
    print(x)


def ssh(*tags, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly 1 instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    print(_pretty(instances[0]))
    try:
        shell.run('ssh -A ubuntu@%s' % instances[0].public_dns_name, interactive=True)
    except:
        sys.exit(1)

def push(src, dst, *tags, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly 1 instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    print(_pretty(instances[0]))
    try:
        shell.run('scp -r %s ubuntu@%s:%s' % (src, instances[0].public_dns_name, dst), interactive=True)
    except:
        sys.exit(1)


def pull(src, dst, *tags, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly 1 instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    print(_pretty(instances[0]))
    try:
        shell.run('scp -r ubuntu@%s:%s %s' % (instances[0].public_dns_name, src, dst), interactive=True)
    except:
        sys.exit(1)


def emacs(path, *tags, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly 1 instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    print(_pretty(instances[0]))
    try:
        shell.run("nohup emacsclient /ubuntu@{}:{} > /dev/null &".format(instances[0].public_dns_name, path), interactive=True)
    except:
        sys.exit(1)

def mosh(*tags, first_n=None, last_n=None):
    assert tags, 'you must specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert len(instances) == 1, 'didnt find exactly 1 instance:\n%s' % ('\n'.join(_pretty(i) for i in instances) or '<nothing>')
    print(_pretty(instances[0]))
    try:
        shell.run('mosh ubuntu@%s' % instances[0].public_dns_name, interactive=True)
    except:
        sys.exit(1)


def stop(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot stop all things, specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    print('going to stop the following instances:')
    for i in instances:
        print('', _pretty(i))
    if not yes:
        print('\nwould you like to proceed? y/n\n')
        if pager.getch() != 'y':
            print('abort')
            sys.exit(1)
    for i in instances:
        i.stop()
        print('stopped:', _pretty(i))


def _wait_for_ip(*ids):
    while True:
        instances = _ls_by_ids(*ids)
        if all(i.public_dns_name for i in instances):
            return [i.public_dns_name for i in instances]
        for i in instances:
            print('waiting for:', end=' ')
            if not i.public_dns_name:
                print(_name(i), end=' ')
            print('')
        time.sleep(2)


def start(*tags, yes=False, first_n=None, last_n=None, ssh=False):
    assert tags, 'you cannot start all things, specify some tags'
    instances = _ls(tags, 'stopped', first_n, last_n)
    assert instances, 'didnt find any stopped instances for those tags'
    print('going to start the following instances:')
    for i in instances:
        print('', _pretty(i))
    if not yes:
        print('\nwould you like to proceed? y/n\n')
        if pager.getch() != 'y':
            print('abort')
            sys.exit(1)
    for i in instances:
        i.start()
        print('started:', _pretty(i))
    if ssh:
        assert len(instances) == 1, s.colors.red('you asked to ssh, but you started more than one instance, so its not gonna happen')
        try:
            shell.run('ssh -A ubuntu@%s' % _wait_for_ip(instances[0].instance_id)[0], interactive=True, echo=True)
        except:
            sys.exit(1)


def _has_wildcard_permission(sg, ip):
    assert '/' not in ip
    for sg_perm in sg.ip_permissions:
        with s.exceptions.ignore(KeyError):
            all_ports = sg_perm['FromPort'] in [0, 1] and sg_perm['ToPort'] == 65535
            matches_ip = any(x['CidrIp'] == ip + '/32' for x in sg_perm['IpRanges'])
            if all_ports and matches_ip:
                return True


def _wildcard_security_groups(ip):
    return [sg for sg in _sgs() if _has_wildcard_permission(sg, ip)]

def sgs():
    for sg in _sgs():
        yield '%s [%s]' % (s.colors.green(sg.group_name), sg.group_id)


def auths(ip):
    for sg in _wildcard_security_groups(ip):
        yield '%s [%s]' % (s.colors.green(sg.group_name), sg.group_id)


def _sgs(names=None):
    sgs = _ec2().security_groups.all()
    if names:
        sgs = [x for x in sgs if x.group_name in names]
    return sgs


def authorize(ip, *names, yes=False):
    assert all(x == '.' or x.isdigit() for x in ip), 'bad ip: %s' % ip
    names = [s.strings.rm_color(x) for x in names]
    sgs = _sgs(names)
    print('going to authorize your ip %s to these groups:' % s.colors.yellow(ip))
    if names:
        sgs = [x for x in sgs if x.group_name in names]
    for sg in sgs:
        print('', '%s [%s]' % (sg.group_name, sg.group_id))
    if not yes:
        print('\nwould you like to authorize access to these groups for your ip %s? y/n\n' % s.colors.yellow(ip))
        if pager.getch() != 'y':
            print('abort')
            sys.exit(1)
    with open('/var/log/ec2_auth_ips.log', 'a') as f:
        f.write(ip + '\n')
    for sg in sgs:
        for proto in ['tcp', 'udp']:
            try:
                sg.authorize_ingress(
                    IpProtocol=proto,
                    FromPort=0,
                    ToPort=65535,
                    CidrIp='%s/32' % ip
                )
                print('authorized:', sg.group_name, sg.group_id, end=' ')
            except Exception as e:
                print(re.sub(r'.*\((.*)\).*', r'\1', str(e)) + ':', sg.group_name, sg.group_id, end=' ')
            print(proto)


def revoke(ip, *names, yes=False):
    assert all(x == '.' or x.isdigit() for x in ip), 'bad ip: %s' % ip
    sgs = _sgs(names) if names else _wildcard_security_groups(ip)
    assert sgs, 'didnt find any security groups'
    print('your ip %s is currently wildcarded to the following security groups:\n' % s.colors.yellow(ip))
    for sg in sgs:
        print('', '%s [%s]' % (sg.group_name, sg.group_id))
    if not yes:
        print('\nwould you like to revoke access to these groups for your ip %s? y/n\n' % s.colors.yellow(ip))
        if pager.getch() != 'y':
            print('abort')
            sys.exit(1)
    for sg in sgs:
        for proto in ['tcp', 'udp']:
            try:
                sg.revoke_ingress(
                    IpProtocol=proto,
                    FromPort=0,
                    ToPort=65535,
                    CidrIp='%s/32' % ip
                )
                print('revoked:', sg.group_name, sg.group_id, end=' ')
            except Exception as e:
                print(re.sub(r'.*\((.*)\).*', r'\1', str(e)) + ':', sg.group_name, sg.group_id, end=' ')
            print(proto)


def images(*name_fragments):
    name_fragments = ('ubuntu/images/',) + name_fragments
    images = list(_ec2().images.filter(Owners=['099720109477'],
                                       Filters=[
                                           {'Name': 'name',
                                            'Values': ['*%s*' % '*'.join(name_fragments)]},
                                           {'Name': 'architecture',
                                            'Values': ['x86_64']},
                                           {'Name': 'virtualization-type',
                                            'Values': ['hvm']}]))
    for name, xs in s.iter.groupby(images, key=lambda x: x.name.split('-')[:-1]):
        image = sorted(xs, key=lambda x: x.creation_date)[-1]
        print(s.colors.green(image.image_id), '-'.join(name))


def main():
    try:
        if s.hacks.override('--stream'):
            with shell.set_stream():
                shell.dispatch_commands(globals(), __name__)
        else:
            shell.dispatch_commands(globals(), __name__)
    except AssertionError as e:
        print(s.colors.red(e.args[0]))
        sys.exit(1)
