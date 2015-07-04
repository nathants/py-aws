import s.cached
import re
import s.colors
import pager
import sys
import s.exceptions
import shell
import boto3


@s.cached.func
def _ec2():
    return boto3.resource('ec2')


def _tags(instance):
    return {x['Key']: x['Value'] for x in (instance.tags or {})}


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
        t = _tags(instance).get(k, '')
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
    return ' '.join([
        s.colors.green(_name(instance)),
        s.colors.yellow(instance.instance_id),
        s.colors.cyan(instance.state['Name']),
        ' '.join([s.colors.red(x['GroupName']) for x in instance.security_groups]),
        s.colors.blue(instance.public_dns_name or '<no-ip>'),
        s.colors.magenta(instance.private_dns_name or '<no-ip>'),
        ' '.join('%s=%s' % (k, v) for k, v in _tags(instance).items() if k != 'Name' and v),
    ])

def _name(instance):
    return _tags(instance).get('Name', '<no-name>')


def _name_group(instance):
    return '%s:%s' % (_tags(instance).get('Name', '<no-name>'), instance.instance_id)


def ips(*tags, first_n=None, last_n=None):
    for i in _ls(tags, 'running', first_n, last_n):
        print(i.public_dns_name)


def ls(*tags, state='all', first_n=None, last_n=None):
    for i in _ls(tags, state, first_n, last_n):
        print(_pretty(i))


def stop(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot stop all things, specify some tags'
    instances = _ls(tags, 'running', first_n, last_n)
    assert instances, 'didnt find any running instances for those tags'
    print('going to stop the following instances:\n')
    for i in instances:
        print('', _pretty(i))
    print('\nwould you like to proceed? y/n\n')
    if not (yes or pager.getch() == 'y'):
        print('abort')
        sys.exit(1)
    for i in instances:
        i.stop()
        print('stopped:', _pretty(i))


def start(*tags, yes=False, first_n=None, last_n=None):
    assert tags, 'you cannot start all things, specify some tags'
    instances = _ls(tags, 'stopped', first_n, last_n)
    assert instances, 'didnt find any stopped instances for those tags'
    print('going to start the following instances:\n')
    for i in instances:
        print('', _pretty(i))
    print('\nwould you like to proceed? y/n\n')
    if not (yes or pager.getch() == 'y'):
        print('abort')
        sys.exit(1)
    for i in instances:
        i.start()
        print('started:', _pretty(i))


def _has_wildcard_permission(sg, ip):
    assert '/' not in ip
    for sg_perm in sg.ip_permissions:
        with s.exceptions.ignore(KeyError):
            all_ports = sg_perm['FromPort'] in [0, 1] and sg_perm['ToPort'] == 65535
            matches_ip = any(x['CidrIp'] == ip + '/32' for x in sg_perm['IpRanges'])
            if all_ports and matches_ip:
                return True


def _wildcard_security_groups(ip):
    return [sg for sg in _ec2().security_groups.all()
            if _has_wildcard_permission(sg, ip)]

def auths(ip):
    for sg in _wildcard_security_groups(ip):
        yield '%s [%s]' % (sg.group_name, sg.group_id)


def authorize(ip, *names, yes=False):
    sgs = _ec2().security_groups.all()
    print('going to authorize your ip %s to these groups:' % s.colors.yellow(ip))
    if names:
        sgs = [x for x in sgs if x.group_name in names]
    for sg in sgs:
        print('', '%s [%s]' % (sg.group_name, sg.group_id))
    print('\nwould you like to authorize access to these groups for your ip %s? y/n\n' % s.colors.yellow(ip))
    if not (yes or pager.getch() == 'y'):
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


def revoke(ip, yes=False):
    sgs = _wildcard_security_groups(ip)
    print('your ip %s is currently wildcarded to the following security groups:\n' % s.colors.yellow(ip))
    for sg in sgs:
        print('', '%s [%s]' % (sg.group_name, sg.group_id))
    print('\nwould you like to revoke access to these groups for your ip %s? y/n\n' % s.colors.yellow(ip))
    if not (yes or pager.getch() == 'y'):
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


def main():
    try:
        shell.dispatch_commands(globals(), __name__)
    except AssertionError as e:
        print(s.colors.red(e.args[0]))
        sys.exit(1)
