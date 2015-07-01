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
    return {x['Key']: x['Value'] for x in instance.tags}


def _ls(*tags, state='running'):
    filters = [{'Name': 'tag:%s' % name, 'Values': [value]}
               for tag in tags
               for name, value in [tag.split('=')]]
    if state != 'all':
        filters += [{'Name': 'instance-state-name', 'Values': [state]}]
    return _ec2().instances.filter(Filters=filters)


def ls(*tags, state='running'):
    for i in _ls(*tags, state=state):
        print(_tags(i)['Name'], i.instance_id, i.state['Name'])


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


def authorize(ip, yes=False):
    sgs = _ec2().security_groups.all()
    print('going to authorize your ip %s to these groups:' % s.colors.yellow(ip))
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
    shell.dispatch_commands(globals(), __name__)
