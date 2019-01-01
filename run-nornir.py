from nornir import InitNornir
from nornir.core.task import AggregatedResult, MultiResult, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config, netmiko_file_transfer
from nornir.plugins.functions.text import print_title, print_result
from cert_auth import cert_functions as cry
import paramiko
import getpass
import os
import sys
import tempfile
import logging
import urllib3
import re

os.environ["REQUESTS_CA_BUNDLE"] = "certs/ca_cert.pem"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_api_status(task):
    # check status Cisco NXOS
    if task.host.platform == 'nxos':
        command_str = 'show feature | inc nxapi'
        re_str = 'nxapi *[0-9]+ *(disabled|enabled)'
    elif task.host.platform == 'eos':
        command_str = 'sh management api http-commands | inc Enabled'
        re_str = 'Enabled: *(Yes|No)'
    elif task.host.platform == 'junos':
        command_str = 'show configuration system services | display set'
        re_str = '(set system services web-management http)'
    else:
        return None
    result = task.run(task=netmiko_send_command,
                      command_string=command_str,
                      name='Check API Status Commands',
                      severity_level=logging.DEBUG)
    re_status = re.search(re_str, result.result)
    if re_status:
        status = re_status.group(1)
        if status == 'Yes' or status == 'enabled' or status == 'set system services web-management http':
            return 'API Enabled'
    return 'API Disabled'


def enable_api(task):
    if task.host.platform == 'nxos':
        config_commands = ['feature nxapi',
                           'feature sftp-server'
                           'nxapi https port 443',
                           'no nxapi http',
                           ]

    elif task.host.platform == 'eos':
        config_commands = ['management api http-commands',
                           'no shutdown',
                           ]
    elif task.host.platform == 'junos':
        config_commands = ['set system services ssh',
                           'set system services netconf ssh',
                           'set system services web-management http',
                           'commit'
                           ]
    else:
        config_commands = ""

    if task.is_dry_run():
        return config_commands
    else:
        task.run(task=netmiko_send_config,
                 config_commands=config_commands,
                 name='Enable API Commands')


def disable_api(task):
    if task.host.platform == 'nxos':
        config_commands = ['no feature nxapi',
                           ]

    elif task.host.platform == 'eos':
        config_commands = ['no management api http-commands',
                           ]
    elif task.host.platform == 'junos':
        config_commands = ['delete system services web-management http',
                           'commit'
                           ]
    else:
        config_commands = ""

    if task.is_dry_run():
        return config_commands
    else:
        task.run(task=netmiko_send_config,
                 config_commands=config_commands,
                 name='Disable API Task')

    return check_api_status(task)


def update_ssl_certs(task, ca_key, ca_cert):
    print(f'Call update_ssl_certs for {task.host.name}')
    host_ssl = dict()

    host_ssl = cry.generate_host_keypair(task.host.hostname, ca_key, ca_cert)
    # host_ssl['key_bytes'] = cry.get_key_bytes(cry.create_key())
    if task.host.platform == 'nxos':
        task.run(task=netmiko_send_config, config_commands='feature sftp-server', name='Enable SFTP-Server')
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(task.host.hostname,
                    username=task.host.username,
                    password=task.host.password,
                    )
        ftp = ssh.open_sftp()
        file_key = ftp.file('nxapi_key.pem', "w", -1)
        file_key.write(host_ssl['key_bytes'])
        file_key.flush()
        file_cert = ftp.file('nxapi_cert.pem', "w", -1)
        file_cert.write(host_ssl['cert_bytes'])
        file_cert.flush()
        ftp.close()
        ssh.close()
    if task.host.platform == 'eos':
        commands = ['management api http-commands',
                    'protocol https certificate',
                    host_ssl['cert_bytes'].decode(),
                    'EOF',
                    host_ssl['key_bytes'].decode(),
                    'EOF']
        task.run(task=netmiko_send_config,
                 config_commands=commands)


def write_remote_file(host, username, password, src, path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password)

    ftp = ssh.open_sftp()
    file = ftp.file(path, "a", -1)
    result = ftp.listdir()
    print(result)
    file.write(src)
    file.flush()
    ftp.close()
    ssh.close()


def task_wrangler(task, ca_key, ca_cert):
    # def _task_wrangler(task):
    result = task.run(check_api_status,
                      name='Pre Enable API Status Check',
                      severity_level=logging.INFO)
    # print(f"{task.host.name} Pre Check {task.host.platform} - {result.result}")
    sys.stdout.flush()
    if result.result == 'API Disabled':
        task.run(enable_api,
                 name='Enable API')
        result = task.run(check_api_status,
                          name='Post Enable API Status Check',
                          severity_level=logging.INFO)
        # print(f"{task.host.name} Post Check {result.result}\n")
        # sys.stdout.flush()
        if result.result == 'API Disabled':
            return f'ERROR: Unable to activate API on {task.host.name}'
    update_ssl_certs(task, ca_key, ca_cert)

    #return _task_wrangler


def unpack(results, depth=0):
    if isinstance(results, AggregatedResult):
        for key, value in results.items():
            print('#' * depth, end='')
            print(f" {key} {value.name} {type(value)}")
            unpack(value, depth + 1)
    elif isinstance(results, MultiResult):
        for mresult in results:
            print('#' * depth, end='')
            print(f" {mresult.name} {type(mresult)}")
            unpack(mresult, depth + 1)
    elif isinstance(results, Result):
        print('#' * depth, end='')
        print(f" {results.name} :\n {results.result}\n")


def transform_inventory(auth_data):
    def _transform_inventory(host):
        """
        Insert the switch login credentials into the inventory
        """
        if not auth_data:
            return

        if 'username' in auth_data:
            host.data["nornir_username"] = auth_data.get('username')
        if 'password' in auth_data:
            host.data["nornir_password"] = auth_data.get('password')

        host.data['auth'] = auth_data

    return _transform_inventory


def main():
    # Create CA
    # passphrase = getpass.getpass('Please enter CA key Passphrase')
    passphrase = 'fred'
    if os.path.isfile('./ssl/ca_key.pem') is False and os.path.isfile('./ssl/ca_cert.pem') is False:
        ca_key = cry.create_key()
        cry.save_key(ca_key, './ssl/ca_key.pem', passphrase)
        ca_csr = cry.create_csr(ca_key, country_name='GB',
                                locality='London',
                                organisation='Tactical Networks',
                                common_name='CA.tactical-net.co.uk',
                                is_ca=True)
        ca_cert = cry.create_cert(ca_key, csr=ca_csr, lifetime=3650, is_ca=True)
        cry.save_cert(ca_cert, './ssl/ca_cert.pem')
    else:
        ca_key = cry.load_key('./ssl/ca_key.pem', passphrase)
        ca_cert = cry.load_cert('./ssl/ca_cert.pem')

    print_title("Playbook to configure the network")
    nr = InitNornir(config_file='config.yaml', dry_run=False)
    result = nr.run(task=disable_api, name='Disable API Task')
    # print_result(result, severity_level=logging.INFO)
    result = nr.run(task=task_wrangler, name='Main Task Wrangler', ca_key=ca_key, ca_cert=ca_cert)
    print_result(result, severity_level=logging.INFO)

    # unpack(result)


if __name__ == "__main__":
    main()
