from nornir import InitNornir
from nornir.core.task import AggregatedResult, MultiResult, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config, napalm_get
from nornir.plugins.functions.text import print_title, print_result
from nornir.core import exceptions
from cert_auth import cert_functions as cry
import paramiko
import os
import logging.config
import urllib3
import re
from ssh_expect.ssh_expect import SshExpect
import socket
import datetime
import yaml
import warnings

os.environ["REQUESTS_CA_BUNDLE"] = "./ssl/ca_cert.pem"
os.environ["PYTHONHTTPSVERIFY"] = "1"
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter('error', 'InsecureRequestWarning')

SSL_REQUIRED = ['nxos', 'junos', 'eos']


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

fh = logging.FileHandler(r'./log/add_api.log')
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)


def check_api_status(task):
    status = 'API Disabled'
    if task.host.platform == 'nxos':
        if check_command_response(task,
                                  command='show feature | inc nxapi',
                                  regex_str='nxapi *[0-9]+ *enabled') and \
                check_command_response(task,
                                       command='show run | inc nxapi',
                                       regex_str='nxapi https port 443'):
            status = 'API Enabled'
    elif task.host.platform == 'eos':
        if check_command_response(task,
                                  command='sh management api http-commands | inc Enabled',
                                  regex_str='Enabled: *Yes'):
            status = 'API Enabled'
    elif task.host.platform == 'junos':
        if check_command_response(task,
                                  command='show configuration system services | display set',
                                  regex_str='set system services web-management http'):
            status = 'API Enabled'
    else:
        status = 'Platform has no API'
    logger.info(f'API Status on {task.host.hostname}: {status}')
    return status


def check_command_response(task, command, regex_str, name='Check Command Response'):
    result = task.run(task=netmiko_send_command,
                      name=name,
                      command_string=command,
                      severity_level=logging.DEBUG)
    return True if re.search(regex_str, result.result) else False


def enable_api(task):
    logger.info(f'Enabling API for {task.host.hostname}')
    if task.host.platform == 'nxos':
        config_commands = ['feature nxapi',
                           'nxapi https port 443',
                           'nxapi certificate bootflash:nornir_user_cert.pem key bootflash:nornir_user_key.pem',
                           'no nxapi http',
                           ]

    elif task.host.platform == 'eos':
        config_commands = ['management api http-commands',
                           'no shutdown',
                           ]
    elif task.host.platform == 'junos':
        config_commands = ['set system services web-management https',
                           'set system services web-management https pki-local-certificate Nornir',
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
    logger.info(f'Disabling API for {task.host.hostname}')
    if task.host.platform == 'nxos':
        config_commands = ['no feature nxapi',
                           ]

    elif task.host.platform == 'eos':
        config_commands = ['no management api http-commands',
                           ]
    elif task.host.platform == 'junos':
        config_commands = ['delete system services web-management',
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


def check_tls(task, ca_cert):
    # Is HTTPS Running:
    s = socket.socket()
    status = False
    try:
        s.connect((task.host.hostname, 443))
        port_listening = True
    except socket.error:
        port_listening = False
    # Is certificate in our Trust chain
    if port_listening:
        cert = cry.get_host_cert(task.host.hostname, 443)
        cert_chain_correct = True if cry.cert_is_issued_by(cert, ca_cert) else False
        # Is Date Correct
        if cert_chain_correct:
            date = cry.get_cert_expiry(cert)
            if date > datetime.datetime.utcnow():
                status = True
    if status:
        logger.info(f'TLS certificate for {task.host} is Trusted')
    else:
        logger.warning(f'TLS certificate for {task.host} is NOT Trusted')
    return status


def copy_ssl_files(task, ca_cert, user_key, user_cert, path=''):
    logger.info(f'Copying SSL Certificates and Key to {task.host.hostname}')
    files = {'ca_cert': {'path': f'{path}nornir_ca_cert.pem',
                         'contents': ca_cert},
             'user_key': {'path': f'{path}nornir_user_key.pem',
                          'contents': user_key},
             'user_cert': {'path': f'{path}nornir_user_cert.pem',
                           'contents': user_cert}
             }
    output = ''
    ssh = SshExpect(task)
    ssh.open_sftp()
    for file in files.values():
        output += ssh.send_sftp(file['path'], file['contents'])

    return output


def update_ssl_certs(task, ca_key, ca_cert):
    logger.info(f'Updating SSL Certificates and keys on {task.host.hostname}')
    output = ''
    host_ssl = cry.generate_host_keypair(task.host.hostname, ca_key, ca_cert)
    # Coso Nexus SSL Configuration
    if task.host.platform == 'nxos':
        task.run(task=netmiko_send_config,
                 config_commands='feature sftp-server',
                 name='2.1 Enable SFTP-Server')
        task.run(copy_ssl_files,
                 ca_cert=cry.get_cert_bytes(ca_cert),
                 user_key=host_ssl['key_bytes'],
                 user_cert=host_ssl['cert_bytes'],
                 name='2.2 Copy SSL Certs and key')
    # Arista SSL Configuration
    if task.host.platform == 'eos':
        commands = ['management api http-commands',
                    'protocol https certificate',
                    host_ssl['cert_bytes'].decode(),
                    'EOF',
                    host_ssl['key_bytes'].decode(),
                    'EOF']
        result = task.run(task=netmiko_send_config,
                 name='2.1 Configure SSL Cert and Key',
                 config_commands=commands)
        if 'SSL certificate error: Invalid Certificate' in result.result:
            raise exceptions.NornirSubTaskError('Certificate Failed to Load')
    # Juniper SSL Configuration
    if task.host.platform == 'junos':
        task.run(task=copy_ssl_files,
                 name='2.1 Copy SSL Certs and Key',
                 ca_cert=cry.get_cert_bytes(ca_cert),
                 user_key=host_ssl['key_bytes'],
                 user_cert=host_ssl['cert_bytes'],
                 path='/var/tmp/')
        cfg_pki = ['set security pki ca-profile Nornir-CA ca-identity test',
                   'set security pki ca-profile Nornir-CA revocation-check disable']
        task.run(task=netmiko_send_config,
                 config_commands=cfg_pki,
                 name='2.2 Configure CA PKI Identity')
        commands = ['clear security pki ca-certificate all',
                    'request security pki ca-certificate load ca-profile Nornir-CA '  # Continues ->
                    'filename /var/tmp/nornir_ca_cert.pem',
                    'yes',
                    'clear security pki local-certificate certificate-id Nornir',
                    'clear security pki key-pair certificate-id Nornir',
                    'request security pki local-certificate load filename /var/tmp/nornir_'
                    'user_cert.pem key /var/tmp/nornir_user_key.pem certificate-id Nornir',
                    ]
        expects = [None,
                   '\[yes,no\] \(no\)',
                   'CA certificate for profile Nornir-CA loaded successfully',
                   None,
                   None,
                   'Local certificate loaded successfully',
                   ]
        ssh = SshExpect(task)
        ssh.open_shell()
        output += ssh.commands_expects(commands, expects)
        ssh.close_shell()
        ssh.close_connection()
    return output


def task_wrangler(task, ca_key, ca_cert):
    logger.info(f'Starting to process tasks for {task.host}')
    # task.run(task=disable_api,
    #          name='1 Disable API for testing')
    if task.host.platform in SSL_REQUIRED and check_tls(task, ca_cert) is False:
        task.run(task=update_ssl_certs,
                 name='2 Update SSL Certs',
                 ca_key=ca_key, ca_cert=ca_cert,
                 )
    result = task.run(task=check_api_status,
                      name='3 Pre Enable API Status Check',
                      severity_level=logging.INFO)
    if result.result == 'API Disabled':
        task.run(task=enable_api,
                 name='4 Enable API')
        result = task.run(check_api_status,
                          name='5 Post Enable API Status Check',
                          severity_level=logging.INFO)
        if result.result == 'API Disabled':
            return f'ERROR: Unable to activate API on {task.host.name}'

    task.run(task=napalm_get, getters='facts')


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
    # result = nr.run(task=disable_api, name='Disable API Task')
    # print_result(result, severity_level=logging.INFO)
    # nr = nr.filter(platform='nxos')
    result = nr.run(task=task_wrangler, name='Main Task Wrangler', ca_key=ca_key, ca_cert=ca_cert)
    print_result(result, severity_level=logging.INFO)

    # unpack(result)


if __name__ == "__main__":
    main()
