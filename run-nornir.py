import jinja2
from nornir import InitNornir
from nornir.core import task
from nornir.plugins.tasks import networking, text
from nornir.plugins.tasks.networking import napalm_get, netmiko_send_command, netmiko_send_config
from nornir.plugins.functions.text import print_title, print_result
import napalm.base.exceptions
import os
import sys
import logging
from pprint import pprint
import urllib3
import cert_functions
import re

os.environ["REQUESTS_CA_BUNDLE"] = "certs/ca_cert.pem"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_api_status_v2(task):
    # check status Cisco NXOS
    if task.host.platform == 'nxos':
        command_str='show feature | inc nxapi'
        re_str = 'nxapi *[0-9]+ *(disabled|enabled)'
    elif task.host.platform == 'eos':
        command_str='sh management api http-commands | inc Enabled'
        re_str = 'Enabled: *(Yes|No)'
    elif task.host.platform == 'junos':
        command_str='show configuration system services | display set'
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
            return True
    return False


def enable_api_v2(task):
    if task.host.platform == 'nxos':
        config_commands = ['feature nxapi',
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


def disable_api_v2(task):
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

    if check_api_status_v2(task):
        return f"API Disabled"


def task_wrangler(task):
    result = task.run(check_api_status_v2,
                      name='Pre Enable API Status Check',
                      severity_level=logging.INFO)
    # print(f"{task.host.name} Pre Check {task.host.platform} - {result.result}")
    # sys.stdout.flush()
    if result.result is False:
        task.run(enable_api_v2,
                 name='Enable API')
        result = task.run(check_api_status_v2,
                          name='Post Enable API Status Check',
                          severity_level=logging.INFO)
        # print(f"{task.host.name} Post Check {result.result}\n")
        # sys.stdout.flush()
        if result.result is False:
            return f'ERROR: Unable to activate API on {task.host.name}'


def unpack(results, depth=0):
    if isinstance(results, task.AggregatedResult):
        for key, value in results.items():
            print('#' * depth, end='')
            print(f" {key} {value.name} {type(value)}")
            unpack(value, depth+1)
    elif isinstance(results, task.MultiResult):
        for mresult in results:
            print('#' * depth, end='')
            print(f" {mresult.name} {type(mresult)}")
            unpack(mresult, depth + 1)
    elif isinstance(results, task.Result):
        print('#' * depth, end='')
        print(f" {results.name} :\n {results.result}\n")


def main():
    print_title("Playbook to configure the network")
    nr = InitNornir(config_file='config.yaml', dry_run=False)
    # result = nr.run(task=disable_api_v2, name='Disable API Task')
    # print_result(result, severity_level=logging.INFO)
    result = nr.run(task=task_wrangler, name='Main Task Wrangler')
    print_result(result, severity_level=logging.INFO)

    # unpack(result)


if __name__ == "__main__":
    main()
