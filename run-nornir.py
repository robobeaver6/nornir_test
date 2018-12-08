import jinja2
from nornir.core import InitNornir
from nornir.plugins.tasks import networking, text
from nornir.plugins.tasks.networking import napalm_get
from nornir.plugins.functions.text import print_title, print_result
import napalm.base.exceptions
import os
import logging
from pprint import pprint
import urllib3

os.environ["REQUESTS_CA_BUNDLE"] = "certs/cacert.pem"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# nr = InitNornir(num_workers=1, dry_run=False)

# result = nr.run(
#             napalm_get,
#             # getters Tested:
#             # get_facts
#             # get_arp_table
#             # get_bgp_config
#             # get_bgp_neighbors
#             # get_bgp_neighbors_detail
#             # get_config
#             # get_environment
#             # get_interfaces
#             # get_interfaces_counters
#             # get_interfaces_ip
#             # get_ipv6_neighbors_table
#             # get_lldp_neighbors
#             # get_lldp_neighbors_detail
#             # get_mac_address_table
#             # get_network_instances
#             # get_ntp_peers
#             # get_ntp_servers
#             # get_ntp_stats
#             # get_optics
#             # get_probes_results
#             # get_route_to    -  Needs a destination= variable not sure how to pass it
#             # get_snmp_information
#             # get_users
#             # is_alive - Doesn't work on nxos or eos
#             getters=['get_config'])
# print_result(result)

# def basic_configuration(task):
#     # Transform inventory data to configuration via a template file
#     print("DEBUG: HOST:{} - MGMT_SVR:{}".format(task.host, task.host['mgmt_svrs']))
#     try:
#         # print("Create Config")
#         r = task.run(task=text.template_file,
#                      name="Base Configuration",
#                      template="management.j2",
#                      path="templates/{}".format(task.host.nos))
#         task.host["config"] = r.result
#     except jinja2.exceptions.TemplateNotFound:
#         print("Template Not Found For {}".format(task.host))
#
#     # Deploy that configuration to the device using NAPALM
#     print("Deploy Config {}".format(task.host))
#
#     task.run(task=networking.napalm_configure,
#              name="Loading Configuration on the device",
#              replace=False,
#              configuration=task.host["config"])

def ca_check_key(task):
    # Does key already Exists?
    cmd_check_key = 'show crypto key mypubkey rsa'
    result = task.run(task=networking.netmiko_send_command,
                      command_string=cmd_check_key,
                      severity_level=logging.DEBUG)
    key_list = []
    for line in result.result.split('\n'):
        # print(line)
        if 'key label:' in line:
            key_list.append(line.split(': ')[1])
    if task.host['cert_key_name'] in key_list:
        return True
    else:
        return False


def ca_enroll_root(task):
    # CA Certificate
    with open('certs/cacert.pem', 'r') as ca_cert_file:
        ca_cert = ca_cert_file.readlines()
    ca_cert += '\nEND OF INPUT\n'

    # Create Key if required
    if ca_check_key(task) is False:
        cmd_str = 'crypto key generate rsa label {} modulus 2048'.format(task.host['cert_key_name'])
        result = task.run(task=networking.netmiko_send_config,
                          config_commands=cmd_str)
        if not result.failed:
            print('New Key Created')
    else:
        print('Key Already Exists')

    # Create Trustpoint
    cfg_trustpoint = task.run(task=text.template_file,
                              name="Base Configuration",
                              template="trustpoint.j2",
                              path="templates/{}".format(task.host.nos))

    result = task.run(task=networking.napalm_configure,
                      configuration=cfg_trustpoint.result,
                      severity_level=logging.DEBUG,
                      dry_run=True
                      )

    print(result.diff)

    # cmd_str = 'crypto ca authenticate {}'.format(task.host['cert_key_name'])
    # print(cmd_str)
    # result = task.run(task=networking.netmiko_send_command,
    #                   command_string=cmd_str,
    #                   expect_string='END OF INPUT :',
    #                   severity_level=logging.DEBUG)
    # print('Step 3')
    # ca_cert += 'END OF INPUT\n'
    # print(ca_cert)
    # result = task.run(task=networking.netmiko_send_command,
    #                   command_string=ca_cert)


def main():
    print_title("Playbook to configure the network")
    nr = InitNornir(num_workers=1, dry_run=False)
    filter_group = nr.filter(nornir_nos='nxos')
    # result = nr.run(task=basic_configuration)
    result = filter_group.run(task=ca_enroll_root)
    print_result(result, severity_level=logging.DEBUG)


if __name__ == "__main__":
    main()
