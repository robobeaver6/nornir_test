import jinja2
from nornir.core import InitNornir
from nornir.plugins.tasks import networking, text
from nornir.plugins.tasks.networking import napalm_get
from nornir.plugins.functions.text import print_title, print_result
import napalm.base.exceptions

nr = InitNornir(num_workers=1, dry_run=True)

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

def basic_configuration(task):
    # Transform inventory data to configuration via a template file
    # print("DEBUG: HOST:{} - MGMT_SVR:{}".format(task.host, task.host['mgmt_svr_1']))
    try:
        # print("Create Config")
        r = task.run(task=text.template_file,
                     name="Base Configuration",
                     template="management.j2",
                     path="templates/{}".format(task.host.nos))
    except jinja2.exceptions.TemplateNotFound:
        print("Template Not Found For {}".format(task.host))

    # Save the compiled configuration into a host variable
    task.host["config"] = r.result

    # Deploy that configuration to the device using NAPALM
    # print("Deploy Config {}".format(task.host))
    try:
        task.run(task=networking.napalm_configure,
                 name="Loading Configuration on the device",
                 replace=False,
                 configuration=task.host["config"])
    except napalm.base.exceptions.MergeConfigException as e:
        print("ERROR: {}".format(e))
    except napalm.base.exceptions.ReplaceConfigException as e:
        print("ERROR: {}".format(e))


print_title("Playbook to configure the network")
result = nr.run(task=basic_configuration)
print_result(result)
# print("Failed Hosts: {}".format(result.failed_hosts))
