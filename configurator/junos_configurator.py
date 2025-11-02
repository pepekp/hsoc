"""
Juniper configuration tool

"""

import os
from dotenv import load_dotenv  # load credentials from .env file
import jinja2
import napalm
from pathlib import Path

# Create directory path
configurator_files_dir = Path(__file__).parent

def napalm_junos_config(malicious_ntp_ips, malicious_dns, attack_key):
    #print(f'add IPs: {malicious_ntp_ips}')
    driver = napalm.get_network_driver("junos")
    optional_args = {'config_private': 'True'}


    load_dotenv()
    host = os.environ.get('HOSTNAME')
    username = os.environ.get('USER_NAME')
    passwd = os.environ.get('PASSWD')

    with open(f'{configurator_files_dir}/load_wan_protect.j2', 'r') as j:
        cfg = j.read()

    template = jinja2.Template(cfg, keep_trailing_newline=True, newline_sequence='\n', autoescape=True)
    output = template.render(ip=malicious_ntp_ips, key=attack_key)
    print(type(output))
    print(output)
    # Generate junos configuration
    with open('load_test.cfg', 'w') as f:
        f.writelines(output)
    f.close()

    # Connect:
    device = driver(
        hostname=host,
        username=username,
        password=passwd,
        optional_args=optional_args
    )

    print(f'Opening {host}...')
    device.open()

    print("Loading merge candidate configuration...")
    device.load_merge_candidate(filename='load_test.cfg')
    device.commit_config()
    print("Loading has been completed")

def block_ssh_login(ip_toblock):


    driver = napalm.get_network_driver("junos")
    optional_args = {'config_private': 'True'}

    load_dotenv()
    host = os.environ.get('HOSTNAME')
    username = os.environ.get('USER_NAME')
    passwd = os.environ.get('PASSWD')

    with open(f'{configurator_files_dir}/load_ssh_protect.j2', 'r') as j:
        cfg = j.read()

    template = jinja2.Template(cfg, keep_trailing_newline=True, newline_sequence='\n', autoescape=True)
    output = template.render(ip=ip_toblock)
    # print(type(output))
    print(output)
    # Generate junos configuration
    with open('load_ssh.cfg', 'w') as f:
        f.writelines(output)
    f.close()

    # Connect:
    device = driver(
        hostname=host,
        username=username,
        password=passwd,
        optional_args=optional_args
    )

    print(f'Opening {host}...')
    device.open()

    print("Loading merge candidate configuration...")
    device.load_merge_candidate(filename='load_ssh.cfg')
    device.commit_config()
    print("Loading of configuration has been completed")
    os.remove('load_ssh.cfg')