from subprocess import check_output

from netmiko import ConnectHandler
import os
from dotenv import load_dotenv  # load credentials from .env file
import jinja2
import napalm
from pathlib import Path

# Create directory path
configurator_files_dir = Path(__file__).parent

host = '192.168.0.101'

def junos_config(malicious_ntp_ips, attack_key):
    print(f'add IPs: {malicious_ntp_ips}')

    load_dotenv()

    username = os.environ.get('USER_NAME')
    passwd = os.environ.get('PASSWD')
    jinja_template = f'{configurator_files_dir}/wan_protect.j2'

    with open(jinja_template, 'r') as j:
        cfg = j.read()
    template = jinja2.Template(cfg)
    output = template.render(ip=malicious_ntp_ips, key=attack_key).strip().split('\n')
    #output = template.render(ip=malicious_ntp_ips, key=attack_key)
    #output = template.render(cfg_list)
    print(output)
    print(type(output))


    junos_device = {'device_type': 'juniper_junos', 'host': host,
                    'username': username, 'password': passwd, 'session_log': 'output.txt' }
    dev = ConnectHandler(**junos_device, fast_cli=True)

    dev.config_mode(config_command='configure private')
    dev.send_config_set(output, exit_config_mode=False)

    dev.commit()

    dev.disconnect()
#junos_config()

def napalm_junos_config(malicious_ntp_ips, attack_key):
    #print(f'add IPs: {malicious_ntp_ips}')
    driver = napalm.get_network_driver("junos")
    optional_args = {'config_private': 'True'}


    load_dotenv()
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