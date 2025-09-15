"""
Get Juniper ARP table and compare whitelist MAC addresses with router ARP table.
Add event to the database including unknown MAC address in ARP table.
"""
import os
import json
from dotenv import load_dotenv
from netmiko import ConnectHandler
import clickhouse_connect

from get_time import get_time
date_time = get_time()
db_date_time = date_time[1]

def get_arp_cache():
    client = clickhouse_connect.get_client(host='172.18.0.2', port=8123, username='default', password='',
                                           database='siem', apply_server_timezone=True)
    mac_whitelist = ['70:4f:57:6c:d2:c8', '70:4f:57:6c:d2:e9']
    mac_table = []
    load_dotenv()
    host = os.environ.get('HOSTNAME')
    username = os.environ.get('USER_NAME')
    passwd = os.environ.get('PASSWD')
    junos_device = {'device_type': 'juniper_junos', 'host': host,
                    'username': username, 'password': passwd}
    dev = ConnectHandler(**junos_device)
    output = dev.send_command('show arp no-resolve', use_textfsm=True)
    sh_arp = json.dumps(output, indent=4)
    sh_arp_json = json.loads(sh_arp)

    for item in sh_arp_json:
        mac = item['mac_address']
        # Create list of mac addresses
        mac_table.append(mac)

    # Check whether addresses in arp cache match with whitelisted MAC addresses.
    mac_element = set(mac_table) - set(mac_whitelist)
    macs = ' '.join(mac_element)

    # Insert event into event database
    if mac_element != set():
        print(f'MAC address is not in whitelist: {macs}')
        row1 = [db_date_time, 'Juniper SRX', 'ARP', 'Warning', 'none',
                f"Detected unknown MAC address: {macs}"]
        data = [row1]
        client.insert('events', data=data, column_names=['received', 'device', 'type', 'lvl', 'action', 'msg'])
    else:
        pass

get_arp_cache()