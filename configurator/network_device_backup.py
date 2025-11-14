# Backup Juniper router running configuration.

import os
from datetime import datetime
from dotenv import load_dotenv
from jnpr.junos import Device
from lxml import etree
from get_time import get_time
date_time = get_time()
db_today_str = date_time[0]

load_dotenv()
host = os.environ.get('HOSTNAME')
username = os.environ.get('USER_NAME')
passwd = os.environ.get('PASSWD')

def get_juniper_config():
    with Device(host=host, user=username, passwd=passwd) as dev:
        data = dev.rpc.get_config(options={'format':'text'})
        print(etree.tostring(data, encoding='unicode', pretty_print=True))
        cfg_xml = etree.tostring(data)
        with open(f'device_backup/srx_backup_{db_today_str}.cfg', 'wb') as f:
            f.write(cfg_xml)
        f.close()
