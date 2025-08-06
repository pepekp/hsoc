"""
Query database for ssh login fail messages and block source IP
Create withe list of users that should not be blocked. We are human and some time we forgot our password.
"""

from datetime import datetime, timedelta
import clickhouse_connect
import ipaddress
from configurator.junos_configurator import block_ssh_login

user_whitelist = ['admin', 'root']
client = clickhouse_connect.get_client(host='172.18.0.2', port=8123, username='default', password='', database='siem', apply_server_timezone=True)

def fail_login_detector(time_ago_var, time_now_var):
    result = client.query(f'select host, daemon, lvl, user, ip, msg from siem.syslog where ( time >= \'{time_ago_var}\' '
                          f'AND time <= \'{time_now_var}\' ) AND lvl=\'critical\' AND msg=\'SSH LOGIN FAILED\'')
    src_ip_str = []
    login_counter = {}
    ip_toblock = []

    # loop result, convert IpAddr object to string and append result to list
    for i in result.result_rows:
        src_ip = str(ipaddress.IPv4Address(i[4]))
        src_ip_str.append(src_ip)

    # loop list, count and return dictionary. Dictionary kay=IP, value=count.
    for i in src_ip_str:
        login_counter[i] = login_counter.get(i, 0) + 1

    # loop  to return IP addresses if the counter is above threshold v
    for k, v in login_counter.items():
        print(k, v)
        if v > 5:
            ip_toblock.append(k)
            block_ssh_login(ip_toblock)

