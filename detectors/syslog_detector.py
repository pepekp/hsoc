"""
Query database for ssh login fail messages and block source IP
Create withe list of users that should not be blocked. We are human and some time we forgot our password.

select host, daemon, lvl, user, ip, msg from siem.syslog where ( time >= '2025-08-05 16:23:00' AND time <= '2025-08-05 16:24:55' ) AND lvl='critical' AND msg='SSH LOGIN FAILED'

"""

from datetime import datetime, timedelta
import clickhouse_connect
import ipaddress
from configurator.junos_configurator import block_ssh_login

user_whitelist = ['pepe', 'root']
client = clickhouse_connect.get_client(host='172.18.0.2', port=8123, username='default', password='', database='siem', apply_server_timezone=True)

def time_period():
    time_now = datetime.now()
    # Define period ago with timedelta
    time_delta = timedelta(minutes=5)
    time_ago = time_now - time_delta
    ta = time_ago.strftime("%Y-%m-%d %H:%M:%S")
    tn = time_now.strftime("%Y-%m-%d %H:%M:%S")
    return [ta, tn] # return list of dates

# time_vars = time_period()
# time_ago_var = time_vars[0]
# time_now_var = time_vars[1]
# print(time_now_var, time_ago_var)

def fail_login_detector(time_ago_var, time_now_var):
#def fail_login_detector(): # test def
    #result = client.query(f'select host, daemon, lvl, user, ip, msg from siem.syslog where ( time >= \'2025-08-05 10:47:37\' '
    #                      f'AND time <= \'2025-08-05 16:29:36\' ) AND lvl=\'critical\' AND msg=\'SSH LOGIN FAILED\'')
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

#fail_login_detector()