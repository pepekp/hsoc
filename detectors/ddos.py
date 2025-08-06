"""
Query database for traffic sourced from UDP port 123 for certain period

db query SELECT received as "time", in_bytes, proto, src_port FROM "siem"."netflow" WHERE
( time >= '2025-06-24 10:06:17' AND time <= '2025-06-24 10:07:33' ) and proto='udp' and dst_port=123 ORDER BY time ASC

with src IP addr and JSON format
 SELECT received as "time", in_bytes, proto, src_port, src4_addr FROM "siem"."netflow" WHERE
  ( time >= '2025-06-24 10:06:17' AND time <= '2025-06-24 10:07:33' ) and proto='udp' and dst_port=123 ORDER BY time ASC format JSONEachRow

SELECT received as "time", in_bytes, proto, src_port, src4_addr FROM "siem"."netflow" WHERE ( time >= '2025-06-24 10:06:17' AND time <= '2025-06-24 10:07:33' ) AND proto='udp' AND dst_port=123 GROUP BY * ORDER BY time ASC

1. Get time interval with time delta. Time format 2025-06-24 10:06:30
2. Query database
3. Distinguish whether the traffic is malicious or not based on volumetric and a whitelist of defined ntp servers
4. Prepare network device config if needed based on the previous step.
5. Generate and store security event to the database.

"""
from datetime import datetime, timedelta
import json
import clickhouse_driver
import clickhouse_connect
import ipaddress
from configurator.junos_configurator import junos_config
from configurator.junos_configurator import napalm_junos_config


# Define whitehost addresses, always add 0.0.0.0 address for safety
ntp_whitelist = ['0.0.0.0', '77.236.182.128', '8.120.162.35', '91.2 10.88.37', '162.159.200.123', '120.25.112.107']
dns_whitelist = ['0.0.0.0', '8.8.8.8', '8.8.4.4']
memcached_whitelist = ['0.0.0.0']

# Database connection client
client = clickhouse_connect.get_client(host='172.18.0.2', port=8123, username='default', password='', database='siem', apply_server_timezone=True)

# Threshold to trigger security event
ntp_bytes_threshold = 500
dns_bytes_threshold = 500
memcached_bytes_threshold = 500

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

def ntp_db_query(time_ago_var, time_now_var):
    result = client.query(f'SELECT received as "time", in_bytes, proto, src_port, src4_addr FROM siem.netflow WHERE (time >= \'{time_ago_var}\' AND time <= \'{time_now_var}\') AND (proto=\'udp\') AND (src_port=123)')
    # Process query
    src_ip_str = []
    for i in result.result_rows:
        src_ip = str(ipaddress.IPv4Address(i[4]))
        src_ip_str.append(src_ip)
    # Compare lists of IP's with NTP white hosts and return malicious set of IP addr.
    malicious_ntp = set(src_ip_str) - set(ntp_whitelist)
    #print(malicious_ntp)
    # Count NTP traffic source IP's
    if malicious_ntp != {}:
        count_ntp_host = len(malicious_ntp)
    else:
        pass
    # Query DB to return sum of bytes for time period
    sum_query_test = client.query(f'SELECT sum(in_bytes) from siem.netflow WHERE (received >= \'{time_ago_var}\' AND received <= \'{time_now_var}\') AND (proto=\'udp\') AND (src_port=123)')
    bytes_sum = sum_query_test.result_rows[0]
    #print(type(bytes_sum))
    bytes_sum = int(bytes_sum[0])
    #count_ntp_host = int(count_ntp_host)
    print(f"DB query function return: {malicious_ntp}, {bytes_sum}, {count_ntp_host}")
    return malicious_ntp, bytes_sum, count_ntp_host

# db_query_result = ntp_db_query()
# print(db_query_result[0])
#ntp_bytes_received = db_query_result[1]
#count_ntp_hosts = db_query_result[2]

def ntp_event_gen(time_now_var, ntp_bytes_received, count_ntp_hosts, malicious_ntp):
    print('Generate and push event to database')
    if ntp_bytes_received > ntp_bytes_threshold:
        print('Threshold violated...')
        # Convert time_now str to DateTime object
        date_time_obj = datetime.strptime(time_now_var, "%Y-%m-%d %H:%M:%S")
        print(date_time_obj)
        row1 = [date_time_obj, 'Juniper SRX', 'NTP DDoS', 'Emergency', 'push',
                f"Received {ntp_bytes_received} Bytes from {count_ntp_hosts} hosts"]
        data = [row1]
        client.insert('events', data=data, column_names=['received', 'device', 'type', 'lvl', 'action', 'msg'])
        # Jinja2 attack type key
        attack_key = 1
        # Call configurator to push configuration
        #import configurator
        junos_config(malicious_ntp, attack_key)
    else:
        print('No malicious NTP traffic')
#ntp_event_gen()

# Query database for malicious DNS traffic

def dns_db_query(time_ago_var, time_now_var):
    #result = client.query('SELECT received as "time", in_bytes, proto, src_port, src4_addr FROM siem.netflow WHERE (time >= \'2025-07-04 12:20:29\' AND time <= \'2025-07-04 12:24:50\') AND (proto=\'udp\') AND (src_port=53)')
    result = client.query(f'SELECT received as "time", in_bytes, proto, src_port, src4_addr FROM siem.netflow WHERE (time >= \'{time_ago_var}\' AND time <= \'{time_now_var}\') AND (proto=\'udp\') AND (src_port=53)')
    # Process query
    src_ip_str = []
    for i in result.result_rows:
        src_ip = str(ipaddress.IPv4Address(i[4]))
        src_ip_str.append(src_ip)
    # Compare lists of IP's with NTP white hosts and return malicious set of IP addr.
    malicious_dns = set(src_ip_str) - set(dns_whitelist)
    #print(malicious_dns)
    # Count NTP traffic source IP's
    if malicious_dns != {}:
        count_dns_host = len(malicious_dns)
    else:
        pass
    # Query DB to return sum of bytes for time period

    sum_query_test = client.query(f'SELECT sum(in_bytes) from siem.netflow WHERE (received >= \'{time_ago_var}\' AND received <= \'{time_now_var}\') AND (proto=\'udp\') AND (src_port=53)')
    bytes_sum = sum_query_test.result_rows[0]
    #print(type(bytes_sum))
    bytes_sum = int(bytes_sum[0])
    #count_ntp_host = int(count_ntp_host)
    print(f"DB query function return: {malicious_dns}, {bytes_sum}, {count_dns_host}")
    return malicious_dns, bytes_sum, count_dns_host

# db_query_result = db_query()
# print(db_query_result[0])
#ntp_bytes_received = db_query_result[1]
#count_ntp_hosts = db_query_result[2]

def dns_event_gen(time_now_var, dns_bytes_received, count_dns_hosts, malicious_dns):
    if dns_bytes_received > dns_bytes_threshold:
        print('DNS Threshold violated...')
        # Convert time_now str to DateTime object
        date_time_obj = datetime.strptime(time_now_var, "%Y-%m-%d %H:%M:%S")
        print(date_time_obj)
        row1 = [date_time_obj, 'Juniper SRX', 'DNS DDoS', 'Emergency', 'push',
                f"Received {dns_bytes_received} Bytes from {count_dns_hosts} hosts"]
        data = [row1]
        client.insert('events', data=data, column_names=['received', 'device', 'type', 'lvl', 'action', 'msg'])

        attack_key = 2
        # Call configurator to push configuration
        import configurator
        junos_config(malicious_dns, attack_key)
    else:
        print('No malicious DNS traffic')

# Memcached DDoS attack
def memcached_db_query(time_ago_var, time_now_var):
    result = client.query(f'SELECT received as "time", in_bytes, proto, src_port, src4_addr FROM siem.netflow WHERE (time >= \'{time_ago_var}\' AND time <= \'{time_now_var}\') AND (proto=\'udp\') AND (src_port=11211)')
    # Process query
    src_ip_str = []
    for i in result.result_rows:
        src_ip = str(ipaddress.IPv4Address(i[4]))
        src_ip_str.append(src_ip)
    # Compare lists of IP's with NTP white hosts and return malicious set of IP addr.
    malicious_memcached = set(src_ip_str) - set(memcached_whitelist)
    #print(memcached_whitelist)
    # Count Memchached traffic source IP's
    if malicious_memcached != {}:
        count_memcached_host = len(malicious_memcached)
    else:
        pass
    # Query DB to return sum of bytes for time period
    #sum_query_test = client.query(f'SELECT sum(in_bytes) from siem.netflow WHERE (received >= \'2025-07-04 12:20:29\' AND received <= \'2025-07-04 12:24:50\') AND (proto=\'udp\') AND (src_port=53)')
    sum_query_test = client.query(f'SELECT sum(in_bytes) from siem.netflow WHERE (received >= \'{time_ago_var}\' AND received <= \'{time_now_var}\') AND (proto=\'udp\') AND (src_port=11211)')
    bytes_sum = sum_query_test.result_rows[0]
    #print(type(bytes_sum))
    bytes_sum = int(bytes_sum[0])
    #count_ntp_host = int(count_ntp_host)
    print(f"DB query function return: {malicious_memcached}, {bytes_sum}, {count_memcached_host}")
    return malicious_memcached, bytes_sum, count_memcached_host

# db_query_result = db_query()
# print(db_query_result[0])
#ntp_bytes_received = db_query_result[1]
#count_ntp_hosts = db_query_result[2]

def memcached_event_gen(time_now_var, memcached_bytes_received, count_memcached_hosts, malicious_memcached):
    if memcached_bytes_received > memcached_bytes_threshold:
        print('Memcached Threshold violated...')
        # Convert time_now str to DateTime object
        date_time_obj = datetime.strptime(time_now_var, "%Y-%m-%d %H:%M:%S")
        print(date_time_obj)
        row1 = [date_time_obj, 'Juniper SRX', 'Memcached DDoS', 'Emergency', 'push',
                f"Received {memcached_bytes_received} Bytes from {count_memcached_hosts} hosts"]
        data = [row1]
        client.insert('events', data=data, column_names=['received', 'device', 'type', 'lvl', 'action', 'msg'])
        attack_key = 3
        # Call configurator to push configuration
        import configurator
        napalm_junos_config(malicious_memcached, attack_key)
    else:
        print('No malicious Memcached traffic')

