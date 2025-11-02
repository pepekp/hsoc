"""
Detect network scans based on netflow data collection

- Detect TCP flags SYN-RST or RST
- Detect nmap scan traffic originating from single host

  https://nmap.org/book/scan-methods.html
  nmap     - single src port, SYN | return SYN RST to single port
  nmap -sS - single src port, SYN | return SYN RST to single port
  nmap -sT - random src port | return SYN RST to random ports
  nmap -sN - singe src port, no tcp flags | return SYN RST to single port
  nmap -sX - single src port, FIN PSH URG | return SYN RST to single port
"""

import clickhouse_connect
import ipaddress
import pandas as pd
client = clickhouse_connect.get_client(host='172.18.0.2', port=8123, username='default', password='', database='siem', apply_server_timezone=True)
#result = client.query(f"select received, src4_addr, src_port, dst4_addr, dst_port, tcp_flags from siem.netflow where (received >= \'2025-08-18 12:00:00\' AND received <= \'2025-08-18 12:05:00\') AND tcp_flags=\'...A.R..\'")
# Query fixed time interval
result = client.query(f"select received, src4_addr, src_port, dst4_addr, dst_port, tcp_flags from siem.netflow where (received >= \'2025-08-18 12:01:51\' AND received <= \'2025-08-18 12:04:51\')")
src_ip_str = []
src_port = []
dst_ip_str = []
dst_port = []
flags = []
src_ip_counter = 0
src_port_counter = 0
dst_ip_counter = 0
dst_port_counter = 0



for i in result.result_rows:
    #print(i)
    src_ip = str(ipaddress.IPv4Address(i[1]))
    src_ip_str.append(src_ip)
    src_port.append(i[2])
    dst_ip = str(ipaddress.IPv4Address(i[3]))
    dst_ip_str.append(dst_ip)
    dst_port.append(i[4])

#print(src_ip_str, src_port)
#print(dst_ip_str, dst_port)
src_ip_dict = {}
for i in src_ip_str:
    src_ip_dict[i]=src_ip_str.count(i)
print(src_ip_dict)
for k, v in src_ip_dict.items():
    if v > 200:
        ip = k
        src_ip_result = client.query(
            f"select received, src4_addr, src_port, dst4_addr, dst_port, tcp_flags from siem.netflow where (received >= \'2025-08-18 12:01:51\' AND received <= \'2025-08-18 12:04:51\') AND src4_addr = '{ip}'")
        print('src_ip_result')
        for i in src_ip_result.result_rows:
            print(i)
            flags.append(i[5])
            for i in flags:
                if i == '..U.P..F':
                    print('Xmas scan ')
                if i == '........':
                    print('Null scan ')


src_port_dict = {}
#print(src_port)
for i in src_port:
    src_port_dict[i]=src_port.count(i)
print(src_port_dict)

dst_ip_dict = {}
for i in dst_ip_str:
    dst_ip_dict[i]=dst_ip_str.count(i)
print(dst_ip_dict)

dst_port_dict = {}
#print(src_port)
for i in dst_port:
    dst_port_dict[i]=dst_port.count(i)
print(dst_port_dict)

