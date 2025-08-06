import json
import os
import glob
from datetime import datetime
import subprocess
from json import JSONDecoder, JSONDecodeError
import clickhouse_driver
import ipaddress
import geoip2.database
from geoip2.errors import AddressNotFoundError

from directory_path import  netflow_home_dir, app_logs_directory, flows_dir

print(f'Pars to db: {flows_dir}')

def find_last_created_file() -> str:
    netflow_dir_name = flows_dir
    files_path = os.path.join(netflow_dir_name, '*')
    files = sorted(glob.iglob(files_path), key=os.path.getctime, reverse=True)
    # remove temp nfcapd file
    filelist = [i for i in files if 'current' not in i]
    file_name = filelist[0].split('/')
    last_file_in_dir = file_name[-1]
    return last_file_in_dir

def nfdumper(last_created_netflow_file):
    print(f'Netflow file: {last_created_netflow_file}')
    command = f'nfdump -r {flows_dir}/{last_created_netflow_file} -o json'
    result = subprocess.check_output(command, shell=True, text=True)
    try:
        data = json.loads(result, cls=JSONDecoder)
        # Geolocation reader
        reader = geoip2.database.Reader(f'{netflow_home_dir}/GeoLite2-ASN.mmdb')
        country_reader = geoip2.database.Reader(f'{netflow_home_dir}/GeoLite2-Country.mmdb')

        for item in data:
            flow_type = item['type']
            sampled = item['sampled']
            export_sysid = item['export_sysid']
            # Replace nfdump netflow iso time format
            f = datetime.fromisoformat(item['first'])
            first_time = (f.strftime("%Y-%m-%d %H:%M:%S"))
            item['first'] = item['first'].replace(item['first'], first_time)
            f = datetime.fromisoformat(item['last'])
            last_time = (f.strftime("%Y-%m-%d %H:%M:%S"))
            item['last'] = item['last'].replace(item['last'], last_time)
            f = datetime.fromisoformat(item['received'])
            received_time = (f.strftime("%Y-%m-%d %H:%M:%S"))
            item['received'] = item['received'].replace(item['received'], received_time)
            in_packets = item['in_packets']
            in_bytes = item['in_bytes']
            proto = item['proto']

            # Protocol Numbers to string
            proto_dict = {'icmp': 1, 'igmp': 2, 'tcp': 6, 'udp': 17}
            protocol_str = [k for k, v in proto_dict.items() if v == proto]
            protocol_str = ''.join(protocol_str)
            item['proto'] = str(item['proto']).replace(str(item['proto']), protocol_str)
            try:
                tcp_flags = item['tcp_flags']
            except KeyError:
                pass
            try:
                src_port = item['src_port']
            except KeyError:
                pass
            try:
                dst_port = item['dst_port']
            except KeyError:
                pass
            src_tos = item['src_tos']
            src4_addr = item['src4_addr']
            dst4_addr = item['dst4_addr']
            ip4_router = item['ip4_router']
            label = item['label']

            # Check is src/dst IP address private or public
            is_priv_srcip = ipaddress.ip_address(src4_addr).is_private
            is_priv_dstip = ipaddress.ip_address(dst4_addr).is_private
            is_multicat_srcip = ipaddress.ip_address(src4_addr).is_multicast
            is_multicat_dstip = ipaddress.ip_address(dst4_addr).is_multicast

            # Get ASN of the IP address
            if (is_priv_srcip or is_multicat_srcip) is not True:
                try:
                    response = reader.asn(src4_addr)
                    src_asn = response.autonomous_system_number
                    src_asn_dic = {'src_asn': src_asn}
                    item.update(src_asn_dic)
                    src_asn_name = response.autonomous_system_organization
                    src_asn_name_dic = {'src_asn_org': src_asn_name}
                    item.update(src_asn_name_dic)
                except AddressNotFoundError:
                    pass
            else:
                src_asn_name = 'private'
                src_asn_dic = {'src_asn': 65534}
                item.update(src_asn_dic)
                src_asn_name_dic = {'src_asn_org': src_asn_name}
                item.update(src_asn_name_dic)
            # Get ASN Org name of the IP address
            if (is_priv_dstip or is_multicat_dstip) is not True:
                try:
                    response = reader.asn(dst4_addr)
                    dst_asn = response.autonomous_system_number
                    dst_asn_dic = {'dst_asn': dst_asn}
                    item.update(dst_asn_dic)
                    dst_asn_name = response.autonomous_system_organization
                    dst_asn_name_dic = {'dst_asn_org': dst_asn_name}
                    item.update(dst_asn_name_dic)
                except AddressNotFoundError:
                    pass
            else:
                dst_asn_name = 'private'
                dst_asn_dic = {'dst_asn': 65534}
                item.update(dst_asn_dic)
                dst_asn_name_dic = {'dst_asn_org': dst_asn_name}
                item.update(dst_asn_name_dic)

            # Geolocation by country
            if (is_priv_srcip or is_multicat_srcip) is not True:
                try:
                    src_ip_country = country_reader.country(src4_addr).country.iso_code
                    src_ip_country_dic = {'dst_ip_country': src_ip_country}
                    item.update(src_ip_country_dic)
                except AddressNotFoundError:
                    pass
            else:
                src_ip_country_dic = {'src_ip_country': 'local'}
                item.update(src_ip_country_dic)
            # Destination IP check
            if (is_priv_dstip or is_multicat_dstip) is not True:
                try:
                    dst_ip_country = country_reader.country(dst4_addr).country.iso_code
                    dst_ip_country_dic = {'dst_ip_country': dst_ip_country}
                    item.update(dst_ip_country_dic)
                except AddressNotFoundError:
                    pass
            else:
                dst_ip_country_dic = {'dst_ip_country': 'local'}
                item.update(dst_ip_country_dic)

            parsed_json = json.dumps(item, ensure_ascii=True, allow_nan=True, indent=4, separators=(',', ':'))

            with open(f'{app_logs_directory}/netflow.log', 'a') as appLog_nf:
                appLog_nf.write(parsed_json)
            appLog_nf.close()

            query = f"INSERT INTO siem.netflow FORMAT JSONEachRow {parsed_json}"
            # print(query)
            conn = clickhouse_driver.Client(host='172.18.0.2', port=9000)
            conn.execute(query)
            print('DB load completed')
    except JSONDecodeError as e:
        print(f'No JSON output: {e}')
        pass




