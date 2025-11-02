
import os
from netmiko import ConnectHandler
from dotenv import load_dotenv  # load credentials from .env file
from jnpr.junos import Device
from jnpr.junos.op.ethport import EthPortTable
from jnpr.junos.op.phyport import PhyPortTable, PhyPortStatsTable, PhyPortErrorTable
import textfsm
import json
import re
import clickhouse_connect
from get_time import get_time

date_time = get_time()
db_date_time = date_time[1]

# today = datetime.now()
# today_str = today.strftime("%Y_%m_%d_%H_%M_%S")
# # DB time format
# date_time_var = today.strftime("%Y-%m-%d %H:%M:%S")
# date_time_obj = datetime.strptime(date_time_var, "%Y-%m-%d %H:%M:%S")

# Load device credentials and IP from .env file
load_dotenv()
host = os.environ.get('HOSTNAME')
username = os.environ.get('USER_NAME')
passwd = os.environ.get('PASSWD')

def chassis_routing_engine():
    show_chassis_re = 'show chassis routing-engine'


    junos_device = {'device_type': 'juniper_junos', 'host': host,
                    'username': username, 'password': passwd}
    dev = ConnectHandler(**junos_device)

    output = dev.send_command(show_chassis_re, use_textfsm=True,
                              textfsm_template='juniper_junos_show_chassis_routing_engine.textfsm')
    show_re = json.dumps(output, indent=4)

    show_re_json = json.loads(show_re)
    for item in show_re_json:
        temperature = item['temperature_c']
        cpu_user = item['cpu_user']
        cpu_kernel = item['cpu_kernel']
        cpu_idle = item['cpu_idle']
        model = item['model']
        uptime = item['uptime']
        load_average_one = item['load_average_one']
        load_average_five = item['load_average_five']
        load_average_fifteen = item['load_average_fifteen']

        return temperature, cpu_user, cpu_kernel, cpu_idle, model, uptime, load_average_one, load_average_five, load_average_fifteen
    dev.disconnect()

chassis_re = chassis_routing_engine()

def ping_probe():
    ping = 'ping 8.8.8.8 count 5 do-not-fragment size 1420 rapid'

    junos_device = {'device_type': 'juniper_junos', 'host': host,
                    'username': username, 'password': passwd}
    dev = ConnectHandler(**junos_device)
    output = dev.send_command(ping)

    packet_loss_re = re.search(r"\d{0,3}\%", output)
    round_trip_re = re.search(r"\d+\.\d+\/\d+\.\d+\/\d+\.\d+\/\d+\.\d+", output)
    loss_val = packet_loss_re.group().strip('%')
    round_trip_val = round_trip_re.group().split('/')
    rt_min = round_trip_val[0]
    rt_avg = round_trip_val[1]
    rt_max = round_trip_val[2]

    dev.disconnect()
    return loss_val, rt_min, rt_avg, rt_max

ping_result = ping_probe()

def show_op_table():
    with Device(host=host, user=username, passwd=passwd) as dev:
        eths = EthPortTable(dev)
        eths.get()
        # print(eths.keys())
        # print(eths.values())
        # print(eths.items())
        print('########## Port table view ##########')
        iface = PhyPortTable(dev)
        iface.get()

        for i in iface.keys():
            if i in iface:
                # print(iface.items())
                d = iface.items()
                for v in d:
                    interface = v[0]
                    oper_status = v[1][0]
                    adm_status = v[1][1]
                    description = v[1][2]
                    link_mode = v[1][4]
                    speed = v[1][5]
                    flapped = v[1][7]
                    # print(v[1][0], v[1][1], v[1][2])
                    print(f'interface: {interface}\n link status: {oper_status[1]}\n admin status: {adm_status[1]}\n'
                          f' description: {description[1]}\n link mode: {link_mode[1]}\n interface speed: {speed[1]}\n '
                          f'last flapped: {flapped[1]}')
        print()
        print('########## Physical Ports Error Table ##########')
        iface_view = PhyPortErrorTable(dev)
        iface_view.get()
        for i in iface_view.keys():
            if i in iface_view:
                d = iface_view.items()
                for v in d:
                    # RX statistics
                    interface = v[0]
                    rx_bytes = v[1][0]
                    rx_packets = v[1][1]
                    rx_err_input = v[1][4]
                    rx_err_drops = v[1][5]
                    rx_err_frame = v[1][6]
                    rx_err_runts = v[1][7]
                    rx_err_discards = v[1][8]
                    rx_err_l3_incompletes = v[1][9]
                    rx_err_l2_channel = v[1][10]
                    rx_err_l2_mismatch = v[1][11]
                    rx_err_fifo = v[1][12]
                    rx_err_resource = v[1][13]

                    # TX statistics
                    tx_bytes = v[1][2]
                    tx_packets = v[1][3]
                    tx_err_carrier_transitions = v[1][14]
                    tx_err_output = v[1][15]
                    tx_err_collisions = v[1][16]
                    tx_err_drops = v[1][17]
                    tx_err_aged = v[1][18]
                    tx_err_mtu = v[1][19]
                    tx_err_hs_crc = v[1][20]
                    tx_err_fifo = v[1][21]
                    tx_err_resource = v[1][22]

                    print(f'Interface errors: {interface}\nRX stats:\n rx bytes: {rx_bytes[1]}\n rx packets: {rx_packets[1]}\n'
                          f' rx err input: {rx_err_input[1]}\n rx err drops: {rx_err_drops[1]}\n rx err frame: {rx_err_frame[1]}\n'
                          f' rx err runts: {rx_err_runts[1]}\n rx err discards: {rx_err_discards[1]}\n rx err l3 incompletes: {rx_err_l3_incompletes[1]}\n'
                          f' rx err l2channel: {rx_err_l2_channel[1]}\n rx err l2mismatch: {rx_err_l2_mismatch[1]}\n'
                          f' rx err fifo: {rx_err_fifo[1]}\n rx err resource: {rx_err_resource[1]}')
                    print(f'TX stats:\n tx bytes: {tx_bytes[1]}\n tx packets: {tx_packets[1]}\n'
                          f' tx err carrier transitions: {tx_err_carrier_transitions[1]}\n tx err output: {tx_err_output[1]}\n'
                          f' tx err collisions: {tx_err_collisions[1]}\n tx err drops: {tx_err_drops[1]}\n'
                          f' tx err aged: {tx_err_aged[1]}\n tx err mtu: {tx_err_mtu[1]}\n tx err hs crc: {tx_err_hs_crc[1]}\n'
                          f' tx err fifo: {tx_err_fifo[1]}\n tx err resource: {tx_err_resource[1]}')


show_op_table()

# Insert device statistics into database
def db_insert():
    # Create list and append returned values from chassis_routing_engine() and ping_probe() functions.
    db_record = [db_date_time]
    for i in chassis_re:
        db_record.append(i)
    for i in ping_result:
        db_record.append(i)

    client = clickhouse_connect.get_client(host='172.18.0.2', port=8123,
                      username='default', password='', database='siem', apply_server_timezone=True)
    data = [db_record]
    client.insert('network_device', data=data, column_names=['received', 'temperature', 'cpu_user',
                        'cpu_kernel', 'cpu_idle', 'model', 'uptime', 'load_average_one', 'load_average_five', 'load_average_fifteen',
                        'ping_loss', 'ping_min', 'ping_avg', 'ping_max'])

db_insert()

