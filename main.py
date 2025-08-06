import os
import threading
import time
import subprocess
import multiprocessing
import schedule
from schedule import every, repeat, run_pending
from netflow import netflow_pars_to_db
from sysloging import syslog_srv_v1
from detectors import ddos, syslog_detector

def netflow():
    print("Starting netflow collector...")
    run_nfcapd = 'nfcapd -p 2055 -t 300 -w ./netflow/flows/'
    try:
        print('Run Nfcapd')
        #nfc = subprocess.Popen(run_nfcapd, shell=True, stdout=subprocess.PIPE)
        nfc = subprocess.Popen(run_nfcapd, shell=True, stdout=subprocess.PIPE)
        #os.system(command=run_nfcapd)
        #netflow_pars_to_db.find_last_created_file().main()
        #netflow_pars_to_db.nfdumper()
        print(nfc.pid)
    except (IOError, SystemExit) as f:
        print(f"Error starting netflow collector: {f}")
        #nfc.terminate()
    except KeyboardInterrupt:

        print("Crtl+C Pressed. Shutting down nfcapd.")

def syslog():
    print('Starting syslog server...')
    syslog_srv_v1.main()
    print('Syslog server is closed')

@repeat(every(5).minutes)
def netflow_parser():
    print('Start netflow parser...')
    last_created_netflow_file = netflow_pars_to_db.find_last_created_file()
    netflow_pars_to_db.nfdumper(last_created_netflow_file)
    time.sleep(5)
    print('Netflow parser competed')

@repeat(every(5).minutes)
def syslog_parser():
    print('Start Log Parser...')
    from sysloging import log_parser_v1
    last_syslog_file = log_parser_v1.find_last_syslogfile()
    log_parser_v1.syslog_processor(last_syslog_file)
    print('Log parser completed')

@repeat(every(5).minutes)
def event_detector():
    print('Start Event detector...')
    time_vars = ddos.time_period()
    time_ago_var = time_vars[0]
    time_now_var = time_vars[1]

    # Syslog SSH

    syslog_detector.fail_login_detector(time_ago_var, time_now_var)
    #syslog_detector.fail_login_detector()

    # NTP DDoS
    db_query_result = ddos.ntp_db_query(time_ago_var, time_now_var)
    malicious_ntp =  db_query_result[0]
    ntp_bytes_received = db_query_result[1]
    count_ntp_hosts = db_query_result[2]
    ddos.ntp_event_gen(time_now_var, ntp_bytes_received, count_ntp_hosts, malicious_ntp)

    # DNS DDoS
    dns_db_query_result = ddos.dns_db_query(time_ago_var, time_now_var)
    malicious_dns = dns_db_query_result[0]
    dns_bytes_received = dns_db_query_result[1]
    count_dns_hosts = dns_db_query_result[2]
    ddos.dns_event_gen(time_now_var, dns_bytes_received, count_dns_hosts, malicious_dns)

    # Memcached DDoS
    memcached_db_query_result = ddos.memcached_db_query(time_ago_var, time_now_var)
    malicious_memcached = memcached_db_query_result[0]
    memcached_bytes_received = memcached_db_query_result[1]
    count_memcached_hosts = memcached_db_query_result[2]
    ddos.memcached_event_gen(time_now_var, memcached_bytes_received, count_memcached_hosts, malicious_memcached)


    print('End Event detector...')

def sched():
    #schedule.every(5).minutes.do(netflow_parser)
    #schedule.every(5).minutes.do(syslog_parser)
    while True:
        #schedule.run_pending()
        run_pending()
        time.sleep(20)

if __name__ == '__main__':
    process1 = multiprocessing.Process(target=netflow)
    process2 = multiprocessing.Process(target=syslog)
    process1.start()
    process2.start()
    sched()

    print('Close schedule..')
