"""
nmap 192.168.0.0/24 --exclude 192.168.0.101 -Pn -A -T4 -sS -sV -vv -n -O -oX > scan_result.xml
"""

import xml.etree.ElementTree as ET

def nmap_parser():
    tree = ET.parse('scan_result.xml')
    root = tree.getroot()
    (ET.tostring(root, encoding='utf8').decode('utf8'))
    for host in root.iter('host'):
        for status in host.iter('status'):
            for address in host.iter('address'):
                #print(status.attrib, address.attrib)
                state = status.attrib['state']
                #print(f'Host state: {state}')
                if address.attrib['addrtype'] == 'ipv4':
                    ip_addr = address.attrib['addr']
                    print(f'IP:{ip_addr} Host state:{state}')
                if address.attrib['addrtype'] == 'mac':
                    mac_addr = address.attrib['addr']
                    # Check whether vendor key return string
                    try:
                        address.attrib['vendor']
                    except KeyError:
                        print(f'MAC Address: {mac_addr}')
                    else:
                        mac_vendor = address.attrib['vendor']
                        print(f'MAC Address: {mac_addr} {mac_vendor}')
        for ports in host.iter('ports'):
            for port in host.iter('port'):
                #print(port.attrib)
                protocol = port.attrib['protocol']
                portid = port.attrib['portid']
                for state in port.iter('state'):
                    #print(state.attrib)
                    port_state = state.attrib['state']
                print(f'Port:{portid} protocol:{protocol} state:{port_state}')
            for elem in port.iter('elem'):
                print(elem.attrib, elem.text)
                    #for fingerprint in elem.iter('fingerprint'):
                    #    print(fingerprint)
        for os in host.iter('os'):
            print('OS scan details:')
            for osmatch in os.iter('osmatch'):
                #print(osmatch.attrib)
                os_name = osmatch.attrib['name']
                os_accuracy = osmatch.attrib['accuracy']
                os_accuracy = int(os_accuracy)
                if os_accuracy > 95:
                    print(f'OS name:{os_name} accuracy:{os_accuracy}')
                else:
                    pass
            for osclass in os.iter('osclass'):
                print(osclass.attrib)
            for cpe in os.iter('cpe'):
                print(cpe.attrib, cpe.text)
        for osfingerprint in host.iter('fingerprint'):
            os_fingerprint = osfingerprint.attrib['fingerprint']
            print(f'OS Fingerprint: {os_fingerprint}')

        print('================================================================')

nmap_parser()

