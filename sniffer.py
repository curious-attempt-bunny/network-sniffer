import datetime
import json
import netaddr
import re
import subprocess
import signal

cmd = ['sudo', '-n', 'tcpdump', '-e', '-n', '--immediate-mode', '-l']
# cmd = ['/bin/sh', '-c', 'cat sniff2.log']

print(f'Running: {cmd}')

def render_timestamp(time):
    return {
        'timestamp_epoch': time.timestamp(),
        'timestamp_human': str(time),
    }

def write_log(mac_to_info, time):
    with open('sniffed.json', 'w') as f:
        data = {
            'mac_addresses' : mac_to_info
        }
        data.update(render_timestamp(time))
        print(f'{data["timestamp_human"]}: Writing log with {len(mac_to_info)} mac address entries.')
        json.dump(data, f, indent=2)

HEX_DIGIT_PAIR=r'[0-9a-f]{2}'
MAC_ADDRESS_REGEX = r':'.join([r'[0-9a-f]{2}']*6)
IP_ADDRESS_REGEX = r'\.'.join([r'[0-9]{1,3}']*4)
PORT_OPTIONAL_REGEX = r'(?:\.[0-9]{1,5})?'
TIMESTAMP_REGEX = r'[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}'
LINE_REGEX=r'^'+TIMESTAMP_REGEX+r' (?P<mac_from>'+MAC_ADDRESS_REGEX+r') > (?P<mac_to>'+MAC_ADDRESS_REGEX+r'), (?:ethertype (?P<protocol>[A-Za-z0-9]{2,6}))?.*?, length [0-9]{1,}: .*?(?P<ip_from>'+IP_ADDRESS_REGEX+r')'+PORT_OPTIONAL_REGEX+r' (?P<operator>[^ ]+) (?P<ip_to>'+IP_ADDRESS_REGEX+r')'+PORT_OPTIONAL_REGEX

output_received = False
mac_to_info = {}

last_log_write = datetime.datetime.now()
write_log(mac_to_info, last_log_write)

with subprocess.Popen(
        cmd,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE
    ) as proc:

    while True:
        line = proc.stdout.readline()
        if not line:
            print('Polling to see if complete?')
                
            if proc.poll() == None:
                continue
            else:
                break

        if not output_received:
            output_received = True
            print(f'First output received from {cmd}')

        time_now = datetime.datetime.now()

        line = line.decode('utf-8')
        # print(line)
        match = re.match(LINE_REGEX, line)
        if match:
            params = match.groupdict()
            # print(params)
            for mac, ip in [
                    (params['mac_from'], params['ip_to'] if params['operator'] == 'tell' else params['ip_from']),
                    (params['mac_to'], params['ip_from'] if params['operator'] == 'tell' else params['ip_to'])
                ]:
                if ip.startswith('192.168.0.') and mac != 'ff:ff:ff:ff:ff:ff':
                    if mac not in mac_to_info:
                        try:
                            organization = netaddr.EUI(mac).oui.registration().org
                        except:
                            organization = 'Unknown'
                            
                        mac_to_info[mac] = {
                            'ip_address': ip,
                            'mac_address': mac,
                            'organization': organization
                        }
                        mac_to_info[mac].update(render_timestamp(time_now))
                        # print(line)
                        # print(params)
                        print(f'Sniffed {mac_to_info[mac]}')
                        last_log_write = time_now
                        write_log(mac_to_info, last_log_write)
                    else:
                        mac_to_info[mac].update(render_timestamp(time_now))
        else:
            if ' IPv6 ' not in line and line != '' and ' is-at ' not in line:
                # print(f'No match for: {line}')
                pass

        if time_now.timestamp() - last_log_write.timestamp() > 30:
            last_log_write = time_now
            write_log(mac_to_info, last_log_write)

    # NOTE: requires entry in /etc/sudoers:
    # <user> <host> = (root) NOPASSWD: /usr/sbin/tcpdump

    print(f'Complete: {cmd} with status code {proc.returncode}')                

    # TODO: What's the returncode when it sudoers is not setup to allow it?



            
    
