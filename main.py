import scapy.all as scapy
from datetime import datetime
import logging
import time

# Devices which are known to be constantly probing
IGNORE_LIST = set(['00:00:00:00:00:00', '01:01:01:01:01:01'])
SEEN_DEVICES = set()  # Devices which have had their probes recieved
d = {'A4:C3:F0:5B:33:17': 'Example MAC Address'}  # Dictionary of all named devices


# This is a sample Python script.

def detect_bluetooth():
    """
    Performs a simple device inquiry followed by a remote name request of each
    discovered device
    """

    import bluetooth

    print("Performing inquiry...")

    nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True,
                                                flush_cache=True, lookup_class=False)

    print("Found {} devices".format(len(nearby_devices)))

    for addr, name in nearby_devices:
        try:
            print("   {} - {}".format(addr, name))
        except UnicodeEncodeError:
            print("   {} - {}".format(addr, name.encode("utf-8", "replace")))


class scan:
    def Arp(self, ip):
        self.ip = ip
        print(ip)
        arp_r = scapy.ARP(pdst=ip)
        br = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        request = br / arp_r
        answered, unanswered = scapy.srp(request, timeout=1)
        print('\tIP\t\t\t\t\tMAC')
        print('_' * 37)
        for i in answered:
            ip, mac = i[1].psrc, i[1].hwsrc
            print(ip, '\t\t' + mac)
            print('-' * 37)


def handle_packet(pkt):
    if not pkt.haslayer(scapy.Dot11ProbeReq):
        return
    if pkt.type == 0 and pkt.subtype == 4:  # subtype used to be 8 (APs) but is now 4 (Probe Requests)
        # logging.debug('Probe Recorded with MAC ' + curmac)
        curmac = pkt.addr2
        curmac = curmac.upper()  # Assign variable to packet mac and make it uppercase
        SEEN_DEVICES.add(curmac)  # Add to set of known devices (sets ignore duplicates so it is not a problem)
        if curmac not in IGNORE_LIST:  # If not registered as ignored
            if curmac in d:
                logging.info('\033[95m' + 'Probe Recorded from ' + '\033[93m' + d[
                    curmac] + '\033[95m' + ' with MAC ' + curmac + '\033[0m')  # Log to file wifiscanner.log with purple color
                print('\033[95m' + 'Probe MAC Address: ' + pkt.addr2 + ' from device ' + '\033[93m' + d[
                    curmac] + '\033[0m')
                # 'with SSID: {pkt.info}'.format(pkt=pkt)) #Print to command line with purple color
            else:
                logging.info(
                    '\033[92m' + 'Probe Recorded from MAC ' + pkt.addr2 + '\033[0m')  # Log to file wifiscanner.log with green color
                print('\033[95m' + 'Device MAC: {pkt.addr2} '
                                   'with SSID: {pkt.info}'.format(
                    pkt=pkt) + '\033[0m')  # Print to command line with green color
        # print SEEN_DEVICES #Just for debug, prints all known devices
        # dump()


def detect_wifi():
    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='wifiscanner.log',
                        level=logging.DEBUG)  # setup logging to file
    logging.info(
        '\n' + '\033[93m' + 'Wifi Scanner Initialized' + '\033[0m' + '\n')  # announce that it has started to log file with yellow color
    print(
        '\n' + '\033[93m' + 'Wifi Scanner Initialized' + '\033[0m' + '\n')  # announce that it has started to command line with yellow color		(/n is newline)

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default='mon0',  # Change mon0 to your monitor-mode enabled wifi interface
                        help='monitor mode enabled interface')
    args = parser.parse_args()
    scapy.sniff(iface="wlo1", prn=handle_packet)  # start sniffin
    while 1:
        time.sleep(1)  # Supposed to make an infinite loop, but for some reason it stops after a while


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # detect_bluetooth()
    while 1:
        arp = scan()  # create an instance of the class
        arp.Arp('192.168.0.1/254')  # call the method
        time.sleep(5)  # Supposed to make an infinite loop, but for some reason it stops after a while
    # detect_wifi()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
