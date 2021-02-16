import socket
import struct
import time
import threading
from datetime import datetime
from collections import defaultdict
import statistics
from statistics import mode


class Ether(object):
    """
    Unpacks the Ethernet 2 packet and extracts the destination MAC address, Source
    MAC address and Protocol.
    """
    def __new__(cls, raw):
        return object.__new__(cls)

    def __init__(self, raw):
        self.dst_mac, self.src_mac, self.protocol = struct.unpack('!6s6sH', raw)
        #print('Source MAC address: ', mac_format(self.src_mac))
        #print('Destination MAC address: ', mac_format(self.dst_mac))
        #print('Protocol: ', socket.htons(self.protocol))


class IpLayer(object):
    """
    Unpacks the IP Layer. Extracting the IP protocol, Source IP, and Destination IP.
    """
    def __new__(cls, ip_data):
        return object.__new__(cls)

    def __init__(self, ip_data):
        self.protocol, self.source_ip, self.target_ip = struct.unpack('!9xB2x4s4s', ip_data[:20])
        #print('IP Protocol: ', self.protocol)
        print('Source IP: ', ipv4_format(self.source_ip))
        print('Destination IP: ', ipv4_format(self.target_ip))


class TcpDissect(object):
    """
    Unpacks TCP. Extracting the Source Port and Destination Port
    """
    def __new__(cls, transport_data):
        return object.__new__(cls)

    def __init__(self, transport_data):
        # Source and Destination ports are both 2 bytes each
        self.src_port, self.dst_port = struct.unpack('!HH', transport_data[:4])
        print('Source Port: ', self.src_port)
        print('Destination Port: ', self.dst_port)


class UdpDissect(object):
    """
    Unpacks UDP. Extracting the Source Port and Destination Port
    """
    def __new__(cls, transport_data):
        return object.__new__(cls)

    def __init__(self, transport_data):
        # Source and Destination ports are both 2 bytes each
        self.src_port, self.dst_port = struct.unpack('!HH', transport_data[:4])
        print('udpSource Port: ', self.src_port)
        print('udpDestination Port: ', self.dst_port)


class IcmpDissect(object):
    """
    Unpacks ICMP. Extracting the ICMP Type and Code
    """
    def __new__(cls, transport_data):
        return object.__new__(cls)

    def __init__(self, transport_data):
        # Type and Code are both 1 byte each
        self.type, self.code = struct.unpack('!BB', transport_data[:2])
        print('ICMP Type: ', self.type)
        print('ICMP Code: ', self.code)


def mac_format(mac):
    """
    Convert the mac address to standard form using map and join to format
    :param mac: String object
    :return: mac address(E.g. 00:00:00:00:00:00)
    """
    mac = map('{:02X}'.format, mac)
    return ':'.join(mac)


def ipv4_format(address):
    """
    Convert the ip address to standard form using map and join
    :param address: String object
    :return: ip address(E.g. 192.168.10.0)
    """
    return '.'.join(map(str, address))


def main():
    # Start a packets socket object to begin listening for incoming packets at Layer 2 of the OSI
    packets = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    #store target ip, target port, source ip, timestamp.
    # Tried to used srcIp as key but dictionary does not allow duplicate keys. Timestamp may work for keys but too long
    targetIP = []
    targetPort = []
    srcIP = []
    timeStamp = []
    start = time.perf_counter()
    tEnd = time.time() + 60 * 5  # run for 5 min
    while time.time() < tEnd:
        # Receive data from the packets buffer.
        ethernet_data = packets.recvfrom(65536)
        # Using the Ether class extract the source MAC, destination MAC, and Protocol from the first 14 Bytes
        # of the buffer data
        ether_header = Ether(ethernet_data[0][:14])
        # If the protocol is 8
        if socket.htons(ether_header.protocol) == 8:
            # Extract the IP protocol, Source IP, and Destination IP
            ip_header = IpLayer(ethernet_data[0][14:])
            sIP = ipv4_format(ip_header.source_ip)
            tIP = ipv4_format(ip_header.target_ip)
            srcIP.append(sIP)
            targetIP.append(tIP)
            # If protocol is TCP
            if ip_header.protocol == 6:
                # Extract the source port and destination port
                # 34: comes from 14 bytes for Ethernet header + 20 bytes from IP header so 34-> will contain
                # the header of TCP
                tcp_header = TcpDissect(ethernet_data[0][34:])
                targetPort.append(tcp_header.dst_port)
                dateTimeObj = datetime.now()
                timeStamp.append(dateTimeObj)

            # If protocol is UDP
            # if ip_header.protocol == 17:
            # Extract the source port and destination port
            # udp_header = UdpDissect(ethernet_data[0][34:])
            # If protocol is ICMP
            # elif ip_header.protocol == 1:
            # Extract the Type and Code
            # icmp_header = IcmpDissect(ethernet_data[0][34:])
            else:
                pass
    finish = time.perf_counter()
    timeElapse = finish - start
    numConnections = len(srcIP)
    fanSec = numConnections/timeElapse
    fanMin = (numConnections/timeElapse) * 60
    fanFiveMin = numConnections
    #print("number of connections is ", numConnections, " and time elapse is ", timeElapse, " seconds")
    print("port scanner detected on source ip ", srcIP[1])
    print("avg. fan out per sec: ", fanSec)
    print("avg. fan out per min: ", fanMin)
    print("avg. fan out per 5min: ", numConnections)
    print("reason: fan out per sec: ", fanSec)





if __name__ == '__main__':
    main()
