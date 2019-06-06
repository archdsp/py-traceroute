from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii
from functools import reduce
import argparse

ICMP_ECHO_REQUEST = 8
TIMEOUT = 1.0
TRIES = 3
PACKET_PROTOCOL = socket.IPPROTO_RAW
MY_PACKET_ID = 12345

def make_checksum(header):
    size = len(header)
    if (size % 2) == 1:
        header += b'\x00'
        size +=1
        
    size = size //2
    header = struct.unpack('!' + str(size) + 'H', header)
    chksum = reduce(lambda x, y: x+y, header)
    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum += chksum>>16
    chksum = (chksum ^ 0xffff)
    
    return chksum

def icmp():
    myChecksum = 0
    myID = 11

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())

    myChecksum = make_checksum(header + data)    
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet

def ip_header(src_ip_addr, dst_ip_addr, ttl, payload):
    ip_ver = 4
    ip_hl = 5
    ip_tol = 20 + len(payload)
    ip_tos = 0
    ip_idf = 0 
    ip_rsv = 0
    ip_dtf = 0
    ip_mrf = 0
    ip_offset = 0
    ip_ttl = ttl
    ip_proto = socket.IPPROTO_ICMP
    ip_checksum = 0
    ip_src = socket.inet_aton(src_ip_addr)
    ip_dst = socket.inet_aton(dst_ip_addr)
    ip_VHL = (ip_ver << 4 ) + ip_hl
    ip_Flag = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + ip_offset

    header = struct.pack('!BBHHHBBH4s4s', ip_VHL, ip_tos, ip_tol, ip_idf, ip_Flag, ip_ttl, ip_proto, ip_checksum, ip_src, ip_dst)
    ip_checksum = make_checksum(header + payload)
    header = struct.pack('!BBHHHBBH4s4s', ip_VHL, ip_tos, ip_tol, ip_idf, ip_Flag, ip_ttl, ip_proto, ip_checksum, ip_src, ip_dst)
    return header + payload

def traceroute(hostname, protocol, MAX_HOPS=30):
    dst_ip_addr = socket.gethostbyname(hostname)
    src_ip_addr = socket.gethostbyname(socket.gethostname())
    src_ip_addr = '59.8.172.254'
    result = ''

    print('traceroute to google.com (%s), %d hops max' % (dst_ip_addr, MAX_HOPS))
    for ttl in range(1, MAX_HOPS + 1):
        print(ttl, end='\t')
        packet = icmp()
        #print(packet)
        for tries in range(TRIES):
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            if protocol == socket.IPPROTO_RAW:
                mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                packet = ip_header(src_ip_addr, dst_ip_addr, ttl, packet)
            
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            recv_socket.settimeout(TIMEOUT)
            
            #print(packet)
            try:
                mySocket.sendto(packet, (dst_ip_addr, 0))
                
                t = time.time()

                if protocol == socket.IPPROTO_RAW:
                    recvPacket, addr = recv_socket.recvfrom(1024)
                else:
                    recvPacket, addr = mySocket.recvfrom(1024)

                timeReceived = time.time()

                icmpHeader = recvPacket[20:28]
                icmpData = recvPacket[28:]
                request_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                
                bytes = struct.calcsize("d")
                timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                takeTime = (timeReceived - t)*1000
                result = addr[0]

                if request_type == 11:
                    if tries == 0:
                        print("%.0fms\t%.0fms\t%.0fms" % (takeTime, takeTime, takeTime), end ='\t')
                        break
                    else:
                        print("%.0fms" % (takeTime), end='\t')

                elif request_type == 3:
                    result = "Destination unreachable"

                elif request_type == 0:
                    if code == 0:
                        print('[%s, %s]' % (src_ip_addr, addr[0]))
                        return 

                else:
                    print("other request " + str(request_type))
                    break

            except socket.timeout:
                print('*', end='\t')
                continue
            
            finally:
                mySocket.close()
                recv_socket.close()
                
        print(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'traceroute')
    parser.add_argument('destination', type = str, metavar = 'dst_ip or domain_name', help = 'dst_ip or domain_name')
    #parser.add_argument('packet_size', type = str, metavar = 'packet_size', help = 'packet size')
    parser.add_argument('-t', type = float, required = False, metavar = 'RECV_TIMEOUT', help = 'recieve timeout')
    parser.add_argument('-c', type = int, required = False, metavar = 'MAX_HOPS', help = 'maximal hops')
    parser.add_argument('-I', action='store_true', required = False, help = 'packet type ICMP')
    parser.add_argument('-p', type = int, required = False, metavar = 'UDP', help = 'packet type UDP')
    parser.add_argument('-U', action='store_true', required = False, help = 'UDP Port number. default is 53')
    
    args = parser.parse_args()
    
    protocol = socket.IPPROTO_RAW
    if args.t is True:
        TIMEOUT = args.t
        
    if args.c is True:
        MAX_HOPS = args.c
    
    if args.I is True:
        protocol = socket.IPPROTO_ICMP
        
    if args.U is True:
        protocol = socket.IPPROTO_UDP
    
    dst_hostname = args.destination
    print(dst_hostname)
    traceroute(dst_hostname, protocol)
