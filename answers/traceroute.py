from socket import *
import os
import sys
import struct
import time
import select
import binascii

# author: Hendrik Werner s4549775

ICMP_ECHO_REQUEST = 8
ICMP_TTL_EXCEEDED = 11
ICMP_ECHO_REPLY = 0
TIMEOUT = 1.0


# computes the checksum
def checksum(str_):
    str_ = bytearray(str_)
    csum = 0
    countTo = (len(str_) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = str_[count + 1] * 256 + str_[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(str_):
        csum = csum + str_[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


# builds an echo request packet with correct checksum
def build_echo_request():
    ID = os.getpid() & 0xFFFF  # Return the current process i
    # Header is type (8), code (8), checksum (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack("bbHHh",
                         ICMP_ECHO_REQUEST,  # type (byte)
                         0,  # code (byte)
                         0,  # checksum (halfword, 2 bytes)
                         ID,  # ID (halfword)
                         1)  # sequence (halfword)
    data = struct.pack("d", time.time())
    # data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    return packet


# sends packet with a given ttl to a host
# returns (address, packet byte string)
def send_packet_with_ttl(hostname, pkt, ttl):
    destAddr = gethostbyname(hostname)
    # SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    # mySocket.settimeout(TIMEOUT)
    mySocket.bind(("", 0))
    # setsockopt method is used to set the time-to-live field.
    mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
    mySocket.settimeout(TIMEOUT)
    # send packet
    mySocket.sendto(pkt, (hostname, 0))
    # receive packet within timeout period
    try:
        recvPacket, addr = mySocket.recvfrom(1024)
    except timeout:
        recvPacket = None
    finally:
        return (addr, recvPacket)


# sends echo request ICMP packet with a given TTL to a host
# returns address (address, imcp_type, icmp_code)
def send_echo_request_with_ttl(hostname, ttl):
    pkt = build_echo_request()
    (addr, responsePacket) = send_packet_with_ttl(hostname, pkt, ttl)
    if responsePacket is not None:
        # Fetch the ICMP type and code from the received packet
        type, code = responsePacket[20:22]
        # print("Type: ", type, "Code: ", code)
        return (addr, type, code)
    return None


MAX_HOPS = 10
MAX_EXP = 3

# main method
if __name__ == "__main__":
    # you can try the routine out
    # rcv = send_echo_request_with_ttl("google.com", 1)
    # print (rcv)
    if len(sys.argv) != 2:
        print("USAGE: \npython traceroute.py hostname|ip_address")
        exit(0)
    hostname = sys.argv[1]
    for ttl in range(1, MAX_HOPS + 1):
        for i in range(MAX_EXP):
            start = time.time()
            # Write your code here
