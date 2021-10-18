from os import error
import dpkt
from socket import inet_ntoa

class Packet:
    def __init__(self, src, dst, sport, dport):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.syn_1 = False
        self.syn_ac_1 = False
        self.ac_1 = False

packets = []

def find(src, dst, sport, dport):
    loc = 0
    for p in packets:
        if (p.src == src and p.dst == dst and p.sport == sport and p.dport == dport) or (p.src == dst and p.dst == src and p.sport == dport and p.dport == sport):
            return (loc, True)
        loc += 1
    return False

# TODO: get the connection setup ->  For the first two transaction after the TCP connection is set up (from sender to receiver), the values of the Sequence number, Ack number, and Receive Window size -> Sender throughput
def parse_pcap(pcap_file_reader):
    for (timestamp, buffer) in pcap_file_reader:
        try:
            ethernet = dpkt.ethernet.Ethernet(buffer)
            ip = ethernet.data
            tcp = ip.data
            if (type(tcp) == dpkt.tcp.TCP):
                if (find(ip.src, ip.dst, tcp.sport, tcp.dport)):
                    # FLAGS: 0x002 -> SYN, 0x012 -> SYN/ACK, 0x010 -> ACK, 0x018 -> PSH/ACK, 0x011 -> FIN/ACK, 0x019 -> FIN/PSH/ACK
                    if tcp.flags == 0x002: # SYN
                        print(f"(SYN) Source: {inet_ntoa(ip.src)} on Port {tcp.sport}, Destination: {inet_ntoa(ip.dst)} on Port {tcp.dport}")
                    elif tcp.flags == 0x012: # SYN/ACK
                        print(f"(SYN/ACK) Source: {inet_ntoa(ip.src)} on Port {tcp.sport}, Destination: {inet_ntoa(ip.dst)} on Port {tcp.dport}")
                    elif tcp.flags == 0x010:
                        print(f"(ACK) Source: {inet_ntoa(ip.src)} on Port {tcp.sport}, Destination: {inet_ntoa(ip.dst)} on Port {tcp.dport}")
                else:
                    # Convert 32-bit IPV4 to standard dotted string decimal (127.0.0.1)
                    pack = Packet(ip.src, ip.dst, tcp.sport, tcp.dport)
                    packets.append(pack)
                    # print(f"Source: {inet_ntoa(ip.src)} on Port {tcp.sport}, Destination: {inet_ntoa(ip.dst)} on Port {tcp.dport}")
        except Exception as e:
            print("Error found!")
            exit(-1)


def run(pcap_file):
    try:
        f = open(pcap_file, 'rb')
        p = dpkt.pcap.Reader(f)
        parse_pcap(p)
        f.close()
    except FileNotFoundError as fe:
        print("\n" + pcap_file + " not found. Make sure your file exists, it's a .pcap file, and it's location is relative to this file.")

if __name__ == "__main__":
    # print("\nThe location of the .pcap file must be relative to the location of this (analysis_pcap_tcp.py) file. \nExample: If file.pcap file is in the same directory, then type file.pcap as the input below.\n")
    # file_loc = input("Enter The directory of the file: ")
    file_loc = "assignment2.pcap"
    run(pcap_file=file_loc)