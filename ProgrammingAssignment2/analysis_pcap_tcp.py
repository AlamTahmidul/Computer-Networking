from os import error
import dpkt
from socket import inet_ntoa

class Packet:
    def __init__(self, src=0, dst=0, sport=80, dport=80):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.syn_1 = False # First Connection (1 of 3)
        self.syn_ac_1 = False # First Connection ACK (2 of 3)
        self.ac_1 = False # Sending ACK back (3 of 3)
        self.fin_found = False # Checking if fin exists
        self.stor_data = [] # List of tuples from sender to receiver; (SEQ, ACK, WindowSize)
        self.rtos_data = [] # List of tuples from receiver to sender

    def check(self, src, dst, sport, dport):
        if self.src == src and self.dst == dst and self.sport == sport and self.dport == dport:
            return True
        return False


packets = []

def find(src, dst, sport, dport):
    loc = 0
    for p in packets:
        if (p.src == src and p.dst == dst and p.sport == sport and p.dport == dport): # Sender to Receiver
            return (loc, False)
        elif (p.src == dst and p.dst == src and p.sport == dport and p.dport == sport): # Receiver to Sender
            return (loc, True)
        loc += 1
    return (-1, False)

# TODO: get the connection setup ->  For the first two transaction after the TCP connection is set up (from sender to receiver), the values of the Sequence number, Ack number, and Receive Window size -> Sender throughput
def parse_pcap(pcap_file_reader):
    for (timestamp, buffer) in pcap_file_reader:
        try:
            ethernet = dpkt.ethernet.Ethernet(buffer)
            ip = ethernet.data
            tcp = ip.data
            if (type(tcp) == dpkt.tcp.TCP):
                loc_stor, stor = find(ip.src, ip.dst, tcp.sport, tcp.dport)
                loc_rtos, rtos = find(ip.dst, ip.src, tcp.dport, tcp.sport)
                if (stor and loc_stor >= 0):
                    # FLAGS: 0x002 -> SYN, 0x012 -> SYN/ACK, 0x010 -> ACK, 0x018 -> PSH/ACK, 0x011 -> FIN/ACK, 0x019 -> FIN/PSH/ACK
                    src_ip, src_port = (inet_ntoa(ip.src), tcp.sport)
                    dst_ip, dst_port = (inet_ntoa(ip.dst), tcp.dport)
                    pack: Packet = packets[stor]

                    if tcp.flags == 0x012: # SYN/ACK (2 of 3)
                        print(f"(SYN/ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port} and modified Packet var")
                        pack.syn_ac_1 = True
                    elif tcp.flags == 0x010: # ACK (3 of 3 /Or-> Sending Back/Receiving ACK)
                        # print(f"(ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                        if (not pack.ac_1):
                            pack.ac_1 = True
                        else:
                            # TODO: APPEND
                            # pack.stor_data.append()
                            pass
                    elif tcp.flags == 0x011:
                        print(f"(FIN/ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                    elif tcp.flags == 0x019:
                        print(f"(FIN/PSH/ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                elif (rtos):
                    src_ip, src_port = (inet_ntoa(ip.dst), tcp.dport)
                    dst_ip, dst_port = (inet_ntoa(ip.src), tcp.sport)
                    
                    if tcp.flags == 0x012: # SYN/ACK (2 of 3)
                        print(f"(SYN/ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                    elif tcp.flags == 0x010: # ACK (3 of 3 /Or-> Sending Back/Receiving ACK)
                        # print(f"(ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                        pass
                    elif tcp.flags == 0x011:
                        print(f"(FIN/ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                    elif tcp.flags == 0x019:
                        print(f"(FIN/PSH/ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                else:
                    # Convert 32-bit IPV4 to standard dotted string decimal (127.0.0.1)
                    pack = Packet(ip.src, ip.dst, tcp.sport, tcp.dport)
                    if tcp.flags == 0x002: # IF IT's A SYN -> 1 of 3 of 3-way handsake
                        pack.syn1 = True
                        print
                    packets.append(pack)
                    # print(f"Source: {inet_ntoa(ip.src)} on Port {tcp.sport}, Destination: {inet_ntoa(ip.dst)} on Port {tcp.dport}")
        except Exception as e:
            # print("Error found!")
            print(e)
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