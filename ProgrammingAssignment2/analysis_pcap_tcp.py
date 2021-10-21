from socket import inet_ntoa
import dpkt
from dpkt.tcp import TH_SYN, TH_ACK, TH_FIN

class Packet:
    tcp_flows = 0 # Counter for Complete TCP flows (SYN - FIN)
    def __init__(self, src=0, dst=0, sport=80, dport=80):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.st = 0 # TOTAL Sender Throughput
        self.syn = False # First Connection (1 of 3)
        self.syn_time = 0
        self.syn_ac_1 = False # First Connection ACK (2 of 3)
        self.ac_1 = False
        self.fin_found = False # Checking if fin exists
        self.retrans = [0, 0, 0] # [Trip-Dup, Timeout, Counter]
        self.win_scale = 1 # Get the win-scale
        self.stor_data = [] # List of tuples from sender to receiver; {"TIME", "SEQ", "ACK", "WINDOW_SIZE", "LENGTH", "TYPE"}
        self.rtos_data = [] # List of tuples from receiver to sender; {"TIME", "SEQ", "ACK", "WINDOW_SIZE", "LENGTH", "TYPE"}
        self.count = 0 # Debugging Purposes


packets = []

def find(src, dst, sport, dport):
    loc = 0
    for p in packets:
        if (p.src == src and p.dst == dst and p.sport == sport and p.dport == dport): # Sender to Receiver
            return (loc, True)
        elif (p.src == dst and p.dst == src and p.sport == dport and p.dport == sport): # Receiver to Sender
            return (loc, False)
        loc += 1
    return (-1, False)

def parse_pcap(pcap_file_reader):
    for (timestamp, buffer) in pcap_file_reader:
        try:
            ethernet = dpkt.ethernet.Ethernet(buffer)
            ip: dpkt.ip.IP = ethernet.data
            tcp: dpkt.tcp.TCP = ip.data
            if (type(tcp) == dpkt.tcp.TCP):
                loc_stor, stor = find(ip.src, ip.dst, tcp.sport, tcp.dport) # Sender to receiver -> Negate stor to get Receiver to Sender

                if (stor and loc_stor >= 0): # Sender to receiver (stor)
                    pack: Packet = packets[loc_stor] # Get the object for sender-receiver pair
                    
                    src_ip, src_port = (inet_ntoa(pack.src), pack.sport)
                    dst_ip, dst_port = (inet_ntoa(pack.dst), pack.dport)

                    if ((tcp.flags & TH_ACK) and not (tcp.flags & TH_SYN) and not pack.fin_found): # ACK
                        pack.stor_data.append( {"TIME": timestamp, "SEQ": tcp.seq, "ACK": tcp.ack, "WINDOW_SIZE": tcp.win, "LENGTH": len(tcp), "TYPE": "ACK"} )
                        if not pack.ac_1 and len(tcp.data) == 0: # Did not receive acknowledgement yet for 3-way handshake
                            pack.ac_1 = True
                        else:
                            pack.st += len(tcp)
                        # print(f"(ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                elif ((not stor) and loc_stor >= 0): # Receiver to sender (rtos)
                    pack: Packet = packets[loc_stor] # Get the object for sender-receiver pair
                    
                    src_ip, src_port = (inet_ntoa(pack.dst), pack.dport)
                    dst_ip, dst_port = (inet_ntoa(pack.src), pack.sport)
                    
                    if ((tcp.flags & TH_SYN) and (tcp.flags & TH_ACK) and not (tcp.flags & TH_FIN)): # SYN/ACK (2 of 3)
                        pack.syn_ac_1 = True
                        # print(f"(SYN/ACK) Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}")
                    elif ((tcp.flags & TH_ACK) and not (tcp.flags & TH_FIN) and not (tcp.flags & TH_SYN)): # ACK
                        pack.rtos_data.append({"TIME": timestamp, "SEQ": tcp.seq, "ACK": tcp.ack, "WINDOW_SIZE": tcp.win, "LENGTH": len(tcp), "TYPE": "ACK"})
                        # print(f"(ACK) Source: {src_ip} on Port {src_port}, Destination: {dst_ip} on Port {dst_port}")
                    elif ( tcp.flags & TH_FIN ): # FIN/ACK
                        pack.fin_found = True
                        pack.rtos_data.append( {"TIME": timestamp, "SEQ": tcp.seq, "ACK": tcp.ack, "WINDOW_SIZE": tcp.win, "LENGTH": len(tcp), "TYPE": "FIN/ACK"} )
                        if (pack.syn):
                            Packet.tcp_flows += 1
                        print(f"(FIN/ACK) Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}")
                else: # COULD BE A SYN (i.e. START OF A NEW TCP FLOW)
                    if ( (tcp.flags & TH_SYN) and not (tcp.flags & TH_ACK) and not (tcp.flags & TH_FIN)): # IF IT's A SYN -> 1 of 3 of 3-way handsake
                        # Convert 32-bit IPV4 to standard dotted string decimal (127.0.0.1)
                        pack = Packet(src=ip.src, dst=ip.dst, sport=tcp.sport, dport=tcp.dport)
                        pack.syn = True
                        pack.syn_time = timestamp
                        pack.win_scale = int.from_bytes(tcp.opts.strip()[-1:], "big") # LAST BYTE HAS WINDOW SCALE
                        packets.append(pack)
                        print(f"(SYN) Source: {inet_ntoa(ip.src)}:{tcp.sport}, Destination: {inet_ntoa(ip.dst)}:{tcp.dport}")
        except Exception as e:
            print("Error found! Exiting...")
            # print(e)
            exit(-1)

# Write to File the Analysis
def analyze():
    with open("analysis.txt", "w") as f:
        f.write("Number of complete TCP Flows (SYN with FIN): " + str(Packet.tcp_flows) + "\n")
        f.write("\nTEMPLATE: SENDER(IP:PORT) or RECEIVER(IP:PORT)\n\n")
        flow_num = 1
        for p in packets:
            pack: Packet = p
            if pack.syn and pack.fin_found: # VALID FLOW
                f.write(f"TCP FLOW #{str(flow_num)}:\n")
                i_offset = 0
                if pack.ac_1:
                    i_offset = 1
                
                time = pack.rtos_data[-1]["TIME"] - pack.stor_data[0 + i_offset]["TIME"]
                for i in range(2): # PRINT THE FIRST 2 TRANSACTIONS
                    f.write(f"""TRANSACTION {i + 1}\n
    SENDER({str(inet_ntoa(pack.src))}:{str(pack.sport)})\n
        SEQ: {str(pack.stor_data[i + i_offset]["SEQ"])}, ACK: {str(pack.stor_data[i + i_offset]["ACK"])}, Window: {str(pack.stor_data[i + i_offset]["WINDOW_SIZE"] << pack.win_scale)}\n
    RECEIVER({str(inet_ntoa(pack.dst))}:{str(pack.dport)})\n
        SEQ: {str(pack.rtos_data[i]["SEQ"])}, ACK: {str(pack.rtos_data[i]["ACK"])}, Window: {str(pack.rtos_data[i]["WINDOW_SIZE"] << pack.win_scale)}\n\n""")
                f.write(f"""
    {pack.st} bytes sent in {str(round(pack.rtos_data[-1]["TIME"] - pack.stor_data[0 + i_offset]["TIME"], 4))} seconds\n
    Total Througput: {str(round(pack.st / time, 4))} bytes/second -> {str(round(pack.st / time / 1000000, 4))} Mbps\n
-------------------------------------------------------------\n""")
                flow_num += 1
    
def run(pcap_file):
    try:
        f = open(pcap_file, 'rb')
        p = dpkt.pcap.Reader(f)
        parse_pcap(p)
        f.close()
    except FileNotFoundError as fe:
        print("\n" + pcap_file + " not found. Make sure your file exists, it's a .pcap file, and it's location is relative to this file.")

def debug():
    for p in packets:
        # manual_sum = p.stor_data[-1]["SEQ"] - p.stor_data[0]["SEQ"]
        time = p.rtos_data[-1]["TIME"] - p.stor_data[1]["TIME"]
        time1 = p.stor_data[1]["TIME"] - p.syn_time
        time2 = p.rtos_data[-1]["TIME"] - p.syn_time
        print(f"Sum: {p.st},  Number of Sender Flows: {len(p.stor_data)}, Time: {time}, First Time: {time1}, Second Time: {time2}, Count: {p.count}")

if __name__ == "__main__":
    file_loc = "assignment2.pcap"
    run(pcap_file=file_loc)
    debug()
    analyze()
