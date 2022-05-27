import dpkt


class Flow:
    def __init__(self, source_port, dest_port):
        self.source_port = source_port
        self.dest_port = dest_port
        self.start_time = 0
        self.end_time = 0
        self.total_data = 0
        self.source_ip = ""
        self.dest_ip = ""
        self.connection_setup = False
        self.throughput = 0
        self.window_scale_factor = 0
        self.transaction_list = []
        self.rec_transactions = []
        self.rtt = 0
        self.next_rtt = 0
        self.cwnd_list = []
        self.packets_per_rtt = 0
        self.triple_retransmissions = 0
        self.timeout_retransmissions = 0


def analyze_pcap(filename):
    # Opening file
    try:
        file = open(filename, "rb")
        pcap = dpkt.pcap.Reader(file)
    # If no file found, print an error
    except FileNotFoundError:
        print("Error: File not found")
        return
    # Flow list in the .pcap file
    flows = []
    ack_check = 0
    dict = {}
    # Loop through each packet of the .pcap file
    for ts, buf in pcap:
        # Create ethernet object to extract data from
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        flags = tcp.flags
        # Obtain source/destination ports
        source_port = tcp.sport
        dest_port = tcp.dport
        # Obtain source/destination IPs
        source_ip = str(ip.src[0]) + "." + str(ip.src[1]) + "." + str(ip.src[2]) + "." + str(ip.src[3])
        dest_ip = str(ip.dst[0]) + "." + str(ip.dst[1]) + "." + str(ip.dst[2]) + "." + str(ip.dst[3])
        # Create flags list to determine what flag is currently displayed
        flags = list(bin(flags)[2:])
        # Flags:
        # [-1] == FIN
        # [-2] == SYN
        # [-3] == RST
        # [-4] == PSH
        # [-5] == ACK
        # [-6] == URG
        # If there is SYN and no ACK, create a new flow and append it to the flow list
        if flags[-2] == "1" and len(flags) <= 2:
            new_flow = Flow(source_port, dest_port)
            # Set source and destination IPs to flow
            new_flow.source_ip = source_ip
            new_flow.dest_ip = dest_ip
            # Increase total data of flow
            new_flow.total_data += len(ip.data)
            new_flow.start_time = ts
            flows.append(new_flow)
            new_flow.window_scale_factor = buf[73]
            continue
        # Obtain the current flow
        current_flow = None
        for flow in flows:
            if (source_port == flow.source_port and dest_port == flow.dest_port) or \
                    (source_port == flow.dest_port and dest_port == flow.source_port):
                current_flow = flow
        # If there is no current flow, skip the packet
        if current_flow is None:
            continue
        # If there is SYN and ACK, continue the handshake
        if flags[-2] == "1" and len(flags) >= 5 and flags[-5] == "1":
            current_flow.rtt = ts - current_flow.start_time
            current_flow.next_rtt = ts + current_flow.rtt
            continue
        # If there is ACK in handshake, end the handshake and skip the packet
        elif flags[-5] == "1" and not current_flow.connection_setup and source_port == current_flow.source_port:
            # Increase total data of flow
            current_flow.total_data += len(ip.data)
            current_flow.connection_setup = True
            continue
        # If there is FIN, calculate throughput
        elif flags[-1] == "1" and source_port == current_flow.source_port:
            # Increase total data of flow
            current_flow.total_data += len(ip.data)
            current_flow.end_time = ts
            current_total_time = current_flow.end_time - current_flow.start_time
            current_flow.throughput = current_flow.total_data / current_total_time
        # Obtain the packet Sequence number, Ack number, Receive Window size
        sequence_number = tcp.seq
        ack_number = tcp.ack
        receive_window_size = tcp.win * (2 ** current_flow.window_scale_factor)
        # If packet is a sender packet, increase total data of current flow and add transaction to
        # transaction list
        if source_port == current_flow.source_port:
            current_flow.total_data += len(ip.data)
            transaction = (sequence_number, ack_number, receive_window_size, current_flow.rtt, ts)
            current_flow.transaction_list.append(transaction)
            payload = len(buf[66:])
            dict[sequence_number + payload] = transaction
            # Calculate cwnd
            if ts > current_flow.next_rtt:
                current_flow.cwnd_list.append(current_flow.packets_per_rtt)
                current_flow.packets_per_rtt = 1
                current_flow.next_rtt += current_flow.rtt
            else:
                current_flow.packets_per_rtt += 1
        # If packet is a receiver packet, add transaction to receiver transactions list
        elif source_port == current_flow.dest_port:
            transaction = (sequence_number, ack_number, receive_window_size, current_flow.rtt, ts)
            current_flow.rec_transactions.append(transaction)
            transaction = dict.get(ack_number)
            if transaction is None:
                continue
            ack_check += 1
            # If it has 3 duplicate ACK, increment triple duplicate ack caused retransmission
            if ack_check > 3:
                current_flow.triple_retransmissions += 1
                ack_check = 0
                continue
            elif ts > (2 * transaction[3] + transaction[4]):
                current_flow.timeout_retransmissions += 1

    print("The total number TCP flows is:", len(flows))
    print()
    for flow in flows:
        print("Flow", flows.index(flow)+1)
        print("Source Port:", flow.source_port)
        print("Source IP:", flow.source_ip)
        print("Destination Port:", flow.dest_port)
        print("Destination IP:", flow.dest_ip)
        print("Transaction 1:")
        print("Sender: Seq =", flow.transaction_list[0][0], "ACK =", flow.transaction_list[0][1], "Win Size:",
              flow.transaction_list[0][2])
        print("Receiver: Seq =", flow.rec_transactions[0][0], "ACK =", flow.rec_transactions[0][1], "Win Size:",
              flow.rec_transactions[0][2])
        print("Transaction 2:")
        print("Sender: Seq =", flow.transaction_list[1][0], "ACK =", flow.transaction_list[1][1], "Win Size:",
              flow.transaction_list[1][2])
        print("Receiver: Seq =", flow.rec_transactions[1][0], "ACK =", flow.rec_transactions[1][1], "Win Size:",
              flow.rec_transactions[1][2])
        print("Throughput:", flow.throughput)
        print()

    for flow in flows:
        print("Flow", flows.index(flow)+1)
        cwnd_counter = 0
        for cwnd in flow.cwnd_list:
            print("CWND " + str(flow.cwnd_list.index(cwnd)+1) + ": " + str(cwnd))
            cwnd_counter += 1
            if cwnd_counter > 2:
                break
        print("Retransmissions due to triple duplicate ACK: " + str(flow.triple_retransmissions))
        print("Retransmissions due to timeout: " + str(flow.timeout_retransmissions))
        print()


if __name__ == "__main__":
    pcap_filename = input("Enter a .pcap file: ")
    analyze_pcap(pcap_filename)