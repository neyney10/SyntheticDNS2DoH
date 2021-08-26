from scapy.all import *
import random
'''
This class represents a DoH client and holds a list of all the relevant DoH queries.

@output_packets_of function which is activate by DoHSession is returning randomized DoH query in case of
synthetic mode or the relative DoH query in case of original mode.
'''
class DoHClient:
    def __init__(self, doh_queries) -> None:
        self.doh_queries = doh_queries
        self.seq          = 0
        self.ack          = 0
        self.output_packets_buffer = []
        
    def output_packets_of(self, packets: list, is_termination=False, mode=''):
        packet = packets[-1]
        time = packet.time
        if is_termination == True:
            return list(map(lambda p: self._update_seq_ack(p), packets))
        if DNS in packet and packet[DNS].qr == 0: # if its a DNS query
            doh_query=list()
            if mode =='s':
                doh_query=random.choice(self.doh_queries)  # NEED TO CHANGE
            else:
                doh_query=self.doh_queries[0]
                if (len(self.doh_queries) != 1):
                    self.doh_queries=self.doh_queries[1:]
                #doh_query=self.doh_queries[:2]  # taking query and ack packets 
                #self.doh_queries=self.doh_queries[2:]   #  remove it from list
            updated_req = list(map(lambda p: self._update_seq_ack(p),
                                   doh_query))
            for updated_pkt in updated_req:
                updated_pkt.time = time + (updated_pkt.time - doh_query[0].time)
            self.output_packets_buffer.extend(updated_req)
        elif TCP in packet:
            self.ack = packet[TCP].seq
            if mode == 's':
                self.output_packets_buffer.append(
                    self._update_seq_ack(
                        self._create_tcp_ack_packet(time)))

        output_packets = self.output_packets_buffer.copy()
        self.output_packets_buffer.clear()
        return output_packets
            
    def set_seq(self, seq):
        self.seq = seq
        
    def set_ack(self, ack):
        self.ack = ack
        
    def _create_tcp_ack_packet(self, time):
        ack = Ether() / IP() / TCP(flags='A' , window = 6000)
        ack.time = time
        return ack
    
    def _update_seq_ack(self, packet):
        cloned_packet = packet.copy()
        cloned_packet[TCP].seq = self.seq
        cloned_packet[TCP].ack = self.ack
        self.seq += len(cloned_packet[TCP].payload)
        return cloned_packet