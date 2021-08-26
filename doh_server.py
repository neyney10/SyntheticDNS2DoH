
from scapy.all import *
from doh_proxy import DoHProxy
'''
This class represents a DoH server and holds a list of all the relevant DoH responses.

@output_packets_of function which is activate by DoHSession is returning randomized DoH response in case of
synthetic mode or the relative DoH response in case of original mode.

'''


class DoHServer:
    def __init__(self, doh_responses) -> None:
        self.doh_responses = doh_responses
        self.seq          = 0
        self.ack          = 0
        self.output_packets_buffer = []
    
    def output_packets_of(self,doh_proxy: DoHProxy, packets: list, is_termination=False, mode =''):  #Idea: Add here index instead of random.
        packet = packets[-1]
        time = packet.time
        if is_termination == True:
            return list(map(lambda p: self._update_seq_ack(p), packets))
        if DNS in packet and packet[DNS].qr == 1: # if its a DNS response 
            doh_response= list()
            packets101= list()
            if mode == 's':
                doh_response=random.choice(self.doh_responses)
            else:
                index=doh_proxy.get_response_index(packet)
               # print(index , " length: " , len(self.doh_responses[0]))
                if index == -1:
                    exit(-1)
                try:
                    doh_response = self.doh_responses[0][index]  # [0][0] index is the relative response to query
                    # del self.doh_responses[0][0]
                except:
                    doh_response = self.doh_responses[0][1]

                if self.doh_responses[1][-1][-1] == True: #if its the first response
                    self.doh_responses[1][-1][-1]=False
                    for pkt in self.doh_responses[1][-1][:-1]:
                        packets101.append(pkt) #append 101 pkt without bool
            acks_in_buffer = list(filter(lambda p: len(p[TCP].payload)==0, self.output_packets_buffer))
            for ack in acks_in_buffer:
                ack.time = sum([ack.time, packet.time]) / 2
            updated_res = list(map(lambda p: self._update_seq_ack(p),
                                    doh_response))
            updated_res.extend(packets101)
            for updated_pkt in updated_res:
                if updated_pkt.time - doh_response[0].time >0:
                    updated_pkt.time = time + (updated_pkt.time - doh_response[0].time)
                else:
                    updated_pkt.time = time + (doh_response[0].time - updated_pkt.time)
            self.output_packets_buffer.extend(updated_res)
            output_packets = self.output_packets_buffer.copy()
            self.output_packets_buffer.clear()
            return output_packets
        elif TCP in packet:
            self.ack = packet[TCP].seq + len(packet[TCP].payload)
            if mode == 's':
                self.output_packets_buffer.append(
                    self._update_seq_ack(
                        self._create_tcp_ack_packet(time)))

            return []

        else:
            return []
            
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