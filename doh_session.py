from doh_server import DoHServer
from doh_client import DoHClient
from handshake import Handshake
from scapy.all import *
from doh_proxy import DoHProxy
'''
This class represents a DoHSession which has its own ip addresses, handshake, termination,
 DoHClient, DoHserver etc.

@output_packets_of receives a DNS packet from the relevant DoHUser (which activate this function) and
according to the nature of the DNS packet (query or response) it uses the @output_packets_of function of
the DoHClient and DoHserver objects to get the relevant DoH packets to replace with the DNS packet.

'''

class DoHSession2:
    def __init__(self,doh_proxy, old_src_ip, old_dst_ip, new_dst_ip, new_src_port, new_dst_port, start_time, doh_queries: list, doh_responses: list, handshake: Handshake, termination) -> None:
        self.doh_proxy  = doh_proxy
        self.old_src_ip = old_src_ip
        self.old_dst_ip = old_dst_ip
        self.new_dst_ip = new_dst_ip
        self.new_src_port = new_src_port
        self.new_dst_port = new_dst_port
        self.start_time = start_time
        self.handshake = handshake
        self.termination = termination
        self.doh_client = DoHClient(doh_queries)
        self.doh_server = DoHServer(doh_responses)
        src_seq, src_ack, dst_seq, dst_ack = self.handshake.get_initial_seq_ack_values()
        self.doh_client.set_seq(src_seq)
        self.doh_client.set_ack(src_ack)
        self.doh_server.set_seq(dst_seq)
        self.doh_server.set_ack(dst_ack)
        self.is_first_query = True
        self.last_dns_packet_time = 0
        self.additonal_pushback= 0

    def output_packets_of(self, packet,mode):
        output_packets = []
        self.last_dns_packet_time = packet.time
        if packet[DNS].qr == 0:
            handshake_packets=list()
            if self.is_first_query:
                handshake_packets=self.get_handshake_packets(self.start_time)
            if mode =='o' or not self.is_first_query:
                self.is_first_query = False
                client_res = self.doh_client.output_packets_of([packet],mode=mode)
                server_res = self.doh_server.output_packets_of(self.doh_proxy,client_res,mode=mode)
                client_res = list(map(lambda p:  self._update_ip_addresses(p,
                                                                            self.old_src_ip,
                                                                            self.new_dst_ip,
                                                                            self.new_src_port,
                                                                            self.new_dst_port),
                                            client_res))
                
                server_res = list(map(lambda p:  self._update_ip_addresses(p,
                                                                            self.new_dst_ip,
                                                                            self.old_src_ip,
                                                                            self.new_dst_port,
                                                                            self.new_src_port),
                                            server_res))
                output_packets.extend(client_res + server_res)
                for pkt in output_packets:
                    pkt.time += self.handshake.duration
                output_packets= handshake_packets + output_packets
        elif packet[DNS].qr == 1:
            server_res = self.doh_server.output_packets_of(self.doh_proxy,[packet],mode =mode)
            client_res = self.doh_client.output_packets_of(server_res,mode=mode)
            duplicate_pkts=list()
            for pkt in server_res: ########## for clients ack & 101 packet
                if pkt[IP].src == '10.0.2.15':
                    new_pkt=self.doh_client._update_seq_ack(pkt)
                    client_res.append(new_pkt)
                    duplicate_pkts.append(pkt)
            for pkt in duplicate_pkts:
                if pkt in server_res:
                    server_res.remove(pkt) #############

            client_res = list(map(lambda p:  self._update_ip_addresses(p,
                                                                        self.old_src_ip,
                                                                        self.new_dst_ip,
                                                                        self.new_src_port,
                                                                        self.new_dst_port),
                                        client_res))
            
            server_res = list(map(lambda p:  self._update_ip_addresses(p,
                                                                        self.new_dst_ip,
                                                                        self.old_src_ip,
                                                                        self.new_dst_port,
                                                                        self.new_src_port),
                                        server_res))

            output_packets.extend(server_res + client_res)
            output_packets.sort(key=lambda p: p.time)
            for pkt in output_packets:
                pkt.time += self.handshake.duration
        

        self.additonal_pushback=self.calculate_additonal_pushback(output_packets)
        return output_packets


    def get_handshake_packets(self, time):
        handshake_packets = self.handshake.output_packets(time)
        handshake_first_packet = handshake_packets[0]
        handshake_src_ip = handshake_first_packet[IP].src
        def update_ip_addresses_bidirectional(p):
            if p[IP].src == handshake_src_ip:
                return self._update_ip_addresses(p, self.old_src_ip, self.new_dst_ip, self.new_src_port, self.new_dst_port)
            else:
                return self._update_ip_addresses(p, self.new_dst_ip, self.old_src_ip, self.new_dst_port, self.new_src_port)
        return list(map(lambda p: update_ip_addresses_bidirectional(p), handshake_packets))
    
    def get_termination_packets(self, gap_time):
        # assuming that the first packet is from the source
        first_packet = self.termination[0]
        output_packets = []
        time = self.last_dns_packet_time
        def update_ip_addresses_seq_ack_bidirectional(p):
            if p[IP].src == first_packet[IP].src:
                return self.doh_client.output_packets_of(
                    [self._update_ip_addresses(p, self.old_src_ip, self.new_dst_ip, self.new_src_port, self.new_dst_port)], True)
            else:
                return self.doh_server.output_packets_of(self.doh_proxy,
                    [self._update_ip_addresses(p, self.new_dst_ip, self.old_src_ip, self.new_dst_port, self.new_src_port)], True)
                
        updated_ip_seq_ack_port_packets = sum(map(lambda p: update_ip_addresses_seq_ack_bidirectional(p), self.termination), [])
        for i, updated_packet in enumerate(updated_ip_seq_ack_port_packets):
            updated_packet.time = time \
                                + (self.termination[i].time - self.termination[0].time) \
                                + gap_time \
                                + self.handshake.duration \
                                + self.additonal_pushback
            output_packets.append(updated_packet)
            
        return output_packets
    
    def _update_ip_addresses(self, packet, src_ip, dst_ip, src_port, dst_port):
        cloned_packet = packet.copy()
        cloned_packet[IP].src = src_ip
        cloned_packet[IP].dst = dst_ip
        cloned_packet[TCP].sport = src_port
        cloned_packet[TCP].dport = dst_port

        return cloned_packet

    def calculate_additonal_pushback(self, output_packets):
        time=output_packets[0].time
        last_pkt_time= output_packets[-1].time
        ans = last_pkt_time-time
        if ans == 0 and self.additonal_pushback != 0: #to keep packets in their order
            ans = self.additonal_pushback
        return ans