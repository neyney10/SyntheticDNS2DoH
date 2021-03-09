from doh_server import DoHServer
from doh_client import DoHClient
from handshake import Handshake
from scapy.all import *
from tcp_session import TCPSession

class DoHSession:
    def __init__(self, tcp_session: TCPSession, doh_query: list, doh_response: list, keep_handshake_dst_ip: bool) -> None:
        self.tcp_session = tcp_session
        self.keep_handshake_dst_ip = keep_handshake_dst_ip
        self.handshake = tcp_session.handshake

        new_src_ip = self.tcp_session.src_ip
        new_dst_ip = self.handshake.packets[0][IP].dst if self.keep_handshake_dst_ip else self.tcp_session.dst_ip
        self.doh_query = list(map(lambda p: self._update_ip_addresses(p, new_src_ip, new_dst_ip), doh_query))
        self.doh_response = list(map(lambda p: self._update_ip_addresses(p, new_dst_ip, new_src_ip), doh_response))

    def output_packets_of(self, packet):
        if packet[DNS].qr == 1:
            return self._doh_output(packet, self.doh_response)
        elif packet[DNS].qr == 0:
            return self._doh_output(packet, self.doh_query)

    def get_handshake_packets(self, time):
        handshake_packets = self.handshake.output_packets(time)
        handshake_first_packet = handshake_packets[0]
        handshake_src_ip = handshake_first_packet[IP].src
        handshake_dst_ip = handshake_first_packet[IP].dst
        new_src_ip = self.tcp_session.src_ip
        new_dst_ip = handshake_dst_ip if self.keep_handshake_dst_ip else self.tcp_session.dst_ip
        def update_ip_addresses_bidirectional(p):
            if p[IP].src == handshake_src_ip:
                return self._update_ip_addresses(p, new_src_ip, new_dst_ip)
            else:
                return self._update_ip_addresses(p, new_dst_ip, new_src_ip)
        return list(map(lambda p: update_ip_addresses_bidirectional(p), handshake_packets))
    
    def _doh_output(self, packet, doh_packets):
        handshake_duration = self.handshake.duration
        output_packets = []
        for doh_pkt in doh_packets:
            updated_packets = self.tcp_session.output_packets_of(doh_pkt)
            for updated_pkt in updated_packets:
                updated_pkt.time = packet.time \
                                    + handshake_duration \
                                    + (doh_pkt.time - doh_packets[0].time)
                                    
                output_packets.append(updated_pkt)
        
        tcp_ack_packet = Ether()/IP(src=doh_packets[-1][IP].dst, dst=doh_packets[-1][IP].src) \
                         /TCP(flags='A', sport=doh_packets[-1][TCP].dport, dport=doh_packets[-1][TCP].sport,
                         window=doh_packets[-1][TCP].window, seq=doh_packets[-1][TCP].seq, ack=doh_packets[-1][TCP].seq)

        tcp_ack_packet.time= output_packets[-1].time
        updated_tcp_ack_packet = self.tcp_session.output_packets_of(tcp_ack_packet)
        output_packets.extend(updated_tcp_ack_packet)

        return output_packets
    
    def _update_ip_addresses(self, packet, src_ip, dst_ip):
        cloned_packet = packet.copy()
        cloned_packet[IP].src = src_ip
        cloned_packet[IP].dst = dst_ip
        
        return cloned_packet
                                    
                
                

class DoHSession2:
    def __init__(self, old_src_ip, old_dst_ip, new_dst_ip, new_src_port, new_dst_port, start_time, doh_queries: list, doh_responses: list, handshake: Handshake, termination) -> None:
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

    def output_packets_of(self, packet):
        output_packets = []
        self.last_dns_packet_time = packet.time
        if packet[DNS].qr == 0:
            if self.is_first_query:
                self.is_first_query = False
                output_packets = self.get_handshake_packets(self.start_time)
            else:
                client_res = self.doh_client.output_packets_of([packet])
                server_res = self.doh_server.output_packets_of(client_res)
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
                output_packets = client_res + server_res
        elif packet[DNS].qr == 1:
            server_res = self.doh_server.output_packets_of([packet])
            client_res = self.doh_client.output_packets_of(server_res)
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
                                       
            output_packets = server_res + client_res
        
        for pkt in output_packets:
            pkt.time += self.handshake.duration
            
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
                return self.doh_server.output_packets_of(
                    [self._update_ip_addresses(p, self.new_dst_ip, self.old_src_ip, self.new_dst_port, self.new_src_port)], True)
                
        updated_ip_seq_ack_port_packets = sum(map(lambda p: update_ip_addresses_seq_ack_bidirectional(p), self.termination), [])
        for i, updated_packet in enumerate(updated_ip_seq_ack_port_packets):
            updated_packet.time = time \
                                + (self.termination[i].time - self.termination[0].time) \
                                + gap_time
            output_packets.append(updated_packet)
            
        return output_packets
    
    def _update_ip_addresses(self, packet, src_ip, dst_ip, src_port, dst_port):
        cloned_packet = packet.copy()
        cloned_packet[IP].src = src_ip
        cloned_packet[IP].dst = dst_ip
        cloned_packet[TCP].sport = src_port
        cloned_packet[TCP].dport = dst_port
        return cloned_packet