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
        if DNSRR in packet:
            return self._doh_output(packet, self.doh_response)
        elif DNSQR in packet:
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
            
        

        tcp_ack_packet = Ether()/IP(src=doh_packets[-1][IP].dst, dst=doh_packets[-1][IP].src)\
                         /TCP(flags='A',sport=doh_packets[-1][TCP].dport, dport=doh_packets[-1][TCP].sport,\
                         window=doh_packets[-1][TCP].window,seq=doh_packets[-1][TCP].seq, ack=doh_packets[-1][TCP].seq)

        tcp_ack_packet.time=output_packets[-1].time
        updated_tcp_ack_packet = self.tcp_session.output_packets_of(tcp_ack_packet)
        output_packets.append(updated_tcp_ack_packet[0])

        return output_packets
    
    def _update_ip_addresses(self, packet, src_ip, dst_ip):
        cloned_packet = packet.copy()
        cloned_packet[IP].src = src_ip
        cloned_packet[IP].dst = dst_ip
        
        return cloned_packet
                                    
                