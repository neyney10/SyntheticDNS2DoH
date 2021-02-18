from scapy.all import *
from doh_session import DoHSession
from tcp_session import TCPSession
from doh_user import DoHUser

class DoHDispatcher:
    def __init__(self, handshake, doh_query, doh_response, termination, keep_handshake_dst_ip: bool) -> None:
        self.handshake = handshake
        self.doh_query =doh_query
        self.doh_response = doh_response
        self.keep_handshake_dst_ip = keep_handshake_dst_ip
        self.doh_users = dict()
    
    def output_packets_of(self, packet):
        # assumes that DNS in packet
        if DNS in packet:
            if DNSQR in packet and not DNSRR in packet: 
                return self._on_dns_query(packet)
            else:
                return self._on_dns_response(packet)
        else: # if not DNS, check if it belongs to one of the users
            return self._on_other(packet)

    def _on_dns_response(self, packet):
        output_packets = []
        if packet[IP].dst in self.doh_users:
            # if session exists
            doh_user = self.doh_users[packet[IP].dst]
            if doh_user.is_belongs(packet):
                # if session exists
                output_packets.extend(doh_user.output_packets_of(packet))
            else: # failsafe, if there is a response without query, output it as it is
                output_packets.append(packet)
                
        return output_packets
    
    def _on_dns_query(self, packet):
        output_packets = []
        
        if packet[IP].src not in self.doh_users:
            self.doh_users[packet[IP].src] = DoHUser(packet[IP].src, [])
            
        doh_user = self.doh_users[packet[IP].src]

        if not doh_user.is_belongs(packet):
            new_doh_session = self._create_new_doh_session(
                    packet[IP].src,
                    packet[UDP].sport,
                    packet[IP].dst,
                    packet[UDP].dport,
                    self.handshake,
                    None,
                    self.doh_query,
                    self.doh_response,
                    self.keep_handshake_dst_ip
                )
            doh_user.add_session(new_doh_session)
            output_packets.extend(new_doh_session.get_handshake_packets(packet.time))
            
        output_packets.extend(doh_user.output_packets_of(packet))
                
        return output_packets
    
    def _on_other(self, packet):
        if packet[IP].src in self.doh_users:
            doh_user = self.doh_users[packet[IP].src]
            return doh_user.output_packets_of(packet)
        else:
            if packet[IP].dst in self.doh_users:
                doh_user = self.doh_users[packet[IP].dst]
                return doh_user.output_packets_of(packet)
    
    def _create_new_doh_session(self, src_ip, src_port, dst_ip, dst_port, handshake, termination, doh_query, doh_response, keep_handshake_dst_ip):
        new_tcp_session = TCPSession(src_ip,
                                    src_port, 
                                    dst_ip, 
                                    dst_port, 
                                    handshake, 
                                    termination)
        new_doh_session = DoHSession(new_tcp_session, doh_query, doh_response, keep_handshake_dst_ip)
        
        return new_doh_session
    
    def is_belongs(self, packet):
        if not IP in packet:
            return False
        if DNS in packet:
            return True
        return packet[IP].src in self.doh_users or packet[IP].dst in self.doh_users