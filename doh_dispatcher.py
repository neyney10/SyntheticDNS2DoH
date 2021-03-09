from scapy.all import *
from doh_session import DoHSession, DoHSession2
from tcp_session import TCPSession
from doh_user import DoHUser
import random

class DoHDispatcher:
    def __init__(self, handshake, doh_queries, doh_responses, termination, keep_handshake_dst_ip: bool) -> None:
        self.handshake = handshake
        self.doh_queries = doh_queries
        self.doh_responses = doh_responses
        self.termination = termination
        self.keep_handshake_dst_ip = keep_handshake_dst_ip
        self.doh_users = dict()
    
    def output_packets_of(self, packet):
        # assumes that DNS in packet
        if DNS in packet:
            if packet[DNS].qr == 0:
                return self._on_dns_query(packet)
            else:
                return self._on_dns_response(packet)
        else: # if not DNS, check if it belongs to one of the users
            return self._on_other(packet)

    def terminate_all_sessions(self, min_gap_time, max_gap_time):
        
        output_packets = []
        for user in self.doh_users.values():
            gap_time = random.uniform(min_gap_time, max_gap_time)
            output_packets.extend(user.get_termination_packets_of_sessions(gap_time))
            
        return output_packets
        
    def _on_dns_response(self, packet):
        output_packets = []
        if packet[IP].dst in self.doh_users:
            # if user exists
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
                src_ip=packet[IP].src,
                dst_ip=packet[IP].dst,
                src_port=packet[UDP].sport,
                new_dst_ip='149.122.122.122',
                new_dst_port=443,
                time=packet.time,
                handshake=self.handshake,
                termination=self.termination,
                doh_query=self.doh_queries,
                doh_response=self.doh_responses,
            )
            doh_user.add_session(new_doh_session)
                        
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
    
    def _create_new_doh_session(self, src_ip, src_port, dst_ip, new_dst_ip, new_dst_port, time, handshake, termination, doh_query, doh_response):
        new_doh_session = DoHSession2(src_ip, dst_ip, new_dst_ip, src_port, new_dst_port, time, doh_query, doh_response, handshake, termination)
        
        return new_doh_session
    
    def is_belongs(self, packet):
        if not IP in packet:
            return False
        if DNS in packet:
            return True
        return packet[IP].src in self.doh_users or packet[IP].dst in self.doh_users