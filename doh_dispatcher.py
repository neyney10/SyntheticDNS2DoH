from scapy.all import *
from doh_session import DoHSession2
from doh_user import DoHUser
from doh_proxy import DoHProxy
import random
'''
This class has the main responsibility to manage the replacement of DNS packets to DoH.

@is_belongs function returns to main True if the packet is DNS or the packet belongs to the session(by IP address)
and false if not.

@output_packets_of function is getting activate by main.py if and only if the packet is DNS,
if the packet is a DNS packet it checks if its DNS query or response.

@ _on_dns_query is activate by @output_packets_of in case of DNS query packet. It will create
DoHUser object and DoHSession object and will use their functions to get the relevant DoH packets to replace
the DNS query.

@ _on_dns_response is activate by @output_packets_of in case of DNS response packet. It will get the relevant
DoHUser object and DoHSession object and will use their functions to get the relevant DoH packets to replace
the DNS response.

@_on_other is activate by @output_packets_of in case of not DNS packet but yet belongs to DoHUser, and will
use the DoHUser object's functions.

@terminate_all_sessions is activate by main.py at the end of the iteration over the pcap file.
it will put termination packets to each DoHUser that exists.

@_create_new_doh_session is activate by @_on_dns_query in case of session that doesn't exist yet,
it creates new DoHSession object and returns it.
'''
class DoHDispatcher:
    def __init__(self,doh_proxy, handshake, doh_queries, doh_responses, termination, mode, doh_server_ip: str) -> None:
        self.mode=mode
        self.handshake = handshake
        self.doh_queries = doh_queries
        self.doh_responses = doh_responses
        self.termination = termination
        self.doh_server_ip = doh_server_ip
        self.doh_users = dict()
        self.doh_proxy= doh_proxy
    
    def output_packets_of(self, packet):
        # assumes that DNS in packet
        if DNS in packet and IP in packet:
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
                output_packets.extend(doh_user.output_packets_of(packet,mode=self.mode))
            else: # failsafe, if there is a response without query, output it as it is
                output_packets.append(packet)
                
        return output_packets
    
    def _on_dns_query(self, packet):
        output_packets = []
        
        if packet[IP].src not in self.doh_users:
            self.doh_users[packet[IP].src] = DoHUser(packet[IP].src, [])
            #ask new class for doh relevant query & response.
            
        doh_user = self.doh_users[packet[IP].src]

        if not doh_user.is_belongs(packet):
            new_doh_session = self._create_new_doh_session(
                src_ip=packet[IP].src,
                dst_ip=packet[IP].dst,
                src_port=packet[UDP].sport,
                new_dst_ip=self.doh_server_ip,
                new_dst_port=443,
                time=packet.time,
                handshake=self.handshake,
                termination=self.termination,
                doh_query=self.doh_queries,
                doh_response=self.doh_responses,
            )
            doh_user.add_session(new_doh_session)
                        
        output_packets.extend(doh_user.output_packets_of(packet,mode=self.mode)) # add here index
                
        return output_packets
    
    def _on_other(self, packet):
        if packet[IP].src in self.doh_users:
            doh_user = self.doh_users[packet[IP].src]
            return doh_user.output_packets_of(packet,self.mode)
        else:
            if packet[IP].dst in self.doh_users:
                doh_user = self.doh_users[packet[IP].dst]
                return doh_user.output_packets_of(packet,self.mode)
    
    def _create_new_doh_session(self, src_ip, src_port, dst_ip, new_dst_ip, new_dst_port, time, handshake, termination, doh_query, doh_response):
        new_doh_session = DoHSession2(self.doh_proxy,src_ip, dst_ip, new_dst_ip, src_port, new_dst_port, time, doh_query, doh_response, handshake, termination)
        
        return new_doh_session
    
    def is_belongs(self, packet):
        if not IP in packet:
            return False
        if DNS in packet and IP in packet and ICMP not in packet and packet[UDP].sport != 5353 and packet[UDP].dport != 5353 :
            return True
        return packet[IP].src in self.doh_users or packet[IP].dst in self.doh_users