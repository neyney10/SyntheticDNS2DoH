from scapy.all import *

'''
This class represents a DoHUser and holds its ip address and the user's sessions.

@output_packets_of receives a signle packet and returns the updated DoH packets by using
@output_packets_of function of the relevant DoHSession object.
'''


class DoHUser:
    def __init__(self, ip_address: str, sessions: list) -> None:
        self.ip_address = ip_address
        self.requested_ips_by_dns = dict()
        self._pushback_duration = 0
        self._sessions = dict()
       # self.last_dns_packet_time=0
        self.additonal_pushback=0
        for session in sessions:
            self._sessions[self._session_two_tuple_string_of(session)] = session
            self._pushback_duration += session.handshake.duration


    def calculate_additonal_pushback(self, output_packets):
        time=output_packets[0].time
        last_pkt_time= output_packets[-1].time
        return last_pkt_time-time



    def output_packets_of(self, packet,mode):
        '''
        Description:  
            Receives a single packet and returns
            a new updated packets (can be multiple) in terms of IP, ACK num, SEQ num, Time.
        Params:
            packet: packet from a pcap file (Scapy format).
        Returns:
            packets: a list of new updated packets.
        '''
        if DNS in packet and self._packet_two_tuple_string_of(packet) in self._sessions:
            doh_session = self._sessions[self._packet_two_tuple_string_of(packet)]
            updated_packets = doh_session.output_packets_of(packet,mode=mode)
            output_packets = []
            for updated_pkt in updated_packets:
                updated_pkt.time += self._pushback_duration - doh_session.handshake.duration # if there are multiple handshakes
                updated_pkt.time += self.additonal_pushback # additonal pushback to avoid unordered packets
                output_packets.append(updated_pkt)
            
            if packet[DNS].qr == 1 and DNSRR in packet : # if response | calculate times, add it as value, key = ip addresess
                self.additonal_pushback= self.calculate_additonal_pushback(output_packets)
                for a in range(packet[DNS].ancount):
                    self.requested_ips_by_dns[packet[DNSRR][a].rdata] = self.additonal_pushback

            
            #self.last_dns_packet_time = packet.time
            return output_packets
        else: # non doh session. 
            cloned_packet = packet.copy()
            if cloned_packet[IP].src in self.requested_ips_by_dns:
                cloned_packet.time += (self._pushback_duration + self.requested_ips_by_dns[cloned_packet[IP].src])

            elif cloned_packet[IP].dst in self.requested_ips_by_dns :
                cloned_packet.time += (self._pushback_duration + self.requested_ips_by_dns[cloned_packet[IP].dst])

            
            return [cloned_packet]
        
    def get_handshake_packets(self, session, time):
        handshake_packets = session.get_handshake_packets(time)
        updated_handshake_packets = []
        for pkt in handshake_packets:
            pkt.time += self._pushback_duration - session.handshake.duration
            updated_handshake_packets.append(pkt)
            
        return updated_handshake_packets
    
    def get_termination_packets_of_sessions(self, gap_time):
        return sum(
            map(
                lambda s: s.get_termination_packets(gap_time), 
                self._sessions.values()
            ),
            []
        )
            
    def add_session(self, session):
        self._sessions[self._session_two_tuple_string_of(session)] = session
        self._pushback_duration += session.handshake.duration
    
    def is_belongs(self, packet):
        return self._packet_two_tuple_string_of(packet) in self._sessions
    
    def _session_two_tuple_string_of(self, session):
        return ''.join(sorted([session.old_src_ip, session.old_dst_ip]))
        
    def _packet_two_tuple_string_of(self, packet):
        return ''.join(sorted([packet[IP].src, packet[IP].dst]))



