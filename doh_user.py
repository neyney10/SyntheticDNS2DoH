from scapy.all import *
class DoHUser:
    def __init__(self, ip_address: str, sessions: list) -> None:
        self.ip_address = ip_address
        self._pushback_duration = 0
        self._sessions = dict()
        
        for session in sessions:
            self._sessions[self._session_four_tuple_string_of(session)] = session
            self._pushback_duration += session.handshake.duration
        
        
    def output_packets_of(self, packet) -> list:
        '''
        Description: 
            Receives a single packet and returns
            a new updated packets (can be multiple) in terms of IP, ACK num, SEQ num, Time.
        Params:
            packet: packet from a pcap file (Scapy format).
        Returns:
            packets: a list of new updated packets.
        '''
        if UDP in packet and self._packet_four_tuple_string_of(packet) in self._sessions:
            doh_session = self._sessions[self._packet_four_tuple_string_of(packet)]
            updated_packets = doh_session.output_packets_of(packet)
            output_packets = []
            for updated_pkt in updated_packets:
                updated_pkt.time += self._pushback_duration - doh_session.handshake.duration
                output_packets.append(updated_pkt)
            
            return output_packets
        else: # non doh session.
            cloned_packet = packet.copy()
            cloned_packet.time += self._pushback_duration
            
            return [cloned_packet]
            
    def add_session(self, session):
        self._sessions[self._session_four_tuple_string_of(session)] = session
        self._pushback_duration += session.handshake.duration
    
    def is_belongs(self, packet):
        return self._packet_four_tuple_string_of(packet) in self._sessions
    
    def _session_four_tuple_string_of(self, session):
        tcp_session = session.tcp_session
        return ''.join(sorted([tcp_session.src_ip,
                        str(tcp_session.src_port),
                        tcp_session.dst_ip,
                        str(tcp_session.dst_port)]))
        
    def _packet_four_tuple_string_of(self, packet):
        return ''.join(sorted([packet[IP].src,
                        str(packet[UDP].sport),
                        packet[IP].dst,
                        str(packet[UDP].dport)]))
    
    