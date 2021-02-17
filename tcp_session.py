from scapy.all import *
class TCPSession:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, handshake, termination) -> None:
        self.src_ip       = src_ip      # Original src ip
        self.src_port     = src_port    # Original src port
        self.dst_ip       = dst_ip      # Original src port
        self.dst_port     = dst_port    # Original src port
        self.handshake    = handshake
        self._termination = termination
        self.src_seq, self.src_ack, self.dst_seq,self.dst_ack = self.handshake.get_initial_seq_ack_values()

        
    def output_packets_of(self, packet):
        if self._is_src2dst(packet):
            updated_packet, self.src_seq = self._update_seq_ack(packet, 
                                                                self.src_seq, 
                                                                self.src_ack)
            self.dst_ack = self.src_seq
        else:
            updated_packet, self.dst_seq = self._update_seq_ack(packet, 
                                                                self.dst_seq, 
                                                                self.dst_ack)
            self.src_ack = self.dst_seq
            
        return [updated_packet]

    def get_termination_packets(self):
        return self.termination

    def _is_src2dst(self, packet) -> bool:
        return packet[IP].src == self.src_ip
    
    def _update_seq_ack(self, packet, old_seq, old_ack):
        cloned_packet = packet.copy()
        cloned_packet[TCP].seq = old_seq
        cloned_packet[TCP].ack = old_ack
        return (cloned_packet, old_seq + len(cloned_packet[TCP].payload))
    
    def _update_ip_addresses(self, packet, src_ip, dst_ip):
        cloned_packet = packet.copy()
        cloned_packet[IP].src = src_ip
        cloned_packet[IP].dst = dst_ip
        
        return cloned_packet