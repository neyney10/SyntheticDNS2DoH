from scapy.all import *
class Handshake:
    def __init__(self, packets) -> None:
        self.packets = packets
        
    def output_packets(self, time):
        output_packets = []
        for i, packet in enumerate(self.packets):
            updated_packet = packet.copy()
            updated_packet.time = time \
                                  + (self.packets[i].time - self.packets[0].time)
            output_packets.append(updated_packet)
            
        return output_packets
        
    def get_initial_seq_ack_values(self):
        first_packet = self.packets[0]
        src2dst_packets = self.src2dst_packets()
        dst2src_packets = self.dst2src_packets()
        
        src_seq = src2dst_packets[-1][TCP].seq + len(src2dst_packets[-1][TCP].payload)
        dst_seq = dst2src_packets[-1][TCP].seq + len(dst2src_packets[-1][TCP].payload)
        
        src_ack = dst_seq
        dst_ack = src_seq
        
        return (src_seq, src_ack, dst_seq, dst_ack)
    
    def src2dst_packets(self):
        first_packet = self.packets[0]
        return list(filter(lambda pkt: pkt[IP].src == first_packet[IP].src,
                            self.packets))
        
    def dst2src_packets(self):
        first_packet = self.packets[0]
        return list(filter(lambda pkt: pkt[IP].src == first_packet[IP].dst,
                            self.packets))
    
    @property
    def duration(self) -> float:
        return self.packets[-1].time - self.packets[0].time