from scapy.all import Ether, IP, UDP, TCP, rdpcap, wrpcap, Ether
import scapy.contrib.http2 as h2
import numpy as np
from scapy.utils import PcapWriter


#packets = rdpcap("./single-doh-query.pcap")
#print(packets)

b_text = b'\xd4\x35\x1d\x15\x9b\x30\xc8\xff\x28\x9e\x85\xaf\x08\x00\x45\x00\x00\x39\x7c\x32\x40\x00\x80\x06\xf9\x81\xc0\xa8\x01\x69\xac\xd9\x16\x0a\xeb\x2c\x00\x50\x6e\xbf\x29\xdc\x90\x4a\x6b\xe3\x50\x18\x01\x00\xeb\x2e\x00\x00\x00\x00\x08\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
binary = bytes(b_text)

print(binary)

binary_tcp_payload = bytes(np.fromfile('packetbytes.bin', dtype='uint8'))
print(binary_tcp_payload)

binary_packet = h2.H2Frame(stream_id=21, len=3) / h2.H2DataFrame('das')
binary_packet.show()

packet = Ether() / IP(dst="www.slashdot.org") / TCP(sport=43242, flags="") / binary_packet




#a= Ether() / IP(dst="www.slashdot.org") / TCP()/"GET /index.html HTTP/1.0 \n\n"
#wrpcap("out.pcap", Ether(binary))
pktdump = PcapWriter("out.pcap", append=False, sync=True)
