from doh_dispatcher import DoHDispatcher
from handshake import Handshake
from doh_session import DoHSession
from doh_user import DoHUser
from scapy.all import *
from tcp_session import TCPSession

opensession  = rdpcap('./pcaps/NewTCPandTLSOpen.pcap')
closesession = rdpcap('./pcaps/TLSandTCPclose.pcap')
dohQuery     = rdpcap('./pcaps/DoHQuery2.pcap')
dohResponse  = rdpcap('./pcaps/DoHResponse.pcap')
inputpcap    = rdpcap('./pcaps/DNSinput.pcap', count=100)

handshake = Handshake(opensession)
outputpcap=list()

doh_dispatcher = DoHDispatcher(handshake, dohQuery, dohResponse, None, keep_handshake_dst_ip=True)

for packet in inputpcap:
    if DNS in packet:
        outputpcap.extend(doh_dispatcher.output_packets_of(packet))
    else:
        outputpcap.append(packet)
        
# Write all changes to new pcap file
wrpcap('out.pcap', outputpcap)


print("done")
