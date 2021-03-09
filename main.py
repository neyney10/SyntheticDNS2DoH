from doh_dispatcher import DoHDispatcher
from handshake import Handshake
from scapy.all import *

print('[System] Version: Alpha | 1.0.0')
print('[System] By Ariel University')
print('[Step 1/5] Starting...')
print('[Step 2/5] Loading PCAPS into memory...')
opensession  = rdpcap('./pcaps/NextDNS/OpenSession.pcapng')
closesession = rdpcap('./pcaps/NextDNS/Termination.pcapng')
dohQueryNextDNS     = rdpcap('./pcaps/NextDNS/DoHQuery.pcapng')
dohQueryQuad9    = rdpcap('./pcaps/Quad9/DoHQuery2.pcap')
dohResponseNextDNS  = rdpcap('./pcaps/NextDNS/DoHResponse.pcapng')
dohResponseQuad9    = rdpcap('./pcaps/Quad9/DoHResponse.pcap')
inputpcap    = rdpcap('./pcaps/DNSinput.pcap', count=222)

handshake  = Handshake(opensession)
termination = closesession
outputpcap = list()

doh_dispatcher = DoHDispatcher(handshake, [dohQueryNextDNS, dohQueryQuad9], [dohResponseNextDNS, dohResponseQuad9], termination, keep_handshake_dst_ip=True)

print('[Step 3/5] Starting synthatic DoH conversion...')

for packet in inputpcap:
    if doh_dispatcher.is_belongs(packet):
        outputpcap.extend(doh_dispatcher.output_packets_of(packet))
    else:
        outputpcap.append(packet)

outputpcap.extend(doh_dispatcher.terminate_all_sessions(10/1000, 500/1000))
# Sort packets by time.
outputpcap.sort(key=lambda p: p.time)

# Write all changes to new pcap file
print("[Step 4/5] Saving into a new PCAP file...")
wrpcap('out.pcap', outputpcap)

print("[Step 5/5] Done! Please see `out.pcap` file")
