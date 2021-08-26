from doh_dispatcher import DoHDispatcher
from handshake import Handshake
from doh_proxy import DoHProxy
from scapy.all import *
import sys

print('[System] Version: Alpha | 2.0.0')
print('[System] By Ariel University')
print('[Step 1/5] Starting...')
OriginalPcapName="./MalwareOriginal.pcap"
#OriginalPcapName= input("Please enter path to input pcap")
inputpcap=rdpcap(OriginalPcapName) #PcapReader
print('[Step 2/5] Loading PCAPS into memory...')
opensession  = rdpcap('./pcaps/OpenSessionV2.pcap')
closesession = rdpcap('./pcaps/TerminationV2.pcap')
dohQueryNextDNS     = rdpcap('./pcaps/NextDNS/DoHQuery.pcap')
dohQueryQuad9    = rdpcap('./pcaps/Quad9/DoHQuery2.pcap')
dohResponseNextDNS  = rdpcap('./pcaps/NextDNS/DoHResponse.pcap')
dohResponseQuad9    = rdpcap('./pcaps/Quad9/DoHResponse.pcap')
#inputpcap    = rdpcap('./pcaps/DNSinput.pcap', count=222)
handshake  = Handshake(opensession)
termination = closesession
outputpcap = list()
userDecision= input("Press s for synthatic OR o for original")
doh_proxy=list()
if( userDecision =='s'):
    DoHpcapName = "./MalwareProxy.pcap"
    inputDoHpcap = rdpcap(DoHpcapName)
    doh_proxy = DoHProxy(inputDoHpcap, inputpcap.copy())
    dns_server = doh_proxy.dns_server
    doh_dispatcher = DoHDispatcher(doh_proxy, handshake, [dohQueryNextDNS, dohQueryQuad9], [dohResponseNextDNS, dohResponseQuad9],
                                   termination,userDecision, doh_server_ip=dns_server)
elif(userDecision =='o'):
    DoHpcapName="./MalwareProxy.pcap"
    #DoHpcapName = input("Please enter path to DoH proxy pcap")
    inputDoHpcap = rdpcap(DoHpcapName)
    doh_proxy = DoHProxy(inputDoHpcap,inputpcap.copy())
    dns_server=doh_proxy.dns_server
    handshake = Handshake(doh_proxy.handshake)
    doh_dispatcher=DoHDispatcher(doh_proxy,handshake,doh_proxy.queries,[doh_proxy.responses,doh_proxy.packet_101],
                                 doh_proxy.termination,userDecision,doh_server_ip=dns_server)

else:
    print("Error please run again and choose o or s")
    exit(-1)

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
wrpcap('nonvpn-filetransfer-scp-62DoH.pcap', outputpcap)

print("[Step 5/5] Done! Please see `MalwareOutput.pcap` file")
