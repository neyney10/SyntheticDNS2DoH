from scapy.all import *
opensession=rdpcap('C:/Users/Zohar_ysncvfn/PycharmProjects/FinalProject/venv/pcaps/TCPandTLSopen2.pcap')
closesession=rdpcap('C:/Users/Zohar_ysncvfn/PycharmProjects/FinalProject/venv/pcaps/TLSandTCPclose.pcap')
dohQuery=rdpcap('C:/Users/Zohar_ysncvfn/PycharmProjects/FinalProject/venv/pcaps/DoHQuery2.pcap')
dohResponse=rdpcap('C:/Users/Zohar_ysncvfn/PycharmProjects/FinalProject/venv/pcaps/DoHResponse.pcap')
inputpcap=rdpcap('C:/Users/Zohar_ysncvfn/PycharmProjects/FinalProject/venv/pcaps/DNSinput.pcap')

outputpcap=list()
firstquery=True

HostSeq=opensession[-1][TCP].seq+len(opensession[-1][TCP].payload)
ServerSeq=opensession[-3][TCP].seq+len(opensession[-3][TCP].payload)
print (ServerSeq)
print(HostSeq)
HostAck=opensession[-1][TCP].ack
ServerAck=opensession[-3][TCP].ack
print (ServerAck)
print(HostAck)
HostIP = None
ServerIP = None
HandshakeDuration=0



def UpdateSeq(packet, oldseq,oldack,IPsrc, IPdest ):
    newpacket=packet.copy()
    newpacket[TCP].seq= oldseq
    newpacket[TCP].ack=oldack
    newpacket[IP].src=IPsrc
    newpacket[IP].dst=IPdest
    return (newpacket,oldseq+len(newpacket[TCP].payload))

for packet in inputpcap:
    first_packet_time=packet.time
    toreplace = True

    if DNSRR in packet:
        newpacket, ServerSeq=UpdateSeq(dohResponse[0],ServerSeq,ServerAck,packet[IP].src,packet[IP].dst )
        newpacket.time=first_packet_time+HandshakeDuration
        HostAck=ServerSeq
        outputpcap.append(newpacket)
        toreplace=False

    if DNSQR in packet and firstquery and toreplace:
        HandshakeDuration=opensession[-1].time-opensession[0].time
        HostIP = packet[IP].src
        ServerIP = packet[IP].dst
        for i , pkt in enumerate(opensession):
            pktcopy=pkt.copy()
            pktcopy.time=first_packet_time+opensession[i].time-opensession[0].time
            outputpcap.append(pktcopy)
        firstquery=False
    if DNSQR in packet and toreplace:
        for i , pkt in enumerate(dohQuery):
            newpacket, HostSeq=UpdateSeq(pkt, HostSeq,HostAck,packet[IP].src,packet[IP].dst)
            newpacket.time=first_packet_time+pkt.time-dohQuery[0].time+HandshakeDuration
            outputpcap.append(newpacket)
        ServerAck=HostSeq
        toreplace=False


    if toreplace:
        packetcopy=packet.copy()
        packetcopy.time+=HandshakeDuration
        outputpcap.append(packetcopy)

# close session (DoH)
new_close_session = []
new_pkt, HostSeq = UpdateSeq(closesession[0], HostSeq,  HostAck, HostIP, ServerIP )
new_close_session.append(new_pkt)
new_pkt, ServerSeq = UpdateSeq(closesession[1], ServerSeq,  ServerAck, ServerIP, HostIP )
new_close_session.append(new_pkt)
new_pkt, HostSeq = UpdateSeq(closesession[2], HostSeq,  HostAck, HostIP, ServerIP )
new_close_session.append(new_pkt)
for i, packet in enumerate(new_close_session):
    pktcopy=packet.copy()
    pktcopy.time = inputpcap[-1].time + closesession[i].time - closesession[0].time+HandshakeDuration
    outputpcap.append(pktcopy)

# Write all changes to new pcap file
wrpcap('out.pcap',outputpcap)



print("done")
