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

def UpdateSeq(packet, oldseq,oldack,IPsrc, IPdest ):
    newpacket=packet.copy()
    newpacket[TCP].seq= oldseq
    newpacket[TCP].ack=oldack
    newpacket[IP].src=IPsrc
    newpacket[IP].dst=IPdest
    return (newpacket,oldseq+len(newpacket[TCP].payload))

for packet in inputpcap:
    toreplace = True

    if DNSRR in packet:
        newpacket, ServerSeq=UpdateSeq(dohResponse[0],ServerSeq,ServerAck,packet[IP].src,packet[IP].dst )
        HostAck=ServerSeq
        outputpcap.append(newpacket)
        toreplace=False

    if DNSQR in packet and firstquery and toreplace:
        for pkt in opensession:
            outputpcap.append(pkt)
        firstquery=False
    if DNSQR in packet and toreplace:
        newpacket, HostSeq=UpdateSeq(dohQuery[0], HostSeq,HostAck,packet[IP].src,packet[IP].dst)
        outputpcap.append(newpacket)
        newpacket, HostSeq = UpdateSeq(dohQuery[1], HostSeq,HostAck,packet[IP].src,packet[IP].dst)
        outputpcap.append(newpacket)
        ServerAck=HostSeq
        toreplace=False



    if toreplace:
        outputpcap.append(packet)




wrpcap('out.pcap',outputpcap)



print("done")
