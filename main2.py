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

for packet in inputpcap:
    toreplace = True

    if DNSRR in packet:
        packet=dohResponse[0]
        outputpcap.append(packet)
        toreplace=False

    if DNSQR in packet and firstquery and toreplace:
        for pkt in opensession:
            outputpcap.append(pkt)
        firstquery=False
    if DNSQR in packet and toreplace:
        packet=dohQuery[0]
        outputpcap.append(packet)
        outputpcap.append(dohQuery[1])
        toreplace=False



    if toreplace:
        outputpcap.append(packet)




wrpcap('out.pcap',outputpcap)

print("done")
