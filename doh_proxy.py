from scapy.all import *
from doh_session import DoHSession2
from tcp_session import TCPSession
from doh_user import DoHUser
'''
This class gets the doh proxy pcap, splits it into partials.
Handshake of TCP & TLS, termination of TLS & TCP,
segments of each doh query and it following packets (acks, doh response and etc.)
'''
class DoHProxy:
    def __init__(self, doh_pcap): #orginal
        self.pcap = doh_pcap
        self.queries = list()
        self.responses = list()     #[ key= packet(doh query), value= packet(doh response) ]
        self.handshake=list()
        self.termination=list()
        self.packet_101= list()  #for the problematic packet after first query&response
        self.split_into_lists(self.pcap)

    #Func to cut handshake, termination and segments due to the decided delay.
    def split_into_lists(self,doh_pcap):
        termination_index= self.check_termination_length(doh_pcap[-5]) #cutting termination packets.
        self.termination=doh_pcap[termination_index:]
        handshake_index, self.handshake =self.get_the_handshake(doh_pcap) # cutting handshake packets.
        doh_pcap = doh_pcap[handshake_index:termination_index] 
        list_of_segments, segment = list(),list() # cutting into segments of 1 seconds, due to decided delay
        index=0
        for pkt in doh_pcap:
            time= doh_pcap[index].time
            if pkt.time-time < 1:
                segment.append(pkt)
            else:
                index=index + len(segment)
                list_of_segments.append(segment.copy())
                segment.clear()
                segment.append(pkt)
        list_of_segments.append(segment.copy())
        self.split_the_segments(list_of_segments)

    #Func to split each segment
    def split_the_segments(self, list_of_segments):
        is_first=True
        query_segment, response_segment = list(), list()
        for segment in list_of_segments:
            if is_first:
                self.take_care_of_first_seg(segment)
                is_first=False
            else:
                for pkt in segment:
                    if pkt[IP].src == '10.0.2.15' and len(pkt)>80:
                        query_segment.append(pkt)
                    else:#if pkt[IP].src == '10.0.2.9':
                        response_segment.append(pkt)
                self.queries.append(query_segment.copy())
                self.responses.append(response_segment.copy())
                query_segment.clear()
                response_segment.clear()


            
                
#Func to take care of first segment which is problematic due to the 101 packet
    def take_care_of_first_seg(self,segment):
        query_segment, response_segment, special_segment = list(), list(), list()
        for index, pkt in enumerate(segment):
                 #for the first segment with 101 pkt
                    if pkt[IP].src == '10.0.2.15' and len(pkt)>101:
                        query_segment.append(pkt)
                    if pkt[IP].src == '10.0.2.15' and len(pkt)<80: #case of ack pkt before 101pkt
                        try:
                            if len(segment[index+1]) == 101:
                                special_segment.extend([pkt, segment[index+1]])
                                if len(segment[index+2]) < 80: # ack pkt after 101 pkt
                                    special_segment.append(segment[index+2])
                        except Exception as e:
                            print("out of index in speical segment")
                    if len(pkt) == 101 and not special_segment: #case of no ack pkt before 101pkt
                        special_segment.append(pkt)
                        try:
                            if len(segment[index+1]) < 80: # ack pkt after 101 pkt
                                special_segment.append(segment[index+1])
                        except:
                            print("out of index in speical segment")

                    if pkt[IP].src == '10.0.2.9' and pkt not in special_segment:
                        response_segment.append(pkt)
        special_segment.append(True)#boolean sign to know if already used or not
        self.queries.append(query_segment)
        self.responses.append(response_segment)
        self.packet_101.append(special_segment)


    def check_termination_length(self,packet):
       return -4 if len(packet)<80 else  -5

    def get_the_handshake(self,doh_pcap):
        time, index=doh_pcap[0].time, 0
        for pkt in doh_pcap:
            if pkt.time-time <2:
                index=index+1
                time=pkt.time
            else:
                break
        return index, doh_pcap[:index]