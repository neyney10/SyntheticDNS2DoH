from scapy.all import *

class DeltaCalculator:
    def __init__(self, proxy_pcap, original_pcap):
        self.proxy          = proxy_pcap
        self.original       = original_pcap
        self.proxy_delta    = calculate_delta(self.proxy)
        self.original_delta = calculate_delta(self.original)


    def calculate_delta(self, pcap_file):




    def filter_dns