import logging

from argparse import ArgumentParser


def parse_options():
    parser = ArgumentParser()
    
    parser.add_argument("-i", "--interface", dest="interface", action="store",
                        type=str, required=True,
                        help="interface to sniff and inject packets (must have monitor mode enabled)")
    
    parser.add_argument("-b", "--bssid", dest="bssid", action="store",
                        type=str, required=True,
                        help="MAC address of the targeted access point")
    
    parser.add_argument("-c", "--client", dest="client", action="store",
                        default='', type=str,
                        help = "MAC address of a single client to direct the attack (if none, a disassociation attack against all clients will be attempted)")
    
    parser.add_argument("-s", "--sniff", action="store_true", dest="should_sniff",
                        help="whether to sniff packets in order to gather client addresses")        

    parser.add_argument("-t", "--timeout", action="store", dest="timeout",
                        default=60, type=int,
                        help="number of seconds to sniff packets (defaults to 60; only meaningful if -s is used)")
    
    return parser.parse_args()

def main():
    options = parse_options()
    # To suppress Scapy warning messages (import has to be done after the
    # following line).
    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)    
    from attack.builder import WiFiDeauthAttackBuilder
    attack = WiFiDeauthAttackBuilder.build_from(options)
    attack.run()


if __name__ == '__main__':
    main()