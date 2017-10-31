#!/usr/bin/python2
#-*-coding:utf-8-*-

'''
这个程序需要在root权限下运行
'''

import os
import sys

from scapy.all import *

#默认监听端口
iface = 'mon0'
ssid_set = set()

def isExist(iface):
    info = os.popen("iw dev | grep -E '"+iface+"$'").read()
    if info != '':
        print(iface+':接口存在')
    else:
        sys.exit('sorry,'+iface+'接口不存在')

def startMonitor(iface):
    info = os.popen("iwconfig "+iface+" | grep '"+iface+"' | awk '{print $4}'").read()
    if 'Monitor' in info or 'monitor' in info:
        print(iface+':监听模式已启动')
    else:
        print(iface+':尚未开启监听模式')

def searchSSID(iface):
    pkt = sniff(iface=iface,count=500,lfilter=lambda x:x.type==0 and x.subtype==5,prn=lambda x:ssid_set.add(x.info))



if __name__ == '__main__':
    if len(sys.argv) >= 2:
        iface = sys.argv[1]
    isExist(iface)
    startMonitor(iface)
    searchSSID(iface)
    print(ssid_set)