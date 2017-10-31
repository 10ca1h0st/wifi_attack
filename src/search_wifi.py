#!/usr/bin/python2
#-*-coding:utf-8-*-

'''
这个程序需要在root权限下运行
'''

import os
import sys

from scapy.all import *
import binascii  #隐藏热点的SSID值为b'\x00\x00\x00\x00\x00\x00\x00'，需要使用这个库进行转换

#默认监听端口
iface = 'mon0'
addr2_list = set()
ssids = {}
hide_ssids = set()

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
    pkts = sniff(iface=iface,count=10,lfilter=lambda x : x.type==0 and x.subtype==8 \
                and x.info != b'' and x.addr2 not in addr2_list,prn=lambda x : addr2_list.add(x.addr2))
    wrpcap('../res/data_from_py.pcap',pkts)
    for pkt in pkts:
        if pkt.info == b'':
            pass
        elif binascii.hexlify(pkt.info)[:2] != b'00':
            ssids[pkt.info] = pkt.addr2
        else:
            hide_ssids.add(pkt.addr2)



if __name__ == '__main__':
    if len(sys.argv) >= 2:
        iface = sys.argv[1]
    isExist(iface)
    startMonitor(iface)
    searchSSID(iface)

    print('---未隐藏热点---')
    for i,j in ssids.items():
        print('找到热点:'+i+' BSSID为:'+j)

    print('---隐藏热点---')
    for i in hide_ssids:
        print('找到隐藏热点 BSSID为:'+i)