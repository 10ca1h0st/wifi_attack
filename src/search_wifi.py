#!/usr/bin/python2
#-*-coding:utf-8-*-

'''
这个程序需要在root权限下运行
'''

import os,sys,threading,argparse

from scapy.all import *
import binascii  #隐藏热点的SSID值为b'\x00\x00\x00\x00\x00\x00\x00'，需要使用这个库进行转换

#默认监听端口
iface = ''
#发送Probe Request的机器的物理地址
addr = ''
#探测到信标帧的数量
count_8 = 0
#探测到Probe Response帧的数量
count_5 = 0
#标志ProbeReq帧是否已经发送完
over = False
#发送的Probe Request帧的数量
count_sendp = 0
#addr2_list = set()
ssids = {}
hide_ssids = set()


'''
class Redirect:
    def __init__(self):
        self.content = ''
        self.savedStdout = sys.stdout
        self.hidden = None
    
    def write(self,outStr):
        #self.content += outStr
        pass
    
    def recover(self):
        sys.stdout = self.savedStdout
    def redirect(self):
        self.hidden = open(os.devnull,'w')
        sys.stdout = self.hidden
'''

def handleArgv():
    global iface,addr,count_5,count_8,count_sendp
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--iface',type=str,default='mon0')
    parser.add_argument('-a','--addr',type=str,default='40:e2:30:d2:c4:0f')
    parser.add_argument('-5','--count_5',type=int,default=100)
    parser.add_argument('-8','--count_8',type=int,default=100)
    parser.add_argument('-c','--count_sendp',type=int,default=1000)
    argv = parser.parse_args()
    iface = argv.iface
    addr = argv.addr
    count_5 = argv.count_5
    count_8 = argv.count_8
    count_sendp = argv.count_sendp
    #print(argv)



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

def searchSSID(iface,subtype):
    count = count_8 if subtype == 8 else count_5
    if count == 0:
        return
    pkts = sniff(iface=iface,count=count,lfilter=lambda x : x.type==0 and x.subtype==subtype)
    wrpcap('../res/data_from_py_subtype:{0}.pcap'.format(subtype),pkts)
    for pkt in pkts:
        if pkt.info == '':
            pass
        elif binascii.hexlify(pkt.info)[:2] != '00':
            ssids[pkt.info] = pkt.addr2
        else:
            hide_ssids.add(pkt.addr2)


class ManagementFrame:
    def __init__(self,Rates='\x02\x04\x0b\x16',ESRates='\x0c\x12\x18\x24\x30\x48\x60\x6c'):
        self.Rates = Rates
        self.ESRates = ESRates

    def ProbeReq(self,addr2,addr1='ff:ff:ff:ff:ff:ff',addr3='ff:ff:ff:ff:ff:ff',SSID=''):
        pkt = RadioTap(len=13,present='Rate+b15+b17',notdecoded='\x02\x00\x00\x00\x00')
        pkt /= Dot11(addr1=addr1,addr2=addr2,addr3=addr3)
        pkt /= Dot11ProbeReq()/Dot11Elt(ID='SSID',info=SSID)
        pkt /= Dot11Elt(ID='Rates',info=self.Rates)
        pkt /= Dot11Elt(ID='ESRates',info=self.ESRates)
        #pkt /= Dot11Elt(ID='DSset',info='\x01')
        #pkt /= Dot11Elt(ID=45,info='\x2C\x01\x03\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        #pkt /= Dot11Elt(ID='vendor',info='\x00\x50\xf2\x08\x00\x00\x00')
        return pkt
      
    






if __name__ == '__main__':

    handleArgv()
    print('iface:'+iface+' addr:'+addr)
    print('subtype :8 count :'+str(count_8)+'       subtype :5 count :'+str(count_5))
    isExist(iface)
    startMonitor(iface)
    mgt = ManagementFrame()
    pkt = mgt.ProbeReq(addr)
    #sendp(pkt,count=1000,iface=iface)

    th1 = threading.Thread(target=searchSSID,args=(iface,8))
    th2 = threading.Thread(target=searchSSID,args=(iface,5))
    th1.start()
    th2.start()
    sendp(pkt,count=count_sendp,iface=iface)
    th1.join()
    th2.join()
    print('detect packets count :'+str(count_5)+' type :5 over')
    print('detect packets count :'+str(count_8)+' type :8 over')

    print('---未隐藏热点---')
    for i,j in ssids.items():
        print('找到热点:'+i+' BSSID为:'+j)

    print('---隐藏热点---')
    for i in hide_ssids:
        print('找到隐藏热点 BSSID为:'+i)
