#!/usr/bin/python2
#-*-coding:utf-8-*-

import requests
import sys
import os

#应用于没有网络时,返回mac地址对应的厂商,返回的字符的类型为unicode
def mac2company_isolation(mac):
    #print(sys.getdefaultencoding())
    info = os.popen('grep -i '+mac.replace(':','').replace('-','')[:5]+' ../reference/oui.txt').read()
    if not len(info):
        return 'Unknown device'.decode('utf-8')
    #print(type(' '.join(info.split()[3:]))) #<type 'str'>
    return ' '.join(info.split()[3:]).decode('utf-8')

#返回mac地址对应的厂商,返回的字符的类型为unicode
def mac2company(mac):
    mac = mac.replace(':','').replace('-','')
    try:
        r = requests.get('https://www.baidu.com/')
    except requests.exceptions.ConnectionError:
        return mac2company_isolation(mac)
    #print(mac)
    url = 'https://services13.ieee.org/RST/standards-ra-web/rest/assignments/'
    payload = {'registry':'MAC','sortby':'organization','sortorder':'asc','size':'1'}
    payload['text'] = mac
    r = requests.get(url,params=payload)
    #print(r.url)
    result = r.json()
    #print(type(result))
    #print(result)
    #print('')
    #print(type(result['data']))
    dict_json = {}
    parseJson(result,dict_json)
    #print(dict_json)
    try:
        return dict_json['organizationName']
        #return 'Known device'
    except KeyError as e:
        return 'Unknown device'.decode('utf-8')




'''
目前可以解析:
'a':{},'a':[{}]
'''
def parseJson(dict_json,new_dict_json):
    for k,v in dict_json.items():
        if isinstance(v,dict):
            new_dict_json.update(parseJson(v,new_dict_json))
            continue
        elif isinstance(v,list):
            for l in v:
                new_dict_json.update(parseJson(l,new_dict_json))
            continue
        new_dict_json[k] = v
    return new_dict_json
        

if __name__ == '__main__':
    mac2company_isolation('f0:b4:29:57:37:d7')