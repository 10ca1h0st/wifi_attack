#!/usr/bin/python3
#-*-coding:utf-8-*-

import sys

def a(l):
    l.append('last')
def b(n):
    n=123
class C:
    gg='global var'
    print('out print')
    def __init__(self):
        print(self.gg)
        #print(gg) #error


if __name__ == '__main__':
    print(sys.getdefaultencoding())
    l = [1,2,3]
    a(l)
    print(l)
    n=798
    b(n)
    print(n)
    dd={'1':1,'2':2}
    dd_new={'3':3,'1':'1_new'}
    dd.update(dd_new)
    print(dd)
    ss=set([1,2,3])
    ss_new=set([4,5,6])
    ss.update(ss_new)
    print(ss)
    c = C()