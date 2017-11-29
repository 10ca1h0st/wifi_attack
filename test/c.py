#!/usr/bin/python
#-*-coding:utf-8-*-

cc='global cc'

dd = {}

ll=[]

class test:
    def __init__(self):
        print(cc)
    def tt(self,ll=[1]):
        ll.append('after')
        print(ll)
    def ss(slef,ll=''):
        ll += '4444'
        print(ll)
    def jiebao(self,a='a',*b):
        print(a)
        print(b)

def aaa():
    ll=[1,2,3]
    dd['a']='a'
    c= cc
    print(c)
    c='inner c'
    print(c)

if __name__ == '__main__':
    test = test()
    test.tt([1,2,3])
    test.tt()
    test.tt()

    test.ss()
    test.ss()

    test.jiebao(*[1,2,3])

    aaa()
    print(cc)
    print(dd)
    print(ll)