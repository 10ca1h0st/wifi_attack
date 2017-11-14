#!/usr/bin/python
#-*-coding:utf-8-*-

cc='global cc'

class test:
    def __init__(self):
        print(cc)
    def tt(self,ll=[1]):
        ll.append('after')
        print(ll)
    def ss(slef,ll=''):
        ll += '4444'
        print(ll)



if __name__ == '__main__':
    test = test()
    test.tt([1,2,3])
    test.tt()
    test.tt()

    test.ss()
    test.ss()