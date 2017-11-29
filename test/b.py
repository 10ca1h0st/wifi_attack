#!/usr/bin/python3
#-*-coding:utf-8-*-

import sys

b='out b'

def B():
    global b
    b = b
    print(len(sys.argv))
    print(b)
    b = 'inner b'
    tan(b)

def tan(c):
    print('tan ',c)


if __name__ == '__main__':
    b='main b'
    B()
    print(b)