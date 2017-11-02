#!/usr/bin/python3
#-*-coding:utf-8-*-

import os,sys

#import b
from b import B

defaultStdout = sys.stdout

def redirect():
    sys.stdout = os.devnull
    print('i am redirected')
    sys.stdout = defaultStdout





if __name__ == '__main__':
    #b.B()
    B()
    #redirect()
