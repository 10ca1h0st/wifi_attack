#!/usr/bin/python2
#-*-coding:utf-8-*-

import sys

def change():
    reload(sys)
    sys.setdefaultencoding('utf-8')

print sys.getdefaultencoding()
#change()
print sys.getdefaultencoding()