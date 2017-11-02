#!/usr/bin/python
#-*-coding:utf-8-*-

import sys

import argparse

def test(args):
    parser = argparse.ArgumentParser(description='it is a test')
    parser.add_argument('--f00','--f0',action='store_const',const=44)
    parser.add_argument('--f1',action='store_true')
    parser.add_argument('--f2',action='store_false')
    parser.add_argument('-c','--f3',action='count')
    parser.add_argument('--f4',type=str,default='mon0')
    p = parser.parse_args(args)
    print(p)


if __name__ == '__main__':
    test(sys.argv[1:])