#!/bin/bash

dir_full=`pwd`
dir=`basename $dir_full`
commit=$1
passwd=$2
if [ $# -lt 2 ];then
    echo "Usage:$0 commit passwd "
    exit
fi

git add .
git commit -m"$commit"

/usr/bin/expect << EOF
set timeout -1
spawn git push https://github.com/wujiaming123/${dir}.git master
expect "'https://github.com':"
send "wujiaming123\n"
expect "'https://wujiaming123@github.com':"
send "${passwd}\n"
expect eof
EOF
