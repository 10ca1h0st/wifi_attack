#!/bin/bash

dir_full=`pwd`
dir=`basename $dir_full`
commit=$1
passwd=$2
if [ $# -lt 2 ];then
    echo "Usage:$0 commit passwd [wait_time]"
    exit
fi
if [ -n "$3" ];then
    time=$3
else
    time=4
    echo "如果此脚本提示 Everything up-to-date，那可能是给git commit的时间不够，请尝试添加第三个参数。"
fi

/usr/bin/expect << EOF
set timeout 20
spawn git add .
sleep 0.5
spawn git commit -m"$commit"
sleep $time
spawn git push https://github.com/wujiaming123/${dir}.git master
expect "'https://github.com':"
send "wujiaming123\n"
expect "'https://wujiaming123@github.com':"
send "${passwd}\n"
expect eof
EOF
