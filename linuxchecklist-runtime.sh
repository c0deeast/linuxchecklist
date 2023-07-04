#!/bin/bash
echo "Version:0.1"
echo "Date:2023-06-06"
echo "安全技术团队修改"

dos2unix linuxchecklist-runtime.sh
date=$(date +%Y%m%d)

if [$? eq 0]; then
	ipadd=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')
else
	ipadd=$(ip addr | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}' | awk -F / '{print $1}')
fi


if [ $(whoami) != "root" ];then
	echo "安全检查必须使用root账号,否则某些项无法检查"
	exit 1
fi

checkresult="${ipadd}_${date}.txt"
saveresult="tee -a $checkresult"
echo -------------------------初始检查清单-------------------------
echo -------------------------查看用户信息-------------------------
while read line
do
    echo "account=passwd=$line"
done < /etc/passwd | $saveresult


echo -------------------------非系统用户-------------------------
if [ -f /etc/login.defs ];then
	uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
	#(echo "系统最小UID为"$uid) | $saveresult
	nosystemuser=`awk -F: '{if ($3>='$uid' && $3!=65534) {print $1}}' /etc/passwd`
	if [ -n "$nosystemuser" ];then
		for line in $nosystemuser
		do
			echo "account=logindefs=$line" | $saveresult
		done
	else
		echo "account=logindefs=null" | $saveresult
	fi
fi

echo -------------------------shadow文件-------------------------
while read line
do
    echo "account=shadow=$line"
done < /etc/shadow | $saveresult


echo -------------------------用户组信息-------------------------
groupinfo=$(more /etc/group | grep -v "^#")
if [ -n "$groupinfo" ];then
	for line in $groupinfo
	do
		echo "account=group=$line" | $saveresult
	done
else
	echo "account=group=null"  | $saveresult
fi

echo -------------------------sudo权限的用户-------------------------
sudoers=$(more /etc/sudoers | grep -v "#|$" | grep "ALL=(ALL)")
if [ -n "$sudoers" ];then
	while read line
do
    echo "account=sudoers=$line"
done < /etc/shadow | $saveresult
else 
	echo "account=sudoers=null" | $saveresult
fi



echo -------------------------网络连接-------------------------
echo -------------------------路由表-------------------------
route -n | grep -v "^D" | grep -v "^K" | while IFS= read -r line; do
    echo "network=route=$line" | $saveresult
done

echo -------------------------正在分析是否开启转发功能-------------------------
#数值分析
#1:开启路由转发
#0:未开启路由转发
ip_forward=`more /proc/sys/net/ipv4/ip_forward`
if [ -n "$ip_forward" ];then
	echo "network=ip_forward=$ip_forward" | $saveresult
else
	echo "network=ip_forward=null" | $saveresult
fi

echo -------------------------ARP表项-------------------------
arp -a -n | grep -v "^A" | grep -v "^D" | grep -v "^K" | while IFS= read -r line; do
    echo "network=arp=$line" | $saveresult
done

echo -------------------------查看TCP开放端口-------------------------
#TCP或UDP端口绑定在0.0.0.0、127.0.0.1、192.168.1.1这种IP上只表示这些端口开放
#只有绑定在0.0.0.0上局域网才可以访问
echo -------------------------正在检查TCP开放端口-------------------------
netstat -anlpt | grep "^tcp" | while IFS= read -r line; do
    echo "network=tcpnetwork=$line" | $saveresult
done


echo -------------------------查看UDP开放端口-------------------------
echo -------------------------正在检查UDP开放端口-------------------------
netstat -anlpu | grep "^udp" | while IFS= read -r line; do
    echo "network=udpnetwork=$line" | $saveresult
done


echo -------------------------进程分析-------------------------
echo -------------------------正在检查进程-------------------------
ps -aux | grep -v "^U" | while IFS= read -r line; do
    echo "process=ps=$line" | $saveresult
done

echo -------------------------正在检查守护进程-------------------------
if [ -e /etc/xinetd.d/rsync ];then
	rsyncinfo=$(more /etc/xinetd.d/rsync | grep -v "^#")
	for line in $rsyncinfo
	do
		echo "process=xinetdprocess=$line" | $saveresult
	done
else
	echo "process=xinetdprocess=null" | $saveresult
fi


echo -------------------------启动项-------------------------
echo -------------------------正在检查系统自启动项-------------------------
systemchkconfig=$(systemctl list-unit-files | grep enabled | awk '{print $1}')
if [ -n "$systemchkconfig" ];then
	for line in $systemchkconfig
	do
		echo "bootitems=systemctl=$line" | $saveresult
	done
else
	echo "bootitems=systemctl=null" | $saveresult
fi

echo -------------------------查看服务-------------------------
more /etc/services | grep -v "#" |grep -v "^$" | while IFS= read -r line; do
    echo "services=services=$line" | $saveresult
done

echo -------------------------查看定时任务-------------------------
more -A /var/spool/cron/* | while IFS= read -r line; do
    echo "cronjob=crontab=$line" | $saveresult
done

grep -rn "*" /etc/cron* | while IFS= read -r line; do
    echo "cronjob=etccron=$line" | $saveresult
done

echo -------------------------关键文件检查-------------------------
echo -------------------------DNS文件检查-------------------------
resolv=$(more /etc/resolv.conf | grep ^nameserver | awk '{print $NF}') 
if [ -n "$resolv" ];then
	for line in $resolv
	do
		echo "file=dns=$line" | $saveresult
	done
else
	echo "file=dns=null" | $saveresult
fi

echo -------------------------hosts文件检查-------------------------
more /etc/hosts | while IFS= read -r line; do
    echo "file=hosts=$line" | $saveresult
done

echo -------------------------正在检查公钥文件-------------------------
#只检查是否存在公钥文件
if [  -e /root/.ssh/*.pub ];then
	echo "file=publickey=1" | $saveresult
else
	echo "file=publickey=0" | $saveresult
fi

echo -------------------------正在检查私钥文件-------------------------
#只检查是否存在私钥文件
if [ -e /root/.ssh/id_rsa ];then
	echo "file=privatekey=1" | $saveresult
else
	echo "file=privatekey=0" | $saveresult
fi


echo -------------------------正在检查运行服务-------------------------
services=$(systemctl | grep -E "\.service.*running" | awk -F. '{print $1}')
if [ -n "$services" ];then
	for line in $services
	do
		echo "service=running=$line" | $saveresult
	done
else
	echo "service=running=null" | $saveresult
fi


echo -------------------------恶意文件-------------------------
#查看黑客常使用的目录文件，做对比

ls -lah /tmp | while IFS= read -r line; do
    echo "file=tmpfile=$line" | $saveresult
done


echo -------------------------文件完整性-------------------------


echo "file=bin=`md5sum /usr/bin/awk`" | $saveresult
echo "file=bin=`md5sum /usr/bin/basename`" | $saveresult
echo "file=bin=`md5sum /usr/bin/bash`" | $saveresult
echo "file=bin=`md5sum /usr/bin/cat`" | $saveresult
echo "file=bin=`md5sum /usr/bin/chattr`" | $saveresult
echo "file=bin=`md5sum /usr/bin/chmod`" | $saveresult
echo "file=bin=`md5sum /usr/bin/chown`" | $saveresult
echo "file=bin=`md5sum /usr/bin/cp`" | $saveresult
echo "file=bin=`md5sum /usr/bin/csh`" | $saveresult
echo "file=bin=`md5sum /usr/bin/curl`" | $saveresult
echo "file=bin=`md5sum /usr/bin/cut`" | $saveresult
echo "file=bin=`md5sum /usr/bin/date`" | $saveresult
echo "file=bin=`md5sum /usr/bin/df`" | $saveresult
echo "file=bin=`md5sum /usr/bin/diff`" | $saveresult
echo "file=bin=`md5sum /usr/bin/dirname`" | $saveresult
echo "file=bin=`md5sum /usr/bin/dmesg`" | $saveresult
echo "file=bin=`md5sum /usr/bin/du`" | $saveresult
echo "file=bin=`md5sum /usr/bin/echo`" | $saveresult
echo "file=bin=`md5sum /usr/bin/ed`" | $saveresult
echo "file=bin=`md5sum /usr/bin/egrep`" | $saveresult
echo "file=bin=`md5sum /usr/bin/env`" | $saveresult
echo "file=bin=`md5sum /usr/bin/fgrep`" | $saveresult
echo "file=bin=`md5sum /usr/bin/file`" | $saveresult
echo "file=bin=`md5sum /usr/bin/find`" | $saveresult
echo "file=bin=`md5sum /usr/bin/gawk`" | $saveresult
echo "file=bin=`md5sum /usr/bin/GET`" | $saveresult
echo "file=bin=`md5sum /usr/bin/grep`" | $saveresult
echo "file=bin=`md5sum /usr/bin/groups`" | $saveresult
echo "file=bin=`md5sum /usr/bin/head`" | $saveresult
echo "file=bin=`md5sum /usr/bin/id`" | $saveresult
echo "file=bin=`md5sum /usr/bin/ipcs`" | $saveresult
echo "file=bin=`md5sum /usr/bin/kill`" | $saveresult
echo "file=bin=`md5sum /usr/bin/killall`" | $saveresult
echo "file=bin=`md5sum /usr/bin/kmod`" | $saveresult
echo "file=bin=`md5sum /usr/bin/last`" | $saveresult
echo "file=bin=`md5sum /usr/bin/lastlog`" | $saveresult
echo "file=bin=`md5sum /usr/bin/ldd`" | $saveresult
echo "file=bin=`md5sum /usr/bin/less`" | $saveresult
echo "file=bin=`md5sum /usr/bin/locate`" | $saveresult
echo "file=bin=`md5sum /usr/bin/logger`" | $saveresult
echo "file=bin=`md5sum /usr/bin/login`" | $saveresult
echo "file=bin=`md5sum /usr/bin/ls`" | $saveresult
echo "file=bin=`md5sum /usr/bin/lsattr`" | $saveresult
echo "file=bin=`md5sum /usr/bin/lynx`" | $saveresult
echo "file=bin=`md5sum /usr/bin/mail`" | $saveresult
echo "file=bin=`md5sum /usr/bin/mailx`" | $saveresult
echo "file=bin=`md5sum /usr/bin/echo`" | $saveresult
echo "file=bin=`md5sum /usr/bin/mktemp`" | $saveresult
echo "file=bin=`md5sum /usr/bin/more`" | $saveresult
echo "file=bin=`md5sum /usr/bin/mount`" | $saveresult
echo "file=bin=`md5sum /usr/bin/mv`" | $saveresult
echo "file=bin=`md5sum /usr/bin/netstat`" | $saveresult
echo "file=bin=`md5sum /usr/bin/newgrp`" | $saveresult
echo "file=bin=`md5sum /usr/bin/numfmt`" | $saveresult
echo "file=bin=`md5sum /usr/bin/passwd`" | $saveresult
echo "file=bin=`md5sum /usr/bin/perl`" | $saveresult
echo "file=bin=`md5sum /usr/bin/pgrep`" | $saveresult
echo "file=bin=`md5sum /usr/bin/ping`" | $saveresult
echo "file=bin=`md5sum /usr/bin/pkill`" | $saveresult
echo "file=bin=`md5sum /usr/bin/ps`" | $saveresult
echo "file=bin=`md5sum /usr/bin/pstree`" | $saveresult
echo "file=bin=`md5sum /usr/bin/pwd`" | $saveresult
echo "file=bin=`md5sum /usr/bin/readlink`" | $saveresult
echo "file=bin=`md5sum /usr/bin/rpm`" | $saveresult
echo "file=bin=`md5sum /usr/bin/runcon`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sed`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sh`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sha1sum`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sha224sum`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sha256sum`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sha384sum`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sha512sum`" | $saveresult
echo "file=bin=`md5sum /usr/bin/size`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sort`" | $saveresult
echo "file=bin=`md5sum /usr/bin/ssh`" | $saveresult
echo "file=bin=`md5sum /usr/bin/stat`" | $saveresult
echo "file=bin=`md5sum /usr/bin/strace`" | $saveresult
echo "file=bin=`md5sum /usr/bin/strings`" | $saveresult
echo "file=bin=`md5sum /usr/bin/su`" | $saveresult
echo "file=bin=`md5sum /usr/bin/sudo`" | $saveresult
echo "file=bin=`md5sum /usr/bin/systemctl`" | $saveresult
echo "file=bin=`md5sum /usr/bin/tail`" | $saveresult
echo "file=bin=`md5sum /usr/bin/tcsh`" | $saveresult
echo "file=bin=`md5sum /usr/bin/telnet`" | $saveresult
echo "file=bin=`md5sum /usr/bin/test`" | $saveresult
echo "file=bin=`md5sum /usr/bin/top`" | $saveresult
echo "file=bin=`md5sum /usr/bin/touch`" | $saveresult
echo "file=bin=`md5sum /usr/bin/tr`" | $saveresult
echo "file=bin=`md5sum /usr/bin/uname`" | $saveresult
echo "file=bin=`md5sum /usr/bin/uniq`" | $saveresult
echo "file=bin=`md5sum /usr/bin/users`" | $saveresult
echo "file=bin=`md5sum /usr/bin/vmstat`" | $saveresult
echo "file=bin=`md5sum /usr/bin/w`" | $saveresult
echo "file=bin=`md5sum /usr/bin/watch`" | $saveresult
echo "file=bin=`md5sum /usr/bin/wc`" | $saveresult
echo "file=bin=`md5sum /usr/bin/wget`" | $saveresult
echo "file=bin=`md5sum /usr/bin/whatis`" | $saveresult
echo "file=bin=`md5sum /usr/bin/whereis`" | $saveresult
echo "file=bin=`md5sum /usr/bin/which`" | $saveresult
echo "file=bin=`md5sum /usr/bin/who`" | $saveresult
echo "file=bin=`md5sum /usr/bin/whoami`" | $saveresult
echo "file=bin=`md5sum /usr/lib/systemd/s`" | $saveresult
echo "file=bin=`md5sum /usr/local/bin/rkh`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/adduser`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/chkconfi`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/chroot`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/depmod`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/fsck`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/fuser`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/groupadd`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/groupdel`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/groupmod`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/grpck`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/ifconfig`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/ifdown`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/ifup`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/init`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/insmod`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/ip`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/lsmod`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/lsof`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/modinfo`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/modprobe`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/nologin`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/pwck`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/rmmod`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/route`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/rsyslogd`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/runlevel`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/sestatus`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/sshd`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/sulogin`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/sysctl`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/tcpd`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/useradd`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/userdel`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/usermod`" | $saveresult
echo "file=bin=`md5sum /usr/sbin/vipw`" | $saveresult


echo -------------------------日志------------------------------
loginsuccess=$(more /var/log/secure)
if [ -n "$loginsuccess" ];then
	more /var/log/secure | while IFS= read -r line; do
    	echo "log=secure=$line" | $saveresult
	done
else
	echo "log=secure=null" | $saveresult
fi


echo -------------------------message日志-------------------------
zmodem=$(more /var/log/message)
if [ -n "$zmodem" ];then
	more /var/log/message | while IFS= read -r line; do
    	echo "log=message=$line" | $saveresult
	done
else
	echo "log=message=null" | $saveresult
fi

# echo -------------------------dmesg日志分析-------------------------
# echo "-------------------------正在查看内核自检日志-------------------------"
# dmesg=$(dmesg)
# if [ $? -eq 0 ];then
# 	dmesg | while IFS= read -r line; do
#     	echo "log=dmesg=$line" | $saveresult
# 	done
# else
# 	echo "log=dmesg=null" | $saveresult
# fi

echo -------------------------btmp日志分析-------------------------
lastb=$(lastb | grep -v "^$" | grep -v "^btmp")
if [ -n "$lastb" ];then
	lastb | grep -v "^$" | grep -v "^btmp" | while IFS= read -r line; do
    	echo "log=btmp=$line" | $saveresult
	done
else
	echo "log=btmp=null" | $saveresult
fi

echo -------------------------lastlog日志分析-------------------------
lastlog=$(lastlog | grep -v "^U")
if [ -n "$lastlog" ];then
	lastlog | grep -v "^U"| while IFS= read -r line; do
    	echo "log=lastlog=$line" | $saveresult
	done
else
	echo "log=lastlog=null" | $saveresult
fi

echo -------------------------wtmp日志分析-------------------------
lasts=$(last | grep -v "^$" | grep -v "^wtmp")
if [ -n "$lasts" ];then
	last | grep -v "^$" | grep -v "^wtmp" | while IFS= read -r line; do
    	echo "log=wtmp=$line" | $saveresult
	done
else
	echo "log=wtmp=null" | $saveresult
fi

# echo -------------------------内核检查-------------------------
# echo "-------------------------正在检查内核信息-------------------------"
# lsmod=$(lsmod | grep -v "^M")
# if [ -n "$lsmod" ];then
# 	lsmod | grep -v "^M" | while IFS= read -r line; do
#     	echo "log=kernel=$line" | $saveresult
# 	done
# else
# 	echo "log=kernel=null" | $saveresult
# fi



echo -------------------------正在检查环境变量-------------------------
env=$(env)
if [ -n "$env" ];then
	env | while IFS= read -r line; do
    	echo "log=env=$line" | $saveresult
	done
else
	echo "log=env=null" | $saveresult
fi