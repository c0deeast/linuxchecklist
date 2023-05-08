#!/bin/bash
startTime_s=`date +%s`
echo "Version:0.1"
echo "Date:2023-04-17"
echo "安全技术团队修改"

cat <<EOF
*********************************************
Linux主机安全检查:
	1.首先采集原始信息保存到/tmp/liuxcheck_${ipadd}_${date}/check_file/文件夹下
	2.将系统日志、应用日志打包并保存到/tmp/linuxcheck_${ipadd}_${date}/log/目录下
	3.在检查过程中若发现存在问题则直接输出到/tmp/linuxcheck_${ipadd}_${date}/danger_file.txt文件中
	4.有些未检查可能存在问题的需要人工分析原始文件
	5.脚本编写环境ubuntu
	6.使用过程中若在windows下修改再同步到Linux下，请使用dos2unix工具进行格式转换,不然可能会报错
	7.在使用过程中必须使用root账号,不然可能导致某些项无法分析

如何使用:
	1.本脚本可以单独运行,单独运行中只需要将本脚本上传到相应的服务器中,然后sh linuxcheck.sh即可
	2.另外本脚本可以作为多台服务器全面检查的安全检查模板,本脚本不需要手工运行,只需要将相应服务器的IP、账号、密码写到hosts.txt文件中，然后sh login.sh即可

功能设计:
	1.主要功能用来采集信息
	2.主要功能将原始数据进行分析,并找出存在可疑或危险项
	3.增加基线检查的功能
	4.对收集过来的信息,如网络连接的IP、定时任务的URL、自启动文件、关键文件的MD5通过第三方的威胁情报接口进行查询并返回相应的结果
	5.可以进行相关危险项或可疑项的自动处理

*********************************************
EOF

dos2unix linuxchecklist.sh
date=$(date +%Y%m%d)

ifconfig -a
if [$? eq 0]; then
	ipadd=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')
else
	ipadd=$(ip a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')
fi

#check_file="/tmp/linuxcheck_${ipadd}_${date}/check_file/"
#danger_file="/tmp/linuxcheck_${ipadd}_${date}/danger_file.txt"
#log_file="/tmp/linuxcheck_${ipadd}_${date}/log/"
#rm -rf $check_file
#rm -rf $danger_file
#rm -rf log_file
#mkdir /tmp/linuxcheck_${ipadd}_${date}/
#echo "检查发现危险项,请注意:" > ${danger_file}
#mkdir $check_file
#echo "" >> $danger_file
#mkdir $log_file
#cd $check_file

if [ $(whoami) != "root" ];then
	echo "安全检查必须使用root账号,否则某些项无法检查"
	exit 1
fi


saveresult="tee -a checkresult.csv"
point="tee -a point.txt"
md5file="sysfile_md5.txt"
echo "检查大项	检查子项	检查情况	符合性" | $saveresult
echo "-------------------------初始检查清单-------------------------"
echo "-------------------------正在检查root用户history-------------------------"
history=$(more /root/.bash_history)
if [ -n "$history" ];then
	(echo "历史操作收集	root用户history	请查看point.txt	自行判断") | $saveresult
	echo "root用户history如下：" | $point
	echo "$history" | $point
else
	echo "历史操作收集	root用户history	无记录	自行判断" | $saveresult
fi

echo "-------------------------正在检查其他用户history-------------------------"-------------------------
# 获取所有使用/bin/bash作为默认shell的用户列表，排除root用户
USERS=$(getent passwd | awk -F: '$7 == "/bin/bash" && $1 != "root" {print $1}')

# 遍历每个用户并输出其历史记录
for USER in $USERS
do
  echo "History for $USER:"
  echo "-------------------------"
  history=$(more /home/$USER/.bash_history)
  if [ -n "$history" ];then
	(echo "历史操作收集	$USER 用户history	请查看point.txt	自行判断") | $saveresult
	echo "$USER 用户history如下：" | $point
	echo "$history" | $point
  else
	echo "历史操作收集	$USER 用户history	无记录	自行判断" | $saveresult
  fi
done

echo "-------------------------正在检查账号和特权用户-------------------------"
echo "-------------------------正在检查正在登录的用户-------------------------"
(echo "账户体系模块检查	检查正在登陆的用户	`who`	自行判断" ) | $saveresult

passwdcmd=$(more /etc/passwd)
echo -------------------------查看用户信息-------------------------
echo "-------------------------正在查看用户信息-------------------------"
echo "账户体系模块检查	检查用户信息	请查看point.txt	自行判断" | $saveresult
echo "passwd如下：" | $point
echo "$passwdcmd" | $point

echo -------------------------超级用户-------------------------
#UID=0的为超级用户,系统默认root的UID为0
echo "-------------------------正在检查是否存在超级用户-------------------------"
Superuser=`more /etc/passwd | egrep -v '^root|^#|^(\+:\*)?:0:0:::' | awk -F: '{if($3==0) print $1}'`
if [ -n "$Superuser" ];then
	echo "账户体系模块检查	检查超级用户	$Superuser	存在超级用户" | $saveresult
	for user in $Superuser
	do
		echo $user | $saveresult
		if [ "${user}" = "toor" ];then
			echo "账户体系模块检查	检查超级用户	toor	存在toor用户,若非BSD系统建议删除该账号" | $saveresult
		fi
	done
else
	echo "账户体系模块检查	检查超级用户	未发现超级用户	安全" | $saveresult
fi

echo -------------------------克隆用户-------------------------
#相同的UID为克隆用户
echo "-------------------------正在检查是否存在克隆用户-------------------------"
uid=`awk -F: '{a[$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd`
if [ -n "$uid" ];then
	cloneuser=$(more /etc/passwd | grep $uid | awk -F: '{print $1}')
	echo "账户体系模块检查	检查克隆用户	$cloneuser	可能存在克隆用户" | $saveresult
else
	echo "账户体系模块检查	检查克隆用户	不存在克隆用户	安全" | $saveresult
fi

echo -------------------------可登录用户-------------------------
echo "-------------------------正在检查可登录的用户-------------------------"
loginuser=`cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}'`
if [ -n "$loginuser" ];then
	echo "账户体系模块检查	检查可登录用户	请查看point.txt	自行判断" | $saveresult
	echo "可登录的用户如下：" | $point
	echo "$loginuser" | $point
else
	echo "账户体系模块检查	检查可登录用户	无	自行判断" | $saveresult
fi

echo -------------------------非系统用户-------------------------
echo "-------------------------正在检查非系统本身自带用户"
if [ -f /etc/login.defs ];then
	uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
	#(echo "系统最小UID为"$uid) | $saveresult
	nosystemuser=`awk -F: '{if ($3>='$uid' && $3!=65534) {print $1}}' /etc/passwd`
	if [ -n "$nosystemuser" ];then
		(echo "账户体系模块检查	检查非系统本身自带用户	请查看point.txt	自行判断") | $saveresult
		echo "非系统本身自带用户如下：" | $point
		echo "$nosystemuser" | $point
	else
		echo "账户体系模块检查	检查非系统本身自带用户	无	安全" | $saveresult
	fi
fi

echo -------------------------shadow文件-------------------------
echo "-------------------------正在检查shadow文件-------------------------"
shadowcmd=$(more /etc/shadow)
(echo "账户体系模块检查	检查shadow文件	请查看point.txt	自行判断") | $saveresult
echo "shadow文件如下：" | $point
echo "$shadowcmd" | $point

echo -------------------------空口令用户-------------------------
echo "-------------------------正在检查空口令用户-------------------------"
nopasswd=`awk -F: '($2=="")||($2=="!") {print $1}' /etc/shadow`
if [ -n "$nopasswd" ];then
	(echo "账户体系模块检查	检查空口令用户	请查看point.txt	请人工分析配置和账号") | $saveresult
	echo "空口令用户如下：" | $point
	echo "$nopasswd" | $point
else
	echo "账户体系模块检查	检查空口令用户	无	安全" | $saveresult
fi

echo -------------------------空口令且可登录-------------------------
echo "-------------------------正在检查空口令且可登录的用户-------------------------"
#允许空口令用户登录方法
#1.passwd -d username
#2.echo "PermitEmptyPasswords yes" >>/etc/ssh/sshd_config
#3.service sshd restart
aa=$(cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}')
bb=$(awk -F: '($2=="")||($2=="!") {print $1}' /etc/shadow)
cc=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
flag=""
for a in $aa
do
    for b in $bb
    do
        if [ "$a" = "$b" ] && [ -n "$cc" ];then
			echo "空口令且可登录用户如下:" | $point
			echo "$a" | $point
            flag=1
        fi
    done
done
if [ -n "$flag" ];then
	echo "账户体系模块检查	检查可登录空口令用户	请查看point.txt	请人工分析配置和账号"| $saveresult
else
	echo "账户体系模块检查	检查可登录空口令用户	无	安全" | $saveresult
fi

echo -------------------------口令未加密-------------------------
echo "-------------------------正在检查口令加密用户-------------------------"
noenypasswd=$(awk -F: '{if($2!="x") {print $1}}' /etc/passwd)
if [ -n "$noenypasswd" ];then
	(echo "账户体系模块检查	检查口令未加密用户	请查看point.txt	建议加密") | $saveresult
	echo "口令未加密的用户如下：" | $point
	echo "$noenypasswd" | $point
else
	echo "账户体系模块检查	检查口令未加密用户	无	安全"  | $saveresult
fi

echo -------------------------用户组信息-------------------------
echo "-------------------------正在检查用户组信息-------------------------"
echo "[*]用户组信息如下:"
groupinfo=$(more /etc/group | grep -v "^#")
if [ -n "$groupinfo" ];then
	(echo "账户体系模块检查	检查用户组信息	请查看point.txt	自行判断") | $saveresult
	echo "用户组信息如下：" | $point
	echo "$groupinfo" | $point
else
	echo "账户体系模块检查	检查用户组信息	无	自行判断"  | $saveresult
fi

echo -------------------------特权用户-------------------------
echo "-------------------------正在检查特权用户-------------------------"
roots=$(more /etc/group | grep -v '^#' | awk -F: '{if ($1!="root"&&$3==0) print $1}')
if [ -n "$roots" ];then
	echo "账户体系模块检查	检查特权用户	请查看point.txt	自行判断" | $saveresult
	echo "特权用户如下：" | $point
	echo "$roots" | $point
else 
	echo "账户体系模块检查	检查特权用户	无	安全" | $saveresult
fi

echo -------------------------sudo权限的用户-------------------------
echo "-------------------------正在检查sudo权限的用户-------------------------"
sudoers=$(more /etc/sudoers | grep -v "#|$" | grep "ALL=(ALL)")
if [ -n "$sudoers" ];then
	echo "账户体系模块检查	检查sudo权限用户	请查看point.txt	自行判断" | $saveresult
	echo "sudo权限用户如下：" | $point
	echo "$sudoers" | $point
else 
	echo "账户体系模块检查	检查sudo权限用户	无	安全" | $saveresult
fi

echo -------------------------相同GID用户组-------------------------
echo "-------------------------正在检查相应GID用户组-------------------------"
groupuid=$(more /etc/group | grep -v "^$" | awk -F: '{print $3}' | uniq -d)
if [ -n "$groupuid" ];then
	(echo "账户体系模块检查	检查相同GID用户组	请查看point.txt	自行判断") | $saveresult
	echo "相同GID用户组如下：" | $point
	echo "$groupuid" | $point
else
	echo "账户体系模块检查	检查相同GID用户组	无	安全" | $saveresult
fi

echo -------------------------相同用户组名-------------------------
echo "-------------------------正在检查相同用户组名-------------------------"
groupname=$(more /etc/group | grep -v "^$" | awk -F: '{print $1}' | uniq -d)
if [ -n "$groupname" ];then
	(echo "账户体系模块检查	检查相同用户组名	请查看point.txt	自行判断") | $saveresult
	echo "相同用户组名如下：" | $point
	echo "$groupname" | $point
else
	echo "账户体系模块检查	检查相同用户组名	无	安全" | $saveresult
fi



echo -------------------------IP及版本-------------------------
echo -------------------------IP地址-------------------------
echo "-------------------------正在检查IP地址-------------------------"
ip=$(ifconfig -a | grep -w inet | awk '{print $2}')
if [ -n "$ip" ];then
	(echo "网络与端口检查	检查IP地址信息	请查看point.txt	无")  | $saveresult
	echo "IP地址信息如下：" | $point
	echo "$ip" | $point
else
	echo "网络与端口检查	检查IP地址信息	无	无IP地址" | $saveresult
fi

echo "-------------------------正在检查路由表-------------------------"
route=$(route -n)
if [ -n "$route" ];then
	(echo "网络与端口检查	检查路由表	请查看point.txt	自行判断") | $saveresult
	echo "路由表如下：" | $point
	echo "$route" | $point
else
	echo "网络与端口检查	检查路由表	无	无路由表" | $saveresult
fi

echo "-------------------------正在分析是否开启转发功能-------------------------"
#数值分析
#1:开启路由转发
#0:未开启路由转发
ip_forward=`more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}'`
if [ -n "$ip_forward" ];then
	echo "网络与端口检查	检查路由转发功能	请查看point.txt	自行判断" | $saveresult
	echo "路由表如下：" | $point
	echo "$ip_forward" | $point
else
	echo "网络与端口检查	检查路由转发功能	无	安全" | $saveresult
fi

echo -------------------------ARP表项-------------------------
arp=$(arp -a -n)
if [ -n "$arp" ];then
	(echo "网络与端口检查	检查ARP表项	请查看point.txt	自行判断") | $saveresult
	echo "ARP表项信息如下：" | $point
	echo "$arp" | $point
else
	echo "网络与端口检查	检查ARP表项	无	自行判断" | $saveresult
fi

echo -------------------------ARP攻击-------------------------
arpattack=$(arp -a -n | awk '{++S[$4]} END {for(a in S) {if($2>1) print $2,a,S[a]}}')
if [ -n "$arpattack" ];then
	(echo "网络与端口检查	检查是否存在ARP攻击	请查看point.txt	存在") | tee -a $danger_file | $saveresult
	echo "ARP攻击如下：" | $point
	echo "$arpattack" | $point
else
	echo "网络与端口检查	检查是否存在ARP攻击	无	安全" | $saveresult
fi

echo -------------------------查看TCP开放端口-------------------------
#TCP或UDP端口绑定在0.0.0.0、127.0.0.1、192.168.1.1这种IP上只表示这些端口开放
#只有绑定在0.0.0.0上局域网才可以访问
echo "-------------------------正在检查TCP开放端口-------------------------"
listenport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | sort -n | uniq)
if [ -n "$listenport" ];then
	(echo "网络与端口检查	检查开放TCP端口开放	请查看point.txt	自行判断") | $saveresult
	echo "TCP端口开放如下：" | $point
	echo "$listenport" | $point
else
	echo "网络与端口检查	检查开放TCP端口开放	无	安全" | $saveresult
fi

accessport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | sort -n | uniq)
if [ -n "$accessport" ];then
	(echo "网络与端口检查	检查TCP端口面向局域网或互联网开放情况	请查看point.txt	自行判断") | $saveresult
	echo "TCP端口面向局域网或互联网开放情况如下：" | $point
	echo "$accessport" | $point
else
	echo "网络与端口检查	检查TCP端口面向局域网或互联网开放情况	无	安全" | $saveresult
fi

echo -------------------------查看UDP开放端口-------------------------
echo "-------------------------正在检查UDP开放端口-------------------------"
udpopen=$(netstat -anlup | awk  '{print $4,$NF}' | grep : | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | sort -n | uniq)
if [ -n "$udpopen" ];then
	(echo "网络与端口检查	检查UDP端口面向局域网或互联网开放情况	请查看point.txt	自行判断") | $saveresult
	echo "UDP开放端口如下：" | $point
	echo "$udpopen" | $point
else
	echo "网络与端口检查	检查UDP端口面向局域网或互联网开放情况	无	安全" | $saveresult
fi

udpports=$(netstat -anlup | awk '{print $4,$NF}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | sort -n | uniq)
if [ -n "$udpports" ];then
	echo "网络与端口检查	检查UDP端口面向局域网或互联网开放情况	请查看point.txt	自行判断" | $saveresult
	echo "UDP端口面向局域网或互联网开放情况如下：" | $point
	echo "$udpports" | $point
else 
	echo "网络与端口检查	检查UDP端口面向局域网或互联网开放情况	无	安全" | $saveresult
fi



echo -------------------------网络连接-------------------------
echo "-------------------------正在检查网络连接情况-------------------------"
netstat=$(netstat -anlp | grep ESTABLISHED)
netstatnum=$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
if [ -n "$netstat" ];then
	(echo "网络与端口检查	检查网络连接情况	请查看point.txt	自行判断") | $saveresult
	echo "网络连接情况如下： | $point"
	echo "$udpports" | $point
	if [ -n "$netstatnum" ];then
		(echo "[*]各个状态的数量如下:" && echo "$netstatnum") | $point
	fi
else
	echo "网络与端口检查	检查网络连接情况	无	安全" | $saveresult
fi

echo -------------------------进程分析-------------------------
echo "-------------------------正在检查进程-------------------------"
ps=$(ps -aux)
if [ -n "$ps" ];then
	(echo "进程检查	收集正在运行的所有进程	查看point.txt	自行判断") | $saveresult
	echo "正在运行的所有进程如下：" | $point
	echo "$ps" | $point
else
	echo "进程检查	收集正在运行的所有进程	无	没有获取到进程信息" | $saveresult
fi

echo "-------------------------正在检查守护进程-------------------------"
if [ -e /etc/xinetd.d/rsync ];then
	rsyncinfo=$(more /etc/xinetd.d/rsync | grep -v "^#")
	(echo "进程检查	检查系统守护进程	请查看point.txt	自行判断") | $saveresult
	echo "系统守护进程如下： | $point"
	echo "$rsyncinfo" | $point
else
	echo "进程检查	检查系统守护进程	无	安全" | $saveresult
fi

echo "-------------------------正在检查隐藏进程-------------------------"
hiddenps=$(ps -ef|awk '{print}' |sort -n |uniq >1)
if [ -n "$hiddenps" ];then
	(echo "进程检查	检查隐藏进程	请查看point.txt	自行判断") | $saveresult
	echo "系统守护进程如下：" | $point
	echo "$hiddenps" | $point
else
	echo "进程检查	检查隐藏进程	无	安全" | $saveresult
fi

echo "-------------------------正在检查可疑进程-------------------------"
danger_process=$(ps -aux  | awk '{print $1,$11}' | sort | uniq | grep -E "(ncat|nc|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)$")
if [ -n "$danger_process" ];then
	(echo "进程检查	检查可疑进程	请查看point.txt	自行判断") | $saveresult
	echo "可疑进程如下：" | $point
	echo "$danger_process" | $point
else
	echo "进程检查	检查可疑进程	无	安全" | $saveresult
fi

echo -------------------------启动项-------------------------
echo "-------------------------正在检查用户自定义启动项-------------------------"
chkconfig=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}')
if [ -n "$chkconfig" ];then
	(echo "启动项检查	检查用户自定义启动项	请查看point.txt	自行判断") | $saveresult
	echo "用户自定义启动项如下：" | $point
	echo "$chkconfig" | $point
else
	echo "进程检查	检查用户自定义启动项	无	安全" | $saveresult
fi

echo "-------------------------正在检查系统自启动项-------------------------"
systemchkconfig=$(systemctl list-unit-files | grep enabled | awk '{print $1}')
if [ -n "$systemchkconfig" ];then
	(echo "启动项检查	检查系统自启动项如下	请查看point.txt	自行判断")  | $saveresult
	echo "系统自启动项如下：" | $point
	echo "$systemchkconfig" | $point
else
	echo "启动项检查	检查系统自启动项如下	无	安全" | $saveresult
fi

echo "-------------------------正在检查危险启动项-------------------------"
dangerstarup=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}' | grep -E "\.(sh|per|py)$")
if [ -n "$dangerstarup" ];then
	(echo "启动项检查	检查危险启动项	请查看point.txt	自行判断") | $saveresult
	echo "危险启动项如下：" | $point
	echo "$dangerstarup" | $point
else
	echo "启动项检查	检查危险启动项	无	安全" | $saveresult
fi


echo -------------------------查看定时任务-------------------------
echo "-------------------------正在分析系统定时任务-------------------------"
syscrontab=$(more /etc/crontab | grep -v "# run-parts" | grep run-parts)
if [ -n "$syscrontab" ];then
	(echo "定时任务检查	检查系统定时任务	请查看point.txt	自行判断") | $saveresult
	echo "系统定时任务如下：" | $point
	more /etc/crontab | $point
else
	echo "定时任务检查	检查系统定时任务	无	安全" | $saveresult
fi

# if [ $? -eq 0 ]表示上面命令执行成功;执行成功输出的是0；失败非0
#ifconfig  echo $? 返回0，表示执行成功
# if [ $? != 0 ]表示上面命令执行失败

echo "-------------------------正在分析系统可疑任务-------------------------"
dangersyscron=$(egrep "((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)$))"  /etc/cron*/* /var/spool/cron/*)
if [ $? -eq 0 ];then
	(echo "定时任务检查	检查可疑定时任务	请查看point.txt	自行判断") | $saveresult
	echo "系统定时任务如下：" | $point
	echo "$dangersyscron" | $point
else
	echo "定时任务检查	检查可疑定时任务	无	安全" | $saveresult
fi


echo "-------------------------正在查看用户定时任务-------------------------"
crontab=$(crontab -l)
if [ $? -eq 0 ];then
	(echo "定时任务检查	检查用户定时任务	请查看point.txt	自行判断") | $saveresult
	echo "用户定时任务如下：" | $point
	echo "$crontab" | $point
else
	echo "定时任务检查	检查用户定时任务	无	安全"  | $saveresult
fi

echo "-------------------------正在分析可疑定时任务-------------------------"
danger_crontab=$(crontab -l | egrep "((chmod|useradd|groupadd|chattr)|((wget|curl).*\.(sh|pl|py)))")
if [ $? -eq 0 ];then
	(echo "定时任务检查	检查可疑定时任务	请查看point.txt	自行判断") | $saveresult
	echo "可疑定时任务如下：" | $point
	echo "$danger_crontab" | $point
else
	echo "定时任务检查	检查可疑定时任务	无	安全" | $saveresult
fi

echo -------------------------关键文件检查-------------------------
echo "-------------------------正在检查DNS文件-------------------------"
resolv=$(more /etc/resolv.conf | grep ^nameserver | awk '{print $NF}') 
if [ -n "$resolv" ];then
	(echo "文件检查	检查DNS服务器	请查看point.txt	自行判断") | $saveresult
	echo "DNS服务器如下：" | $point
	echo "$resolv" | $point
else
	echo "文件检查	检查DNS服务器	无	安全" | $saveresult
fi

echo "-------------------------正在检查hosts文件-------------------------"
hosts=$(more /etc/hosts)
if [ -n "$hosts" ];then
	(echo "文件检查	检查hosts文件	请查看point.txt	自行判断") | $saveresult
	echo "hosts文件如下：" | $point
	echo "$hosts" | $point
else
	echo "文件检查	检查hosts文件	无	安全" | $saveresult
fi

echo "-------------------------正在检查公钥文件-------------------------"
if [  -e /root/.ssh/*.pub ];then
	echo "文件检查	检查公钥文件	请查看point.txt	自行判断" | $saveresult
	echo "公钥文件如下：" | $point
	more /root/.ssh/*.pub | $point
else
	echo "文件检查	检查公钥文件	无	安全" | $saveresult
fi

echo "-------------------------正在检查私钥文件-------------------------"
if [ -e /root/.ssh/id_rsa ];then
	echo "文件检查	检查私钥文件	请查看point.txt	自行判断" | $saveresult
	echo "私钥文件如下：" | $point
	more /root/.ssh/id_rsa | $point
else
	echo "文件检查	检查私钥文件	无	安全" | $saveresult
fi


echo "-------------------------正在检查运行服务-------------------------"
services=$(systemctl | grep -E "\.service.*running" | awk -F. '{print $1}')
if [ -n "$services" ];then
	(echo "文件检查	检查运行服务	请查看point.txt	自行判断") | $saveresult
	echo "运行服务如下：" | $point
	echo "$services" | $point
else
	echo "文件检查	检查运行服务	无	安全" | $saveresult
fi

echo "-------------------------正在检查web服务日志路径-------------------------"
pid=$(ps -aux | grep -E "(apache2|httpd|nginx|tomcat|weblogic)" | awk 'NR==1{print $2}')
webpaths=$(lsof -p $pid |grep log | awk '{print $9}')
flag1=""
for webpath in $webpaths
do
	if [ -n "$webpath" ];then
		echo "web日志路径如下：" | $point
		echo "$webpath" | $point
		flag1=1
	fi
done
if [ -n "$flag1" ];then
	echo "文件检查	检查web日志路径	请查看point.txt	自行判断"| $saveresult
else
	echo "文件检查	检查web日志路径	无	暂无运行的web服务和日志" | $saveresult
fi



echo -------------------------恶意文件-------------------------
#webshell这一块因为技术难度相对较高,并且已有专业的工具，目前这一块建议使用专门的安全检查工具来实现
#系统层的恶意文件建议使用rootkit专杀工具来查杀,如rkhunter,下载地址:http://rkhunter.sourceforge.net

echo -------------------------最近24小时内变动的文件-------------------------
#查看最近24小时内有改变的文件
24changed_files=$(find / -mtime 0 | grep -E "\.(py|sh|per|pl|php|asp|jsp)$")
flag2=""
for file in 24changed_files
do
	if [ -n "$file" ];then
		echo "最近24小时内变动的文件如下：" | $point
		echo "$file" | $point
		flag2=1
	fi
done
if [ -n "$flag2" ];then
	echo "文件检查	收集最近24小时内变动的文件	请查看point.txt	自行判断" | $saveresult
else
	echo "文件检查	收集最近24小时内变动的文件	无	安全" | $saveresult
fi


echo -------------------------文件完整性-------------------------
echo -------------------------系统文件完整性-------------------------
#通过取出系统关键文件的MD5值,一方面可以直接将这些关键文件的MD5值通过威胁情报平台进行查询
#另一方面,使用该软件进行多次检查时会将相应的MD5值进行对比,若和上次不一样,则会进行提示

echo "-------------------------正在采集系统关键文件MD5-------------------------"

if [ -e "$md5file" ]; then 
	md5sum -c "$md5file" 2>&1; 
else
	touch $md5file
	md5sum /usr/bin/awk >> $md5file
	md5sum /usr/bin/basename >> $md5file
	md5sum /usr/bin/bash >> $md5file
	md5sum /usr/bin/cat >> $md5file
	md5sum /usr/bin/chattr >> $md5file
	md5sum /usr/bin/chmod >> $md5file
	md5sum /usr/bin/chown >> $md5file
	md5sum /usr/bin/cp >> $md5file
	md5sum /usr/bin/csh >> $md5file
	md5sum /usr/bin/curl >> $md5file
	md5sum /usr/bin/cut >> $md5file
	md5sum /usr/bin/date >> $md5file
	md5sum /usr/bin/df >> $md5file
	md5sum /usr/bin/diff >> $md5file
	md5sum /usr/bin/dirname >> $md5file
	md5sum /usr/bin/dmesg >> $md5file
	md5sum /usr/bin/du >> $md5file
	md5sum /usr/bin/echo >> $md5file
	md5sum /usr/bin/ed >> $md5file
	md5sum /usr/bin/egrep >> $md5file
	md5sum /usr/bin/env >> $md5file
	md5sum /usr/bin/fgrep >> $md5file
	md5sum /usr/bin/file >> $md5file
	md5sum /usr/bin/find >> $md5file
	md5sum /usr/bin/gawk >> $md5file
	md5sum /usr/bin/GET >> $md5file
	md5sum /usr/bin/grep >> $md5file
	md5sum /usr/bin/groups >> $md5file
	md5sum /usr/bin/head >> $md5file
	md5sum /usr/bin/id >> $md5file
	md5sum /usr/bin/ipcs >> $md5file
	md5sum /usr/bin/kill >> $md5file
	md5sum /usr/bin/killall >> $md5file
	md5sum /usr/bin/kmod >> $md5file
	md5sum /usr/bin/last >> $md5file
	md5sum /usr/bin/lastlog >> $md5file
	md5sum /usr/bin/ldd >> $md5file
	md5sum /usr/bin/less >> $md5file
	md5sum /usr/bin/locate >> $md5file
	md5sum /usr/bin/logger >> $md5file
	md5sum /usr/bin/login >> $md5file
	md5sum /usr/bin/ls >> $md5file
	md5sum /usr/bin/lsattr >> $md5file
	md5sum /usr/bin/lynx >> $md5file
	md5sum /usr/bin/mail >> $md5file
	md5sum /usr/bin/mailx >> $md5file
	md5sum /usr/bin/md5sum >> $md5file
	md5sum /usr/bin/mktemp >> $md5file
	md5sum /usr/bin/more >> $md5file
	md5sum /usr/bin/mount >> $md5file
	md5sum /usr/bin/mv >> $md5file
	md5sum /usr/bin/netstat >> $md5file
	md5sum /usr/bin/newgrp >> $md5file
	md5sum /usr/bin/numfmt >> $md5file
	md5sum /usr/bin/passwd >> $md5file
	md5sum /usr/bin/perl >> $md5file
	md5sum /usr/bin/pgrep >> $md5file
	md5sum /usr/bin/ping >> $md5file
	md5sum /usr/bin/pkill >> $md5file
	md5sum /usr/bin/ps >> $md5file
	md5sum /usr/bin/pstree >> $md5file
	md5sum /usr/bin/pwd >> $md5file
	md5sum /usr/bin/readlink >> $md5file
	md5sum /usr/bin/rpm >> $md5file
	md5sum /usr/bin/runcon >> $md5file
	md5sum /usr/bin/sed >> $md5file
	md5sum /usr/bin/sh >> $md5file
	md5sum /usr/bin/sha1sum >> $md5file
	md5sum /usr/bin/sha224sum >> $md5file
	md5sum /usr/bin/sha256sum >> $md5file
	md5sum /usr/bin/sha384sum >> $md5file
	md5sum /usr/bin/sha512sum >> $md5file
	md5sum /usr/bin/size >> $md5file
	md5sum /usr/bin/sort >> $md5file
	md5sum /usr/bin/ssh >> $md5file
	md5sum /usr/bin/stat >> $md5file
	md5sum /usr/bin/strace >> $md5file
	md5sum /usr/bin/strings >> $md5file
	md5sum /usr/bin/su >> $md5file
	md5sum /usr/bin/sudo >> $md5file
	md5sum /usr/bin/systemctl >> $md5file
	md5sum /usr/bin/tail >> $md5file
	md5sum /usr/bin/tcsh >> $md5file
	md5sum /usr/bin/telnet >> $md5file
	md5sum /usr/bin/test >> $md5file
	md5sum /usr/bin/top >> $md5file
	md5sum /usr/bin/touch >> $md5file
	md5sum /usr/bin/tr >> $md5file
	md5sum /usr/bin/uname >> $md5file
	md5sum /usr/bin/uniq >> $md5file
	md5sum /usr/bin/users >> $md5file
	md5sum /usr/bin/vmstat >> $md5file
	md5sum /usr/bin/w >> $md5file
	md5sum /usr/bin/watch >> $md5file
	md5sum /usr/bin/wc >> $md5file
	md5sum /usr/bin/wget >> $md5file
	md5sum /usr/bin/whatis >> $md5file
	md5sum /usr/bin/whereis >> $md5file
	md5sum /usr/bin/which >> $md5file
	md5sum /usr/bin/who >> $md5file
	md5sum /usr/bin/whoami >> $md5file
	md5sum /usr/lib/systemd/s >> $md5file
	md5sum /usr/local/bin/rkh >> $md5file
	md5sum /usr/sbin/adduser >> $md5file
	md5sum /usr/sbin/chkconfi >> $md5file
	md5sum /usr/sbin/chroot >> $md5file
	md5sum /usr/sbin/depmod >> $md5file
	md5sum /usr/sbin/fsck >> $md5file
	md5sum /usr/sbin/fuser >> $md5file
	md5sum /usr/sbin/groupadd >> $md5file
	md5sum /usr/sbin/groupdel >> $md5file
	md5sum /usr/sbin/groupmod >> $md5file
	md5sum /usr/sbin/grpck >> $md5file
	md5sum /usr/sbin/ifconfig >> $md5file
	md5sum /usr/sbin/ifdown >> $md5file
	md5sum /usr/sbin/ifup >> $md5file
	md5sum /usr/sbin/init >> $md5file
	md5sum /usr/sbin/insmod >> $md5file
	md5sum /usr/sbin/ip >> $md5file
	md5sum /usr/sbin/lsmod >> $md5file
	md5sum /usr/sbin/lsof >> $md5file
	md5sum /usr/sbin/modinfo >> $md5file
	md5sum /usr/sbin/modprobe >> $md5file
	md5sum /usr/sbin/nologin >> $md5file
	md5sum /usr/sbin/pwck >> $md5file
	md5sum /usr/sbin/rmmod >> $md5file
	md5sum /usr/sbin/route >> $md5file
	md5sum /usr/sbin/rsyslogd >> $md5file
	md5sum /usr/sbin/runlevel >> $md5file
	md5sum /usr/sbin/sestatus >> $md5file
	md5sum /usr/sbin/sshd >> $md5file
	md5sum /usr/sbin/sulogin >> $md5file
	md5sum /usr/sbin/sysctl >> $md5file
	md5sum /usr/sbin/tcpd >> $md5file
	md5sum /usr/sbin/useradd >> $md5file
	md5sum /usr/sbin/userdel >> $md5file
	md5sum /usr/sbin/usermod >> $md5file
	md5sum /usr/sbin/vipw >> $md5file
fi
echo "文件检查	收集关键命令MD5值	请查看point.txt	自行判断" | $saveresult


echo -------------------------日志分析------------------------------
echo "-------------------------正在查看日志配置-------------------------"
logconf=$(more /etc/rsyslog.conf | egrep -v "#|^$")
if [ -n "$logconf" ];then
	(echo "系统日志收集与分析	检查日志配置	请查看point.txt	自行判断") | $saveresult
	echo "日志配置如下：" | $point
	echo "$logconf" | $point
else
	echo "系统日志收集与分析	检查日志配置	无	请尽快配置日志配置文件" | $saveresult
fi

echo "-------------------------正在分析日志文件是否存在-------------------------"
logs=$(ls -l /var/log/)
if [ -n "$logs" ];then
	echo "系统日志收集与分析	检查日志是否存在	存在	符合要求" | $saveresult
else
	echo "系统日志收集与分析	检查日志是否存在	不存在	清确认日志文件是否被清除" | $saveresult
fi

echo "-------------------------正在分析日志审核是否开启-------------------------"
service auditd status | grep running
if [ $? -eq 0 ];then
	echo "系统日志收集与分析	检查日志审核是否开启	存在	符合要求" | $saveresult
else
	echo "系统日志收集与分析	检查日志审核是否开启	存在	不符合要求,建议开启日志审核。可使用以下命令开启:service auditd start" | $saveresult
fi

echo "-------------------------正在打包日志-------------------------"
zip -r system_log.zip /var/log/
if [ $? -eq 0 ];then
	echo "[*]日志打包成功"
else
	echo "[!!!]日志打包失败,请工人导出日志"
fi

echo -------------------------secure日志分析-------------------------
echo -------------------------成功登录-------------------------
echo "-------------------------正在检查日志中成功登录的情况-------------------------"
loginsuccess=$(more /var/log/secure* /var/log/auth.log | grep "Accepted password" | awk '{print $1,$2,$3,$(NF-3),$NF}')
if [ -n "$loginsuccess" ];then
	echo "系统日志收集与分析	检查服务器成功登录的情况	请查看point.txt	自行判断" | $saveresult
	echo "服务器成功登录的情况如下："  | $point
	(echo "[*]日志中分析到以下用户成功登录:" && echo "$loginsuccess")  | $point
	(echo "[*]登录成功的IP及次数如下：" && grep "Accepted " /var/log/secure* /var/log/auth.log | awk '{print $NF}' | sort -nr | uniq -c )  | $point
	(echo "[*]登录成功的用户及次数如下:" && grep "Accepted" /var/log/secure* /var/log/auth.log | awk '{print $(NF-3)}' | sort -nr | uniq -c )  | $point
else
	echo "系统日志收集与分析	检查服务器成功登录的情况	无	自行判断" | $saveresult
fi

echo -------------------------登录失败-------------------------
echo "-------------------------存在检查日志中登录失败的情况-------------------------"
loginfailed=$(more /var/log/secure* /var/log/auth.log | grep "Failed password" | awk '{print $1,$2,$3,$(NF-3),$NF}')
if [ -n "$loginfailed" ];then
	echo "系统日志收集与分析	检查服务器成功失败的情况	请查看point.txt	自行判断" | $saveresult
	echo "服务器失败登录的情况如下："  | $point
	(echo "[!!!]日志中发现以下登录失败的情况:" && echo "$loginfailed") | $point
	(echo "[!!!]登录失败的IP及次数如下:" && grep "Failed password" /var/log/secure* /var/log/auth.log | awk '{print $NF}' | sort -nr | uniq -c)  | $point
	(echo "[!!!]登录失败的用户及次数如下:" && grep "Failed password" /var/log/secure* /var/log/auth.log | awk '{print $(NF-3)}' | sort -nr | uniq -c)  | $point
else
	echo "系统日志收集与分析	检查服务器成功失败的情况	无	自行判断" | $saveresult
fi

echo "-------------------------正在检查本机登录情况-------------------------"
systemlogin=$(more /var/log/secure* /var/log/auth.log | grep -E "sshd:session.*session opened" | awk '{print $1,$2,$3,$11}')
if [ -n "$systemlogin" ];then
	echo "系统日志收集与分析	检查本机登录情况	请查看point.txt	自行判断" | $saveresult
	echo "本机登录情况如下："  | $point
	(echo "[*]本机登录情况:" && echo "$systemlogin") | $point
	(echo "[*]本机登录账号及次数如下:" && more /var/log/secure* /var/log/auth.log | grep -E "sshd:session.*session opened" | awk '{print $11}' | sort -nr | uniq -c) | $point
else
	echo "系统日志收集与分析	检查本机登录情况	无	自行判断" | $point
fi

echo "-------------------------正在检查新增用户-------------------------"
newusers=$(more /var/log/secure* /var/log/auth.log | grep "new user"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -n "$newusers" ];then
	echo "系统日志收集与分析	检查新增用户	请查看point.txt	自行判断" | $saveresult
	echo "新增用户情况如下："  | $point
	(echo "[!!!]日志中发现新增用户:" && echo "$newusers") | $point
	(echo "[*]新增用户账号及次数如下:" && more /var/log/secure* /var/log/auth.log | grep "new user" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $point
else
	echo "系统日志收集与分析	检查新增用户	无	安全" | $saveresult
fi

echo "-------------------------正在检查新增用户组-------------------------"
newgoup=$(more /var/log/secure* /var/log/auth.log | grep "new group"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -n "$newgoup" ];then
	echo "系统日志收集与分析	检查新增用户组	请查看point.txt	自行判断" | $saveresult
	echo "新增用户组情况如下："  | $point
	(echo "[!!!]日志中发现新增用户组:" && echo "$newgoup") | $point
	(echo "[*]新增用户组及次数如下:" && more /var/log/secure* /var/log/auth.log | grep "new group" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $point
else
	echo "系统日志收集与分析	检查新增用户组	无	安全" | $saveresult
fi

echo  "-------------------------挖矿木马检查 -------------------------"
mining_proccess=$(ps -aux | awk '{print $1,$11}' | sort | uniq | grep "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb|warmup")
mining_autorun=$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f)
if [ -n "$mining_proccess" ] || [ -n "$mining_autorun" ];then
	echo "系统日志收集与分析	常规挖矿进程检测	请查看point.txt	可能中招" | $saveresult
	echo "常规挖矿进程检测如下："  | $point
	(echo "[!!!]发现可疑挖矿木马进程:" && echo "$mining_proccess" && echo "$mining_autorun") | $point
else
	echo "系统日志收集与分析	常规挖矿进程检测	无	安全" | $saveresult
fi

ntpclient_proccess=$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz|warmup')
ntpclient_file=$(ls -lah /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null)
if [ -n "$ntpclient_proccess" ] || [ -n "$ntpclient_file" ];then
	echo "系统日志收集与分析	Ntpclient挖矿木马检测	请查看point.txt	可能中招" | $saveresult
	echo "Ntpclient 挖矿木马检测如下："  | $point
	(echo "[!!!]发现可疑Ntpclient挖矿木马进程:" && echo "$ntpclient_proccess" && echo "$ntpclient_file") | $point
else
	echo "系统日志收集与分析	Ntpclient挖矿木马检测	无	安全" | $saveresult
fi

workminerps_proccess=$(ps -aux | awk '{print $1,$11}' | sort | uniq | grep "work32|work64|/tmp/secure.sh|/tmp/auth.sh|warmup")
workminerps_file=$(ls -lah /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null)
if [ -n "$workminerps_proccess" ] || [ -n "$workminerps_file" ];then
	echo "系统日志收集与分析	WorkMiner挖矿木马检测	请查看point.txt	可能中招" | $saveresult
	echo "Ntpclient 挖矿木马检测如下："  | $point
	(echo "[!!!]发现可疑WorkMiner挖矿木马进程:" && echo "$ntpclient_proccess" && echo "$ntpclient_file") | $point
else
	echo "系统日志收集与分析	WorkMiner挖矿木马检测	无	安全" | $saveresult
fi


echo -------------------------message日志分析-------------------------
#下面命令仅显示传输的文件名,并会将相同文件名的去重
#more /var/log/message* | grep "ZMODEM:.*BPS" | awk -F '[]/]' '{print $0}' | sort | uniq
echo "-------------------------正在检查传输文件-------------------------"
zmodem=$(more /var/log/message* | grep "ZMODEM:.*BPS")
if [ -n "$zmodem" ];then
	echo "系统日志收集与分析	检查message日志-传输文件记录	请查看point.txt	自行判断" | $saveresult
	echo "message日志-传输文件记录如下："  | $point
	(echo "[!!!]传输文件情况:" && echo "$zmodem") | $point
else
	echo "系统日志收集与分析	检查message日志-传输文件记录	无	安全" | $saveresult
fi

echo -------------------------历史使用DNS服务器-------------------------
echo "-------------------------正在检查日志中使用DNS服务器的情况-------------------------"
dns_history=$(more /var/log/messages* | grep "using nameserver" | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq)
if [ -n "$dns_history" ];then
	echo "系统日志收集与分析	检查message日志-检查历史DNS服务器使用记录	请查看point.txt	自行判断" | $saveresult
	echo "message日志-历史DNS服务器使用情况如下："  | $point
	(echo "[!!!]该服务器曾经使用以下DNS:" && echo "$dns_history") | $point
else
	echo "系统日志收集与分析	检查历史DNS服务器使用记录	无	安全" | $saveresult
fi

echo -------------------------cron日志分析-------------------------
echo "-------------------------正在分析定时下载-------------------------"
cron_download=$(more /var/log/cron* | grep "wget|curl")
if [ -n "$cron_download" ];then
	echo "系统日志收集与分析	检查cron日志-检查定时下载	请查看point.txt	自行判断" | $saveresult
	echo "cron日志-定时下载情况如下："  | $point
	(echo "[!!!]定时下载情况:" && echo "$cron_download") | $point
else
	echo "系统日志收集与分析	检查cron日志-检查定时下载	无	安全" | $saveresult
fi

echo -------------------------定时执行脚本-------------------------
echo "-------------------------正在分析定时执行脚本-------------------------"
cron_shell=$(more /var/log/cron* | grep -E "\.py$|\.sh$|\.pl$") 
if [ -n "$cron_shell" ];then
	echo "系统日志收集与分析	检查cron日志-检查定时执行脚本	请查看point.txt	自行判断" | $saveresult
	echo "cron日志-执行脚本："  | $point
	(echo "[!!!]发现定时执行脚本:" && echo "$cron_download") | $point
else
	echo "系统日志收集与分析	检查cron日志-检查定时执行脚本	无	安全" | $saveresult
fi

echo -------------------------dmesg日志分析-------------------------
echo "-------------------------正在查看内核自检日志-------------------------"
dmesg=$(dmesg)
if [ $? -eq 0 ];then
	echo "系统日志收集与分析	dmesg日志分析-检查内核自检	请查看point.txt	自行判断" | $saveresult
	echo "dmesg日志分析-内核自检情况："  | $point
	(echo "[*]日志自检日志如下：" && "$dmesg" ) | $point
else
	echo "系统日志收集与分析	dmesg日志分析-检查内核自检	无	自行判断" | $saveresult
fi

echo -------------------------btmp日志分析-------------------------
echo "-------------------------正在分析错误登录日志-------------------------"
lastb=$(lastb)
if [ -n "$lastb" ];then
	echo "系统日志收集与分析	btmp日志分析-检查错误登录日志	请查看point.txt	自行判断" | $saveresult
	echo "btmp日志分析-内核自检情况："  | $point
	(echo "[*]错误登录日志如下:" && echo "$lastb") | $point
else
	echo "系统日志收集与分析	btmp日志分析-检查错误登录日志	无	建议开启" | $saveresult
fi

echo -------------------------lastlog日志分析-------------------------
echo "-------------------------正在分析所有用户最后一次登录日志-------------------------"
lastlog=$(lastlog)
if [ -n "$lastlog" ];then
	echo "系统日志收集与分析	lastlog日志分析-检查用户最后一次登录日志	请查看point.txt	自行判断" | $saveresult
	echo "lastlog日志分析-用户最后一次登录日志:"  | $point
	(echo "[*]所有用户最后一次登录日志如下:" && echo "$lastlog") | $point
else
	echo "系统日志收集与分析	lastlog日志分析-检查用户最后一次登录日志	无	建议开启" | $saveresult
fi

echo -------------------------wtmp日志分析-------------------------
echo "-------------------------正在检查历史上登录到本机的用户-------------------------"
lasts=$(last | grep pts | grep -vw :0)
if [ -n "$lasts" ];then
	echo "系统日志收集与分析	wtmp日志分析-检查历史上登录到本机的用户	请查看point.txt	自行判断" | $saveresult
	echo "wtmp日志分析-历史上登录到本机的用户:"  | $point
	(echo "[*]历史上登录到本机的用户如下:" && echo "$lasts") | $point
else
	echo "系统日志收集与分析	wtmp日志分析-检查历史上登录到本机的用户	无	建议开启" | $saveresult
fi

echo -------------------------内核检查-------------------------
echo "-------------------------正在检查内核信息-------------------------"
lsmod=$(lsmod)
if [ -n "$lsmod" ];then
	echo "内核检查	检查内核信息	请查看point.txt	自行判断" | $saveresult
	echo "内核信息:"  | $point
	(echo "$lsmod") | $point
else
	echo "内核检查	检查内核信息	无	无" | $saveresult
fi

echo "-------------------------正在检查可疑内核-------------------------"
danger_lsmod=$(lsmod | grep -Ev "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state")
if [ -n "$danger_lsmod" ];then
	echo "内核检查	检查可疑内核	请查看point.txt	自行判断" | $saveresult
	echo "发现可疑内核模块:"  | $point
	(echo "$danger_lsmod") | $point
else
	echo "[*]未发现可疑内核模块" | $saveresult
fi

echo -------------------------版本信息-------------------------
echo "-------------------------正在检查系统内核版本-------------------------"
corever=$(uname -a | sed 's/ /-/g')
if [ -n "$corever" ];then
	(echo "系统项检查	检查系统内核版本信息	$corever	自行判断") | $saveresult
else
	echo "系统项检查	检查系统内核版本信息	无	自行判断" | $saveresult
fi

echo "-------------------------正在检查系统发行版本-------------------------"
systemver=$(cat /etc/issue | sed 's/ /-/g')
if [ -n "$systemver" ];then
	(echo "系统项检查	检查系统发行版本	$systemver	自行判断") | $saveresult
else
	echo "系统项检查	检查系统发行版本	无	自行判断" | $saveresult
fi

echo "-------------------------正在检查环境变量-------------------------"
env=$(env)
if [ -n "$env" ];then
	echo "系统项检查	检查环境变量	请查看point.txt	自行判断" | $saveresult
	echo "环境变量如下:"  | $point
	(echo "$env") | $point
else
	echo "系统项检查	检查环境变量	无	无" | $saveresult
fi

echo -------------------------性能分析-------------------------
echo "-------------------------正在检查CPU相关信息-------------------------"
echo "系统项检查	检查CPU相关信息	请查看point.txt	自行判断" | $saveresult
(echo "CPU硬件信息如下:" && more /proc/cpuinfo ) | $point
(echo "CPU使用情况如下:" && ps -aux | sort -nr -k 3 | awk  '{print $1,$2,$3,$NF}') | $point

echo "-------------------------正在检查占用CPU前5资源的进程-------------------------"
(echo "占用CPU资源前5进程：" && ps -aux | sort -nr -k 3 | head -5)  | $point

echo "-------------------------正在检查占用CPU较大的进程-------------------------"
pscpu=$(ps -aux | sort -nr -k 3 | head -5 | awk '{if($3>=20) print $0}')
if [ -n "$pscpu" ];then
	echo "[!!!]以下进程占用的CPU超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD" 
	echo "$pscpu" | $point
fi

echo "-------------------------正在检查内存相关信息-------------------------"
echo "系统项检查	检查内存相关信息	请查看point.txt	自行判断" | $saveresult
(echo "内存信息如下:" && more /proc/meminfo) | $point
(echo "内存使用情况如下:" && free -m) | $point

echo "-------------------------正在检查占用内存前5资源的进程-------------------------"
(echo "占用内存资源前5进程：" && ps -aux | sort -nr -k 4 | head -5) | $point

echo -------------------------占用内存较多进程-------------------------
echo "-------------------------正在检查占用内存较多的进程-------------------------"
psmem=$(ps -aux | sort -nr -k 4 | head -5 | awk '{if($4>=2) print $0}')
if [ -n "$psmem" ];then
	echo "以下进程占用的内存超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD"
	echo "$psmem" | $point
fi

# echo "-------------------------正在检查系统运行时间及负载情况-------------------------"
# runningtime=$(uptime)
# (echo "系统项检查	检查系统运行时间	uptime") | $saveresult

echo "-------------------------正在将检查文件压缩到/tmp/目录下-------------------------"
zip -r ./linuxcheck_${ipadd}_${date}.zip checkresult.csv point.txt sysfile_md5.txt
echo "检查结束！！！"
iconv -f UTF-8 -t GBK checkresult.csv -o checkresult.csv
endTime_s=`date +%s`
sumTime=$((endTime_s-startTime_s))
echo "脚本执行时长:$sumTime 秒"