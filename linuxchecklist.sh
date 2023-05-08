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

check_file="/tmp/linuxcheck_${ipadd}_${date}/check_file/"
danger_file="/tmp/linuxcheck_${ipadd}_${date}/danger_file.txt"
log_file="/tmp/linuxcheck_${ipadd}_${date}/log/"
rm -rf $check_file
rm -rf $danger_file
rm -rf log_file
mkdir /tmp/linuxcheck_${ipadd}_${date}/
echo "检查发现危险项,请注意:" > ${danger_file}
mkdir $check_file
echo "" >> $danger_file
mkdir $log_file
cd $check_file

if [ $(whoami) != "root" ];then
	echo "安全检查必须使用root账号,否则某些项无法检查"
	exit 1
fi


saveresult="tee -a checkresult.txt"
echo "-------------------------初始检查清单-------------------------" && "$saveresult"
echo -------------------------检查root用户history-------------------------
echo -------------------------检查其他用户history-------------------------
echo "-------------------------正在检查root用户history-------------------------" | $saveresult
history=$(more /root/.bash_history)
if [ -n "$history" ];then
	(echo "[*]操作系统历史命令如下:" && echo "$history") | $saveresult
else
	echo "[!!!]未发现历史命令,请检查是否记录及已被清除" | $saveresult
fi
printf "\n" | $saveresult

echo "-------------------------正在检查其他用户history-------------------------" | $saveresult
# 获取所有使用/bin/bash作为默认shell的用户列表，排除root用户
USERS=$(getent passwd | awk -F: '$7 == "/bin/bash" && $1 != "root" {print $1}')

# 遍历每个用户并输出其历史记录
for USER in $USERS
do
  echo "History for $USER:"
  echo "-------------------------"
  history=$(more /home/$USER/.bash_history)
  if [ -n "$history" ];then
	(echo "[*]操作系统历史命令如下:" && echo "$history") | $saveresult
  else
	echo "[!!!]未发现历史命令,请检查是否记录及已被清除" | $saveresult
  fi
  printf "\n" | $saveresult
  echo ""
done

echo "-------------------------正在检查账号和特权用户-------------------------" | $saveresult
echo -------------------------查看登录用户-------------------------
echo "-------------------------正在检查正在登录的用户-------------------------" | $saveresult
(echo "[*]系统登录用户:" && who ) | $saveresult
printf "\n" | $saveresult

echo -------------------------查看用户信息-------------------------
echo "-------------------------正在查看用户信息-------------------------" | $saveresult
echo "[*]用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录Shell" | $saveresult
more /etc/passwd  | $saveresult
printf "\n" | $saveresult

echo -------------------------超级用户-------------------------
#UID=0的为超级用户,系统默认root的UID为0
echo "-------------------------正在检查是否存在超级用户-------------------------" | $saveresult
Superuser=`more /etc/passwd | egrep -v '^root|^#|^(\+:\*)?:0:0:::' | awk -F: '{if($3==0) print $1}'`
if [ -n "$Superuser" ];then
	echo "[!!!]除root外发现超级用户:" | tee -a $danger_file | $saveresult
	for user in $Superuser
	do
		echo $user | $saveresult
		if [ "${user}" = "toor" ];then
			echo "[!!!]BSD系统默认安装toor用户,其他系统默认未安装toor用户,若非BSD系统建议删除该账号" | $saveresult
		fi
	done
else
	echo "[*]未发现超级用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------克隆用户-------------------------
#相同的UID为克隆用户
echo "-------------------------正在检查是否存在克隆用户-------------------------" | $saveresult
uid=`awk -F: '{a[$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd`
if [ -n "$uid" ];then
	echo "[!!!]发现下面用户的UID相同:" | tee -a $danger_file | $saveresult
	(more /etc/passwd | grep $uid | awk -F: '{print $1}') | tee -a $danger_file | $saveresult
else
	echo "[*]未发现相同UID的用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------可登录用户-------------------------
echo "-------------------------正在检查可登录的用户-------------------------" | $saveresult
loginuser=`cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}'`
if [ -n "$loginuser" ];then
	echo "[!!!]以下用户可以登录：" | tee -a $danger_file | $saveresult
	for user in $loginuser
	do
		echo $user | tee -a $danger_file | $saveresult
	done
else
	echo "[*]未发现可以登录的用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------非系统用户-------------------------
echo "-------------------------正在检查非系统本身自带用户" | $saveresult
if [ -f /etc/login.defs ];then
	uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
	(echo "系统最小UID为"$uid) | $saveresult
	nosystemuser=`gawk -F: '{if ($3>='$uid' && $3!=65534) {print $1}}' /etc/passwd`
	if [ -n "$nosystemuser" ];then
		(echo "以下用户为非系统本身自带用户:" && echo "$nosystemuser") | tee -a $danger_file | $saveresult
	else
		echo "[*]未发现除系统本身外的其他用户" | $saveresult
	fi
fi
printf "\n" | $saveresult

echo -------------------------shadow文件-------------------------
echo "-------------------------正在检查shadow文件-------------------------" | $saveresult
(echo "[*]shadow文件" && more /etc/shadow ) | $saveresult
printf "\n" | $saveresult

echo -------------------------空口令用户-------------------------
echo "正在检查空口令用户-------------------------" | $saveresult
nopasswd=`gawk -F: '($2=="")||($2=="!") {print $1}' /etc/shadow`
if [ -n "$nopasswd" ];then
	(echo "[!!!]以下用户口令为空：" && echo "$nopasswd") | $saveresult
else
	echo "[*]未发现空口令用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------空口令且可登录-------------------------
echo "-------------------------正在检查空口令且可登录的用户-------------------------" | $saveresult
#允许空口令用户登录方法
#1.passwd -d username
#2.echo "PermitEmptyPasswords yes" >>/etc/ssh/sshd_config
#3.service sshd restart
aa=$(cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}')
bb=$(gawk -F: '($2=="")||($2=="!") {print $1}' /etc/shadow)
cc=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
flag=""
for a in $aa
do
    for b in $bb
    do
        if [ "$a" = "$b" ] && [ -n "$cc" ];then
            echo "[!!!]发现空口令且可登录用户:"$a | $saveresult
            flag=1
        fi
    done
done
if [ -n "$flag" ];then
	echo "请人工分析配置和账号" | $saveresult
else
	echo "[*]未发现空口令且可登录用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------口令未加密-------------------------
echo "-------------------------正在检查口令加密用户-------------------------" | $saveresult
noenypasswd=$(awk -F: '{if($2!="x") {print $1}}' /etc/passwd)
if [ -n "$noenypasswd" ];then
	(echo "[!!!]以下用户口令未加密:" && echo "$noenypasswd") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现口令未加密的用户"  | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------用户组分析-------------------------
echo -------------------------用户组信息-------------------------
echo "-------------------------正在检查用户组信息-------------------------" | $saveresult
echo "[*]用户组信息如下:"
(more /etc/group | grep -v "^#") | $saveresult
printf "\n" | $saveresult

echo -------------------------特权用户-------------------------
echo "-------------------------正在检查特权用户-------------------------" | $saveresult
roots=$(more /etc/group | grep -v '^#' | gawk -F: '{if ($1!="root"&&$3==0) print $1}')
if [ -n "$roots" ];then
	echo "[!!!]除root用户外root组还有以下用户:" | tee -a $danger_file | $saveresult
	for user in $roots
	do
		echo $user | tee -a $danger_file | $saveresult
	done
else 
	echo "[*]除root用户外root组未发现其他用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------sudo权限的用户-------------------------
echo "-------------------------正在检查sudo权限的用户-------------------------" | $saveresult
sudoers=$(more /etc/sudoers | grep -v "#|$" | grep "ALL=(ALL)")
if [ -n "$sudoers" ];then
	echo "[!!!]sudo权限的用户如下:" | tee -a $danger_file | $saveresult
	for sudouser in $sudoers
	do
		echo $sudouser | tee -a $danger_file | $saveresult
	done
else 
	echo "[*]除root用户外root组未发现其他用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------相同GID用户组-------------------------
echo "-------------------------正在检查相应GID用户组-------------------------" | $saveresult
groupuid=$(more /etc/group | grep -v "^$" | awk -F: '{print $3}' | uniq -d)
if [ -n "$groupuid" ];then
	(echo "[!!!]发现相同GID用户组:" && echo "$groupuid") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现相同GID的用户组" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------相同用户组名-------------------------
echo "正在检查相同用户组名-------------------------" | $saveresult
groupname=$(more /etc/group | grep -v "^$" | awk -F: '{print $1}' | uniq -d)
if [ -n "$groupname" ];then
	(echo "[!!!]发现相同用户组名:" && echo "$groupname") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现相同用户组名" | $saveresult
fi
printf "\n" | $saveresult



echo "-------------------------正在检查IP地址-------------------------" && "$saveresult"

echo -------------------------IP及版本-------------------------
echo -------------------------IP地址-------------------------
echo "-------------------------正在检查IP地址-------------------------" | $saveresult
ip=$(ifconfig -a | grep -w inet | awk '{print $2}')
if [ -n "$ip" ];then
	(echo "[*]本机IP地址信息:" && echo "$ip")  | $saveresult
else
	echo "[!!!]本机未配置IP地址" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------版本信息-------------------------
echo "-------------------------正在检查系统内核版本-------------------------" | $saveresult
corever=$(uname -a)
if [ -n "$corever" ];then
	(echo "[*]系统内核版本信息:" && echo "$corever") | $saveresult
else
	echo "[!!!]未发现内核版本信息" | $saveresult
fi
printf "\n" | $saveresult

echo "-------------------------正在检查系统发行版本-------------------------" | $saveresult
systemver=$(cat /etc/redhat-release)
if [ -n "$systemver" ];then
	(echo "[*]系统发行版本:" && echo "$systemver") | $saveresult
else
	echo "[!!!]未发现发行版本信息" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------ARP-------------------------
echo -------------------------ARP表项-------------------------
echo "-------------------------正在查看ARP表项-------------------------" | $saveresult
arp=$(arp -a -n)
if [ -n "$arp" ];then
	(echo "[*]ARP表项如下:" && echo "$arp") | $saveresult
else
	echo "[未发现arp表]" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------ARP攻击-------------------------
echo "正在检测是否存在ARP攻击-------------------------" | $saveresult
arpattack=$(arp -a -n | awk '{++S[$4]} END {for(a in S) {if($2>1) print $2,a,S[a]}}')
if [ -n "$arpattack" ];then
	(echo "[!!!]发现存在ARP攻击:" && echo "$arpattack") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现ARP攻击" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------查看端口情况-------------------------
echo -------------------------查看TCP开放端口-------------------------
#TCP或UDP端口绑定在0.0.0.0、127.0.0.1、192.168.1.1这种IP上只表示这些端口开放
#只有绑定在0.0.0.0上局域网才可以访问
echo "-------------------------正在检查TCP开放端口-------------------------" | $saveresult
listenport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$listenport" ];then
	(echo "[*]该服务器开放TCP端口以及对应的服务:" && echo "$listenport") | $saveresult
else
	echo "[!!!]系统未开放TCP端口" | $saveresult
fi
printf "\n" | $saveresult

accessport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$accessport" ];then
	(echo "[!!!]以下TCP端口面向局域网或互联网开放,请注意！" && echo "$accessport") | $saveresult
else
	echo "[*]端口未面向局域网或互联网开放" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------查看UDP开放端口-------------------------
echo "-------------------------正在检查UDP开放端口-------------------------" | $saveresult
udpopen=$(netstat -anlup | awk  '{print $4,$NF}' | grep : | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$udpopen" ];then
	(echo "[*]该服务器开放UDP端口以及对应的服务:" && echo "$udpopen") | $saveresult
else
	echo "[!!!]系统未开放UDP端口" | $saveresult
fi
printf "\n" | $saveresult

udpports=$(netstat -anlup | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
if [ -n "$udpports" ];then
	echo "[*]以下UDP端口面向局域网或互联网开放:" | $saveresult
	for port in $udpports
	do
		nc -uz 127.0.0.1 $port
		if [ $? -eq 0 ];then
			echo $port  | $saveresult
		fi
	done
else 
	echo "[*]未发现在UDP端口面向局域网或互联网开放." | $saveresult
fi
printf "\n" | $saveresult



echo -------------------------网络连接-------------------------
echo "-------------------------正在检查网络连接情况-------------------------" | $saveresult
netstat=$(netstat -anlp | grep ESTABLISHED)
netstatnum=$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
if [ -n "$netstat" ];then
	(echo "[*]网络连接情况:" && echo "$netstat") | $saveresult
	if [ -n "$netstatnum" ];then
		(echo "[*]各个状态的数量如下:" && echo "$netstatnum") | $saveresult
	fi
else
	echo "[*]未发现网络连接" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------进程分析-------------------------
echo "-------------------------正在检查进程-------------------------" | $saveresult
ps=$(ps -aux)
if [ -n "$ps" ];then
	(echo "[*]系统进程如下:" && echo "$ps") | $saveresult
else
	echo "[*]未发现系统进程" | $saveresult
fi
printf "\n" | $saveresult

echo "-------------------------正在检查守护进程-------------------------" | $saveresult
if [ -e /etc/xinetd.d/rsync ];then
	(echo "[*]系统守护进程:" && more /etc/xinetd.d/rsync | grep -v "^#") | $saveresult
else
	echo "[*]未发现守护进程" | $saveresult
fi
printf "\n" | $saveresult

echo "-------------------------正在检查隐藏进程-------------------------" | $saveresult
hiddenps=$(ps -ef|awk '{print}' |sort -n |uniq >1)
if [ -n "$hiddenps" ];then
	(echo "[*]隐藏进程如下:" && echo "$ps") | $saveresult
else
	echo "[*]未发现隐藏进程" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------可疑进程-------------------------
echo "-------------------------正在检查可疑进程-------------------------" | $saveresult
danger_process=$(ps -aux  | awk '{print $1,$11}' | sort | uniq | grep -E "(ncat|nc|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)$")
if [ -n "$danger_process" ];then
	(echo "[!!!]以下可疑进程,需要人工分析:"  && echo "$danger_process") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑进程" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------启动项-------------------------
echo "-------------------------正在检查用户自定义启动项-------------------------" | $saveresult
chkconfig=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}')
if [ -n "$chkconfig" ];then
	(echo "[*]用户自定义启动项:" && echo "$chkconfig") | $saveresult
else
	echo "[!!!]未发现用户自定义启动项" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------系统自启动项-------------------------
echo "-------------------------正在检查系统自启动项-------------------------" | $saveresult
systemchkconfig=$(systemctl list-unit-files | grep enabled | awk '{print $1}')
if [ -n "$systemchkconfig" ];then
	(echo "[*]系统自启动项如下:" && echo "$systemchkconfig")  | $saveresult
else
	echo "[*]未发现系统自启动项" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------危险启动项-------------------------
echo "-------------------------正在检查危险启动项-------------------------" | $saveresult
dangerstarup=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}' | grep -E "\.(sh|per|py)$")
if [ -n "$dangerstarup" ];then
	(echo "[!!!]发现危险启动项:" && echo "$dangerstarup") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现危险启动项" | $saveresult
fi
printf "\n" | $saveresult


echo -------------------------查看定时任务-------------------------
echo -------------------------系统定时任务分析-------------------------
echo -------------------------查看系统定时任务-------------------------
echo "-------------------------正在分析系统定时任务-------------------------" | $saveresult
syscrontab=$(more /etc/crontab | grep -v "# run-parts" | grep run-parts)
if [ -n "$syscrontab" ];then
	(echo "[!!!]发现存在系统定时任务:" && more /etc/crontab ) | tee -a $danger_file | $saveresult
else
	echo "[*]未发现系统定时任务" | $saveresult
fi
printf "\n" | $saveresult

# if [ $? -eq 0 ]表示上面命令执行成功;执行成功输出的是0；失败非0
#ifconfig  echo $? 返回0，表示执行成功
# if [ $? != 0 ]表示上面命令执行失败

echo -------------------------分析系统可疑定时任务-------------------------
echo "-------------------------正在分析系统可疑任务-------------------------" | $saveresult
dangersyscron=$(egrep "((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)$))"  /etc/cron*/* /var/spool/cron/*)
if [ $? -eq 0 ];then
	(echo "[!!!]发现下面的定时任务可疑,请注意！！！" && echo "$dangersyscron") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑系统定时任务" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------分析用户定时任务-------------------------
echo -------------------------查看用户定时任务-------------------------
echo "-------------------------正在查看用户定时任务-------------------------" | $saveresult
crontab=$(crontab -l)
if [ $? -eq 0 ];then
	(echo "[!!!]发现用户定时任务如下:" && echo "$crontab") | $saveresult
else
	echo "[*]未发现用户定时任务"  | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------查看可疑用户定时任务-------------------------
echo "-------------------------正在分析可疑用户定时任务-------------------------" | $saveresult
danger_crontab=$(crontab -l | egrep "((chmod|useradd|groupadd|chattr)|((wget|curl).*\.(sh|pl|py)))")
if [ $? -eq 0 ];then
	(echo "[!!!]发现可疑定时任务,请注意！！！" && echo "$danger_crontab") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑定时任务" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------关键文件检查-------------------------
echo -------------------------DNS文件检查-------------------------
echo "-------------------------正在检查DNS文件-------------------------" | $saveresult
resolv=$(more /etc/resolv.conf | grep ^nameserver | awk '{print $NF}') 
if [ -n "$resolv" ];then
	(echo "[*]该服务器使用以下DNS服务器:" && echo "$resolv") | $saveresult
else
	echo "[*]未发现DNS服务器" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------hosts文件检查-------------------------
echo "-------------------------正在检查hosts文件-------------------------" | $saveresult
hosts=$(more /etc/hosts)
if [ -n "$hosts" ];then
	(echo "[*]hosts文件如下:" && echo "$hosts") | $saveresult
else
	echo "[*]未发现hosts文件" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------公钥文件检查-------------------------
echo "-------------------------正在检查公钥文件-------------------------" | $saveresult
if [  -e /root/.ssh/*.pub ];then
	echo "[!!!]发现公钥文件,请注意！"  | tee -a $danger_file | $saveresult
else
	echo "[*]未发现公钥文件" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------私钥文件检查-------------------------
echo "-------------------------正在检查私钥文件-------------------------" | $saveresult
if [ -e /root/.ssh/id_rsa ];then
	echo "[!!!]发现私钥文件,请注意！" | tee -a $danger_file | $saveresult
else
	echo "[*]未发现私钥文件" | $saveresult
fi
printf "\n" | $saveresult


echo -------------------------运行服务-------------------------
echo "-------------------------正在检查运行服务-------------------------" | $saveresult
services=$(systemctl | grep -E "\.service.*running" | awk -F. '{print $1}')
if [ -n "$services" ];then
	(echo "[*]以下服务正在运行：" && echo "$services") | $saveresult
else
	echo "[!!!]未发现正在运行的服务！" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------web服务日志路径-------------------------
echo "-------------------------正在检查web服务日志路径-------------------------" | $saveresult
pid=$(ps -aux | grep -E "(apache2|httpd|nginx|tomcat|weblogic)" | awk 'NR==1{print $2}')
webpaths=$(lsof -p $pid |grep log | awk '{print $9}')
for webpath in $webpaths
do
	if [ -n "$webpath" ];then
		(echo "[*]web日志路径如下：" && echo "$webpath") | $saveresult
	else
		echo "[!!!]未发现web服务！" | $saveresult
	fi
	printf "\n" | $saveresult
done


ifconfig -a
if [$? eq 0]; then
	ipadd=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')
else
	ipadd=$(ip a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')
fi


echo -------------------------路由与路由转发-------------------------
echo "-------------------------正在检查路由表-------------------------" | $saveresult
route=$(route -n)
if [ -n "$route" ];then
	(echo "[*]路由表如下:" && echo "$route") | $saveresult
else
	echo "[*]未发现路由器表" | $saveresult
fi
printf "\n" | $saveresult

echo "-------------------------正在分析是否开启转发功能-------------------------" | $saveresult
#数值分析
#1:开启路由转发
#0:未开启路由转发
ip_forward=`more /proc/sys/net/ipv4/ip_forward | gawk -F: '{if ($1==1) print "1"}'`
if [ -n "$ip_forward" ];then
	echo "[!!!]该服务器开启路由转发,请注意！" | tee -a $danger_file  | $saveresult
else
	echo "[*]该服务器未开启路由转发" | $saveresult
fi
printf "\n" | $saveresult



echo -------------------------恶意文件-------------------------
#webshell这一块因为技术难度相对较高,并且已有专业的工具，目前这一块建议使用专门的安全检查工具来实现
#系统层的恶意文件建议使用rootkit专杀工具来查杀,如rkhunter,下载地址:http://rkhunter.sourceforge.net

echo -------------------------最近24小时内变动的文件-------------------------
#查看最近24小时内有改变的文件
(find / -mtime 0 | grep -E "\.(py|sh|per|pl|php|asp|jsp)$") | tee -a $danger_file | $saveresult
printf "\n" | $saveresult


echo -------------------------文件完整性-------------------------
echo -------------------------系统文件完整性-------------------------
#通过取出系统关键文件的MD5值,一方面可以直接将这些关键文件的MD5值通过威胁情报平台进行查询
#另一方面,使用该软件进行多次检查时会将相应的MD5值进行对比,若和上次不一样,则会进行提示

echo "-------------------------正在采集系统关键文件MD5-------------------------"
file="/tmp/linuxcheck_${ipadd}_${date}/sysfile_md5.txt"
if [ -e "$file" ]; then 
	md5sum -c "$file" 2>&1; 
else
	md5sum /usr/bin/awk >> $file
	md5sum /usr/bin/basename >> $file
	md5sum /usr/bin/bash >> $file
	md5sum /usr/bin/cat >> $file
	md5sum /usr/bin/chattr >> $file
	md5sum /usr/bin/chmod >> $file
	md5sum /usr/bin/chown >> $file
	md5sum /usr/bin/cp >> $file
	md5sum /usr/bin/csh >> $file
	md5sum /usr/bin/curl >> $file
	md5sum /usr/bin/cut >> $file
	md5sum /usr/bin/date >> $file
	md5sum /usr/bin/df >> $file
	md5sum /usr/bin/diff >> $file
	md5sum /usr/bin/dirname >> $file
	md5sum /usr/bin/dmesg >> $file
	md5sum /usr/bin/du >> $file
	md5sum /usr/bin/echo >> $file
	md5sum /usr/bin/ed >> $file
	md5sum /usr/bin/egrep >> $file
	md5sum /usr/bin/env >> $file
	md5sum /usr/bin/fgrep >> $file
	md5sum /usr/bin/file >> $file
	md5sum /usr/bin/find >> $file
	md5sum /usr/bin/gawk >> $file
	md5sum /usr/bin/GET >> $file
	md5sum /usr/bin/grep >> $file
	md5sum /usr/bin/groups >> $file
	md5sum /usr/bin/head >> $file
	md5sum /usr/bin/id >> $file
	md5sum /usr/bin/ipcs >> $file
	md5sum /usr/bin/kill >> $file
	md5sum /usr/bin/killall >> $file
	md5sum /usr/bin/kmod >> $file
	md5sum /usr/bin/last >> $file
	md5sum /usr/bin/lastlog >> $file
	md5sum /usr/bin/ldd >> $file
	md5sum /usr/bin/less >> $file
	md5sum /usr/bin/locate >> $file
	md5sum /usr/bin/logger >> $file
	md5sum /usr/bin/login >> $file
	md5sum /usr/bin/ls >> $file
	md5sum /usr/bin/lsattr >> $file
	md5sum /usr/bin/lynx >> $file
	md5sum /usr/bin/mail >> $file
	md5sum /usr/bin/mailx >> $file
	md5sum /usr/bin/md5sum >> $file
	md5sum /usr/bin/mktemp >> $file
	md5sum /usr/bin/more >> $file
	md5sum /usr/bin/mount >> $file
	md5sum /usr/bin/mv >> $file
	md5sum /usr/bin/netstat >> $file
	md5sum /usr/bin/newgrp >> $file
	md5sum /usr/bin/numfmt >> $file
	md5sum /usr/bin/passwd >> $file
	md5sum /usr/bin/perl >> $file
	md5sum /usr/bin/pgrep >> $file
	md5sum /usr/bin/ping >> $file
	md5sum /usr/bin/pkill >> $file
	md5sum /usr/bin/ps >> $file
	md5sum /usr/bin/pstree >> $file
	md5sum /usr/bin/pwd >> $file
	md5sum /usr/bin/readlink >> $file
	md5sum /usr/bin/rpm >> $file
	md5sum /usr/bin/runcon >> $file
	md5sum /usr/bin/sed >> $file
	md5sum /usr/bin/sh >> $file
	md5sum /usr/bin/sha1sum >> $file
	md5sum /usr/bin/sha224sum >> $file
	md5sum /usr/bin/sha256sum >> $file
	md5sum /usr/bin/sha384sum >> $file
	md5sum /usr/bin/sha512sum >> $file
	md5sum /usr/bin/size >> $file
	md5sum /usr/bin/sort >> $file
	md5sum /usr/bin/ssh >> $file
	md5sum /usr/bin/stat >> $file
	md5sum /usr/bin/strace >> $file
	md5sum /usr/bin/strings >> $file
	md5sum /usr/bin/su >> $file
	md5sum /usr/bin/sudo >> $file
	md5sum /usr/bin/systemctl >> $file
	md5sum /usr/bin/tail >> $file
	md5sum /usr/bin/tcsh >> $file
	md5sum /usr/bin/telnet >> $file
	md5sum /usr/bin/test >> $file
	md5sum /usr/bin/top >> $file
	md5sum /usr/bin/touch >> $file
	md5sum /usr/bin/tr >> $file
	md5sum /usr/bin/uname >> $file
	md5sum /usr/bin/uniq >> $file
	md5sum /usr/bin/users >> $file
	md5sum /usr/bin/vmstat >> $file
	md5sum /usr/bin/w >> $file
	md5sum /usr/bin/watch >> $file
	md5sum /usr/bin/wc >> $file
	md5sum /usr/bin/wget >> $file
	md5sum /usr/bin/whatis >> $file
	md5sum /usr/bin/whereis >> $file
	md5sum /usr/bin/which >> $file
	md5sum /usr/bin/who >> $file
	md5sum /usr/bin/whoami >> $file
	md5sum /usr/lib/systemd/s >> $file
	md5sum /usr/local/bin/rkh >> $file
	md5sum /usr/sbin/adduser >> $file
	md5sum /usr/sbin/chkconfi >> $file
	md5sum /usr/sbin/chroot >> $file
	md5sum /usr/sbin/depmod >> $file
	md5sum /usr/sbin/fsck >> $file
	md5sum /usr/sbin/fuser >> $file
	md5sum /usr/sbin/groupadd >> $file
	md5sum /usr/sbin/groupdel >> $file
	md5sum /usr/sbin/groupmod >> $file
	md5sum /usr/sbin/grpck >> $file
	md5sum /usr/sbin/ifconfig >> $file
	md5sum /usr/sbin/ifdown >> $file
	md5sum /usr/sbin/ifup >> $file
	md5sum /usr/sbin/init >> $file
	md5sum /usr/sbin/insmod >> $file
	md5sum /usr/sbin/ip >> $file
	md5sum /usr/sbin/lsmod >> $file
	md5sum /usr/sbin/lsof >> $file
	md5sum /usr/sbin/modinfo >> $file
	md5sum /usr/sbin/modprobe >> $file
	md5sum /usr/sbin/nologin >> $file
	md5sum /usr/sbin/pwck >> $file
	md5sum /usr/sbin/rmmod >> $file
	md5sum /usr/sbin/route >> $file
	md5sum /usr/sbin/rsyslogd >> $file
	md5sum /usr/sbin/runlevel >> $file
	md5sum /usr/sbin/sestatus >> $file
	md5sum /usr/sbin/sshd >> $file
	md5sum /usr/sbin/sulogin >> $file
	md5sum /usr/sbin/sysctl >> $file
	md5sum /usr/sbin/tcpd >> $file
	md5sum /usr/sbin/useradd >> $file
	md5sum /usr/sbin/userdel >> $file
	md5sum /usr/sbin/usermod >> $file
	md5sum /usr/sbin/vipw >> $file
fi
printf "\n" | $saveresult


echo -------------------------日志分析------------------------------
echo -------------------------查看日志配置与打包-------------------------
echo -------------------------查看日志配置-------------------------
echo "-------------------------正在查看日志配置-------------------------" | $saveresult
logconf=$(more /etc/rsyslog.conf | egrep -v "#|^$")
if [ -n "$logconf" ];then
	(echo "[*]日志配置如下:" && echo "$logconf") | $saveresult
else
	echo "[!!!]未发现日志配置文件" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------日志是否存在-------------------------
echo "-------------------------正在分析日志文件是否存在-------------------------" | $saveresult
logs=$(ls -l /var/log/)
if [ -n "$logs" ];then
	echo "[*]日志文件存在" | $saveresult
else
	echo "[!!!]日志文件不存在,请分析是否被清除！" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------日志审核是否开启-------------------------
echo "-------------------------正在分析日志审核是否开启-------------------------" | $saveresult
service auditd status | grep running
if [ $? -eq 0 ];then
	echo "[*]系统日志审核功能已开启,符合要求" | $saveresult
else
	echo "[!!!]系统日志审核功能已关闭,不符合要求,建议开启日志审核。可使用以下命令开启:service auditd start" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------打包日志-------------------------
echo "-------------------------正在打包日志-------------------------." | $saveresult
zip -r ${log_file}system_log.zip /var/log/
if [ $? -eq 0 ];then
	echo "[*]日志打包成功" | $saveresult
else
	echo "[!!!]日志打包失败,请工人导出日志" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------secure日志分析-------------------------
echo -------------------------成功登录-------------------------
echo "-------------------------正在检查日志中成功登录的情况-------------------------" | $saveresult
loginsuccess=$(more /var/log/secure* /var/log/auth.log | grep "Accepted password" | awk '{print $1,$2,$3,$(NF-3),$NF}')
if [ -n "$loginsuccess" ];then
	(echo "[*]日志中分析到以下用户成功登录:" && echo "$loginsuccess")  | $saveresult
	(echo "[*]登录成功的IP及次数如下：" && grep "Accepted " /var/log/secure* /var/log/auth.log | awk '{print $NF}' | sort -nr | uniq -c )  | $saveresult
	(echo "[*]登录成功的用户及次数如下:" && grep "Accepted" /var/log/secure* /var/log/auth.log | awk '{print $(NF-3)}' | sort -nr | uniq -c )  | $saveresult
else
	echo "[*]日志中未发现成功登录的情况" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------登录失败-------------------------
echo "-------------------------存在检查日志中登录失败的情况-------------------------" | $saveresult
loginfailed=$(more /var/log/secure* /var/log/auth.log | grep "Failed password" | awk '{print $1,$2,$3,$(NF-3),$NF}')
if [ -n "$loginfailed" ];then
	(echo "[!!!]日志中发现以下登录失败的情况:" && echo "$loginfailed") |  tee -a $danger_file  | $saveresult
	(echo "[!!!]登录失败的IP及次数如下:" && grep "Failed password" /var/log/secure* /var/log/auth.log | awk '{print $NF}' | sort -nr | uniq -c)  | $saveresult
	(echo "[!!!]登录失败的用户及次数如下:" && grep "Failed password" /var/log/secure* /var/log/auth.log | awk '{print $(NF-3)}' | sort -nr | uniq -c)  | $saveresult
else
	echo "[*]日志中未发现登录失败的情况" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------本机登录情况-------------------------
echo "-------------------------正在检查图本机登录情况-------------------------" | $saveresult
systemlogin=$(more /var/log/secure* /var/log/auth.log | grep -E "sshd:session.*session opened" | awk '{print $1,$2,$3,$11}')
if [ -n "$systemlogin" ];then
	(echo "[*]本机登录情况:" && echo "$systemlogin") | $saveresult
	(echo "[*]本机登录账号及次数如下:" && more /var/log/secure* /var/log/auth.log | grep -E "sshd:session.*session opened" | awk '{print $11}' | sort -nr | uniq -c) | $saveresult
else
	echo "[!!!]未发现在本机登录退出情况,请注意！！！" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------新增用户-------------------------
echo "-------------------------正在检查新增用户-------------------------" | $saveresult
newusers=$(more /var/log/secure* /var/log/auth.log | grep "new user"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -n "$newusers" ];then
	(echo "[!!!]日志中发现新增用户:" && echo "$newusers") | tee -a $danger_file | $saveresult
	(echo "[*]新增用户账号及次数如下:" && more /var/log/secure* /var/log/auth.log | grep "new user" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $saveresult
else
	echo "[*]日志中未发现新增加用户" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------新增用户组-------------------------
echo "-------------------------正在检查新增用户组-------------------------" | $saveresult
newgoup=$(more /var/log/secure* /var/log/auth.log | grep "new group"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -n "$newgoup" ];then
	(echo "[!!!]日志中发现新增用户组:" && echo "$newgoup") | tee -a $danger_file | $saveresult
	(echo "[*]新增用户组及次数如下:" && more /var/log/secure* /var/log/auth.log | grep "new group" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $saveresult
else
	echo "[*]日志中未发现新增加用户组" | $saveresult
fi
printf "\n" | $saveresult

echo  "-------------------------挖矿木马检查 -------------------------" | $saveresult
echo  "[*]常规挖矿进程检测" | $saveresult
mining_proccess=$(ps -aux | awk '{print $1,$11}' | sort | uniq | grep "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb|warmup")
mining_autorun=$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f)
if [ -n "$mining_proccess" ] || [ -n "$mining_autorun" ];then
	(echo "[!!!]发现可疑挖矿木马进程:" && echo "$mining_proccess" && echo "$mining_autorun") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑挖矿木马进程" | $saveresult
fi

echo  "Ntpclient 挖矿木马检测" | $saveresult
ntpclient_proccess=$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz|warmup')
ntpclient_file=$(ls -lah /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null)
if [ -n "$ntpclient_proccess" ] || [ -n "$ntpclient_file" ];then
	(echo "[!!!]发现可疑Ntpclient挖矿木马进程:" && echo "$ntpclient_proccess" && echo "$ntpclient_file") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑Ntpclient挖矿木马进程" | $saveresult
fi

echo  "WorkMiner 挖矿木马检测" | $saveresult
workminerps_proccess=$(ps -aux | awk '{print $1,$11}' | sort | uniq | grep "work32|work64|/tmp/secure.sh|/tmp/auth.sh|warmup")
workminerps_file=$(ls -lah /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null)
if [ -n "$workminerps_proccess" ] || [ -n "$workminerps_file" ];then
	(echo "[!!!]发现可疑WorkMiner挖矿木马进程:" && echo "$ntpclient_proccess" && echo "$ntpclient_file") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑WorkMiner挖矿木马进程" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------message日志分析-------------------------
echo -------------------------传输文件-------------------------
#下面命令仅显示传输的文件名,并会将相同文件名的去重
#more /var/log/message* | grep "ZMODEM:.*BPS" | awk -F '[]/]' '{print $0}' | sort | uniq
echo "-------------------------正在检查传输文件-------------------------" | $saveresult
zmodem=$(more /var/log/message* | grep "ZMODEM:.*BPS")
if [ -n "$zmodem" ];then
	(echo "[!!!]传输文件情况:" && echo "$zmodem") | tee -a $danger_file | $saveresult
else
	echo "[*]日志中未发现传输文件" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------历史使用DNS服务器-------------------------
echo "-------------------------正在检查日志中使用DNS服务器的情况-------------------------" | $saveresult
dns_history=$(more /var/log/messages* | grep "using nameserver" | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq)
if [ -n "$dns_history" ];then
	(echo "[!!!]该服务器曾经使用以下DNS:" && echo "$dns_history") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现使用DNS服务器" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------cron日志分析-------------------------
echo -------------------------定时下载-------------------------
echo "-------------------------正在分析定时下载-------------------------" | $saveresult
cron_download=$(more /var/log/cron* | grep "wget|curl")
if [ -n "$cron_download" ];then
	(echo "[!!!]定时下载情况:" && echo "$cron_download") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现定时下载情况" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------定时执行脚本-------------------------
echo "-------------------------正在分析定时执行脚本-------------------------" | $saveresult
cron_shell=$(more /var/log/cron* | grep -E "\.py$|\.sh$|\.pl$") 
if [ -n "$cron_shell" ];then
	(echo "[!!!]发现定时执行脚本:" && echo "$cron_download") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现定时下载脚本" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------dmesg日志分析-------------------------
echo -------------------------内核自检日志-------------------------
echo "-------------------------正在查看内核自检日志-------------------------" | $saveresult
dmesg=$(dmesg)
if [ $? -eq 0 ];then
	(echo "[*]日志自检日志如下：" && "$dmesg" ) | $saveresult
else
	echo "[*]未发现内核自检日志" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------btmp日志分析-------------------------
echo -------------------------错误登录日志分析-------------------------
echo "-------------------------正在分析错误登录日志-------------------------" | $saveresult
lastb=$(lastb)
if [ -n "$lastb" ];then
	(echo "[*]错误登录日志如下:" && echo "$lastb") | $saveresult
else
	echo "[*]未发现错误登录日志" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------lastlog日志分析-------------------------
echo -------------------------所有用户最后一次登录日志分析-------------------------
echo "-------------------------正在分析所有用户最后一次登录日志-------------------------" | $saveresult
lastlog=$(lastlog)
if [ -n "$lastlog" ];then
	(echo "[*]所有用户最后一次登录日志如下:" && echo "$lastlog") | $saveresult
else
	echo "[*]未发现所有用户最后一次登录日志" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------wtmp日志分析-------------------------
echo -------------------------所有登录用户分析-------
echo "-------------------------正在检查历史上登录到本机的用户:" | $saveresult
lasts=$(last | grep pts | grep -vw :0)
if [ -n "$lasts" ];then
	(echo "[*]历史上登录到本机的用户如下:" && echo "$lasts") | $saveresult
else
	echo "[*]未发现历史上登录到本机的用户信息" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------内核检查-------------------------
echo -------------------------内核情况-------------------------
echo "-------------------------正在检查内核信息-------------------------." | $saveresult
lsmod=$(lsmod)
if [ -n "$lsmod" ];then
	(echo "[*]内核信息如下:" && echo "$lsmod") | $saveresult
else
	echo "[*]未发现内核信息" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------可疑内核检查-------------------------
echo "-------------------------正在检查可疑内核-------------------------" | $saveresult
danger_lsmod=$(lsmod | grep -Ev "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state")
if [ -n "$danger_lsmod" ];then
	(echo "[!!!]发现可疑内核模块:" && echo "$danger_lsmod") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑内核模块" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------环境变量-------------------------
echo "-------------------------正在检查环境变量-------------------------" | $saveresult
env=$(env)
if [ -n "$env" ];then
	(echo "[*]环境变量:" && echo "$env") | $saveresult
else
	echo "[*]未发现环境变量" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------性能分析-------------------------
echo -------------------------磁盘分析-------------------------
echo -------------------------磁盘使用-------------------------
echo "-------------------------正在检查磁盘使用-------------------------" | $saveresult
echo "[*]磁盘使用情况如下:" && df -h  | $saveresult
printf "\n" | $saveresult

echo -------------------------检查磁盘使用过大-------------------------
echo "-------------------------正在检查磁盘使用是否过大-------------------------" | $saveresult
#使用超过70%告警
df=$(df -h | awk 'NR!=1{print $1,$5}' | awk -F% '{print $1}' | awk '{if ($2>70) print $1,$2}')
if [ -n "$df" ];then
	(echo "[!!!]硬盘空间使用过高，请注意！！！" && echo "$df" ) | tee -a $danger_file | $saveresult
else
	echo "[*]硬盘空间足够" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------CPU分析-------------------------
echo -------------------------CPU情况-------------------------
echo "-------------------------正在检查CPU相关信息-------------------------" | $saveresult
(echo "CPU硬件信息如下:" && more /proc/cpuinfo ) | $saveresult
(echo "CPU使用情况如下:" && ps -aux | sort -nr -k 3 | awk  '{print $1,$2,$3,$NF}') | $saveresult
printf "\n" | $saveresult

echo -------------------------占用CPU前5进程-------------------------
echo "-------------------------正在检查占用CPU前5资源的进程-------------------------" | $saveresult
(echo "占用CPU资源前5进程：" && ps -aux | sort -nr -k 3 | head -5)  | $saveresult
printf "\n" | $saveresult

echo -------------------------占用CPU较大进程-------------------------
echo "-------------------------正在检查占用CPU较大的进程-------------------------" | $saveresult
pscpu=$(ps -aux | sort -nr -k 3 | head -5 | awk '{if($3>=20) print $0}')
if [ -n "$pscpu" ];then
	echo "[!!!]以下进程占用的CPU超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD" 
	echo "$pscpu" | tee -a 20.2.3_pscpu.txt | tee -a $danger_file | $saveresult
else
	echo "[*]未发现进程占用资源超过20%" | $saveresult
fi
printf "\n" | $saveresult

echo -------------------------内存分析-------------------------
echo -------------------------内存情况-------------------------
echo "-------------------------正在检查内存相关信息-------------------------" | $saveresult
(echo "[*]内存信息如下:" && more /proc/meminfo) | $saveresult
(echo "[*]内存使用情况如下:" && free -m) | $saveresult
printf "\n" | $saveresult

echo -------------------------占用内存前5进程-------------------------
echo "-------------------------正在检查占用内存前5资源的进程-------------------------" | $saveresult
(echo "[*]占用内存资源前5进程：" && ps -aux | sort -nr -k 4 | head -5) | $saveresult
printf "\n" | $saveresult

echo -------------------------占用内存较多进程-------------------------
echo "-------------------------正在检查占用内存较多的进程-------------------------" | $saveresult
psmem=$(ps -aux | sort -nr -k 4 | head -5 | awk '{if($4>=2) print $0}')
if [ -n "$psmem" ];then
	echo "[!!!]以下进程占用的内存超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD"
	echo "$psmem" | tee -a $danger_file | $saveresult
else
	echo "[*]未发现进程占用内存资源超过20%" | $saveresult
fi
printf "\n" | $saveresult


echo -------------------------其他-------------------------
echo -------------------------运行时间及负载-------------------------
echo "-------------------------正在检查系统运行时间及负载情况-------------------------." | $saveresult
(echo "[*]系统运行时间如下:" && uptime) | $saveresult
printf "\n" | $saveresult

echo "-------------------------正在将检查文件压缩到/tmp/目录下-------------------------."
zip -r /tmp/linuxcheck_${ipadd}_${date}.zip /tmp/linuxcheck_${ipadd}_${date}/*

echo "检查结束！！！"
endTime_s=`date +%s`
sumTime=$((endTime_s-startTime_s))
echo "脚本执行时长:$sumTime 秒"