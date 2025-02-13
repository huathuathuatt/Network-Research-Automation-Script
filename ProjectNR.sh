#!/bin/bash
#~ Name:Muhammad Fuad Bin Zulkifli
#~ Student Code:S13
#~ Unit Code:CFC060524
#~ Trainer Name:Samson

#Log file output path
LOGENTRIES="/var/log/nr.log"

#Function to log scan entries
function log_entry()
{
    local DOMAIN=$1
    local SCAN_TYPE=$2
    local TIMESTAMP=$(date '+%a %b %d %T %Z %Y')
    
    case "$SCAN_TYPE" in
        whois)
            echo "$TIMESTAMP - [*] Whois data collected for: $DOMAIN" >> $LOGENTRIES
            ;;
        nmap)
            echo "$TIMESTAMP - [*] Nmap data collected for: $DOMAIN" >> $LOGENTRIES
            ;;
       
    esac
}

#NIPE Directory
NIPE_DIR="/home/kali/nipe"

#Variables to check for required applications.
Geoipbin=$(dpkg --status geoip-bin)
sshpass=$(dpkg --status sshpass)
Tor=$(dpkg --status tor)
NIPE=$(dpkg --status nipe)
Pkgchecker=$(dpkg --status checkinstall)
Cpanminus=$(dpkg --status cpanminus)


#Check required for applications and install if necessary.
if [[ $Geoipbin == *"Status: install ok installed"* ]] 					
then
	echo '[#] Geoip-bin is already installed.'
else
	echo 'Geoipbin is not installed'
	sleep 1
	echo 'Installing Geoip-bin....'
	sleep 1
	sudo apt-get update > /dev/null 2>&1 
	sleep 1
	sudo apt-get install --assume-yes geoip-bin > /dev/null 2>&1 
	echo 'Geoip-bin is installed.'
fi

if [[ $Tor == *"Status: install ok installed"* ]]
then
	echo '[#] Tor is already installed.'
else
	echo 'Tor is not installed'
	sleep 1
	echo 'Installing Tor....'
	sleep 1
	sudo apt-get update > /dev/null 2>&1 
	sleep 1
	sudo apt-get install --assume-yes tor > /dev/null 2>&1 
	echo 'Tor is installed.'
fi

if [[ $sshpass == *"Status: install ok installed"* ]]
then
	echo '[#] sshpass is already installed'
else
	echo 'sshpass is not install'
	sleep 1
	echo 'Installing sshpass....'
	sleep 1
	sudo apt-get update > /dev/null 2>&1 
	sleep 1
	sudo apt-get install --assume-yes sshpass > /dev/null 2>&1 
	echo 'sshpass is installed'
fi

if [[ $Pkgchecker == *"Status: install ok installed"* ]]		
then
	echo '[#] checkinstall is already installed' 
else
	echo 'Installing checkinstall....'
	sleep 1
	sudo apt-get install --assume-yes checkinstall > /dev/null 2>&1 	
	echo 'checkinstall is installed'
fi

if [[ $NIPE == *"Status: install ok installed"* ]]
then
	echo '[#] Nipe is already installed.'
else
	echo 'NIPE is not install'
	sleep 1
	echo 'Installing NIPE....'
	if [[ $Cpanminus == *"Status: install ok installed"* ]]
	then
	echo > /dev/null 2>&1
	else
		sudo apt-get update > /dev/null 2>&1
		sleep 1 
		sudo apt-get -y install cpanminus > /dev/null 2>&1
	fi
	sleep 1
	git clone https://github.com/htrgouvea/nipe > /dev/null 2>&1
	sleep 1
	cd "$NIPE_DIR" || { echo "Failed to navigate to Nipe directory."; exit 1; }
	cpanm --installdeps . > /dev/null 2>&1
	sleep 1
	sudo cpan install Switch JSON LWP::UserAgent Config::Simple > /dev/null 2>&1 
	sleep 1
	sudo perl nipe.pl install > /dev/null 2>&1
	cd $NIPE_DIR
	sudo checkinstall --install=no --pkgname=nipe --pkgversion=1.0.0 --default perl nipe.pl install > /dev/null 2>&1 
	sleep 1
	sudo dpkg --install nipe_1.0.0-1_amd64.deb > /dev/null 2>&1 
	echo 'Nipe is installed'
fi

#Navigitating and powering NIPE
cd "$NIPE_DIR" || { echo "Failed to navigate to Nipe directory."; exit 1; }
sudo perl nipe.pl start
sleep 2
status=$(sudo perl nipe.pl status)

#checking if the user is connected or not.
if [[ $status == *"Status: true"* ]]
then
	echo '[*] You are anonymous.. Connecting to the remote Sever.'
else
	echo '**** you are not connected anonymously. Goodbye ****'
	exit
fi
echo

#Variables for getting the spoofed IP address and country using ifconfig.io and geoiplookup
IP=$(curl --silent ifconfig.io)
country=$(geoiplookup $IP | awk '{print $5}')
echo "[*] Your Spoofed IP address is: $IP , Spoofed country: $country"
read -p "[?] Specify a Domain/IP address to scan: " Domain


#Variables for connecting to Remote Serversudo 
USER="tc"
PASS="tc"
REMOTE_SERVER="192.168.225.129"

#Variables for the output
OUTPUT="Nmap_$Domain.txt"

#4. Connect to a remote server(`Ubuntu`)  via ssh. (`sshpass`)
# 1. We will then scan the domain/url provided by the user FROM THE REMOTE SERVER
#2. Save the result of the scan onto the remote server(Ubuntu)
sshpass -p $PASS ssh -T -o StrictHostKeyChecking=no $USER@$REMOTE_SERVER <<EOF > /dev/null 2>&1
nmap -Pn -sV $Domain -oN $OUTPUT
EOF

#Log the nmap scan
log_entry $Domain "nmap"

#function to navigate back to HOME directory
function HOMEDIRECTORY()
{
	cd /home/kali
}

#Navigate to Home Directory to execute file transfer using SCP to the current directory
#3. Retrieve the results of the scan from your local machine(Kali)
HOMEDIRECTORY
ftp -n -V $REMOTE_SERVER <<EOF
user $USER $PASS
cd /home/tc
get $OUTPUT
exit
EOF

#Variables for Whois command
Whois=$(whois $Domain | grep 'Address' | awk -F: '{print $2}' | head -n 1 | tr -s ' ')
Whoiscountry=$(whois $Domain | grep 'Country' | awk -F: '{print $2}' | tr -s ' ')
Whoisdata="/home/kali/whois_$Domain.txt"

#Execute the WHOIS command and save the output to the file path
whois $Domain > "$Whoisdata"

#Log the whois lookup
log_entry $Domain "whois"

#Extracted information from WHOIS & NMAP and their file saving path.
echo "[*] Whoising victim's address:$Whoiscountry , $Whois"
echo "[@] Whois data was saved into: $Whoisdata"
echo
echo "Scanning victim's address:$Domain"
echo "[@] Nmap scan was saved into /home/kali/$OUTPUT"
