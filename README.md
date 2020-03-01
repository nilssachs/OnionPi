# OnionPi
Using a Raspberry Pi as Sensor feeding into a Security Onion Server

# Install Raspbian Buster

# Upgrade and Change Hostname
apt update && apt upgrade

sudo nano /etc/hostname
	
	onionpi
  
# Install Software Packages
apt install git raspberrypi-kernel-headers cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev autoconf

# Install PF_RING
git clone https://github.com/ntop/PF_RING.git

cd PF_RING/kernel

make

sudo make install

cd ../PF_RING/userland/lib

./configure

make

make install	

cd ../libpcap

./configure

make 

make install

cd ../tcpdump-4.9.2

./configure

make

make install

# Network Config
nano /etc/network/interfaces

	allow-hotplug lo
	iface lo inet loopback

	#Configure Management interface using DHCP 
	allow-hotplug eth0
	iface eth0 inet dhcp
	allow-hotplug eth1
	iface eth1 inet manual
	  up ifconfig $IFACE -arp up
	  up ip link set $IFACE promisc on
	  down ip link set $IFACE promisc off
	  down ifconfig $IFACE down
	  post-up for i in rx tx sg tso ufo gso gro lro; do ethtool -K $IFACE $i off; done
	  # Disable IPv6:
	  post-up echo 1 > /proc/sys/net/ipv6/conf/$IFACE/disable_ipv6
    
# Install Snort
apt-get install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev libnghttp2-dev libluajit-5.1-dev libtool


mkdir snort

wget https://snort.org/downloads/snort/daq-2.0.6.tar.gz

tar -xvzf daq-2.0.6.tar.gz

cd daq-2.0.6

./configure

make

sudo make install

cd ..

wget https://snort.org/downloads/snort/snort-2.9.15.tar.gz

tar -xvzf snort-2.9.15.tar.gz

cd snort-2.9.15

./configure --enable-sourcefire --prefix=/nsm/snort

make

sudo make install

sudo ldconfig

sudo ln -s /nsm/snort/bin/snort /usr/sbin/snort

# Snort Config
sudo groupadd nsm

sudo useradd nsm -r -s /sbin/nologin -c NSM_USER -g nsm

#Create the Snort directories:

sudo mkdir /nsm/snort/rules

sudo mkdir /nsm/snort/rules/iplists

sudo mkdir /nsm/snort/preproc_rules

sudo mkdir /nsm/snort/lib/snort_dynamicrules

sudo mkdir /nsm/snort/so_rules

#Create some files that stores rules and ip lists

sudo touch /nsm/snort/rules/iplists/black_list.rules

sudo touch /nsm/snort/rules/iplists/white_list.rules

sudo touch /nsm/snort/rules/local.rules

sudo touch /nsm/snort/sid-msg.map

#Create our logging directories:

sudo mkdir /var/log/snort

sudo mkdir /var/log/snort/archived_logs

#Adjust permissions:

sudo chmod -R 5775 /nsm/snort

sudo chmod -R 5775 /var/log/snort

sudo chmod -R 5775 /var/log/snort/archived_logs

sudo chmod -R 5775 /nsm/snort/so_rules

sudo chmod -R 5775 /nsm/snort/lib/snort_dynamicrules

#Change Ownership on folders:

sudo chown -R nsm:nsm /nsm/snort

sudo chown -R nsm:nsm /var/log/snort

sudo chown -R nsm:nsm /nsm/snort/lib/snort_dynamicrules

cd /home/pi/tmp/snort/snort-2.9.15/etc/

sudo cp *.conf* /nsm/snort

sudo cp *.map /nsm/snort

sudo cp *.dtd /nsm/snort

cd ../src/dynamic-preprocessors/build/nsm/snort/lib/snort_dynamicpreprocessor/
´
sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf

nano /nsm/snort/snort.conf

	var WHITE_LIST_PATH /nsm/snort/rules/iplists
	var BLACK_LIST_PATH /nsm/snort/rules/iplists
	var RULE_PATH /nsm/snort/rules
	var SO_RULE_PATH /nsm/snort/so_rules
	var PREPROC_RULE_PATH /nsm/snort/preproc_rules
	Uncomment: include $RULE_PATH/local.rules
	# path to dynamic preprocessor libraries
	dynamicpreprocessor directory /nsm/snort/lib/snort_dynamicpreprocessor/
	# path to base preprocessor engine
	dynamicengine /nsm/snort/lib/snort_dynamicengine/libsf_engine.so
	# path to dynamic rules libraries
	dynamicdetection directory /nsm/snort/lib/snort_dynamicrules	
	output unified2: filename snort.u2, limit 128
  
# Barnyard Install
sudo apt install tcl tcl8.6-dev tcl-tls

cd /home/pi/tmp

wget https://github.com/firnsy/barnyard2/archive/master.tar.gz -O barnyard2-Master.tar.gz

tar zxvf barnyard2-Master.tar.gz

cd barnyard2-master

autoreconf -fvi -I ./m4

sudo ln -s /usr/include/dumbnet.h /usr/include/dnet.h

sudo ldconfig

./configure --with-tcl=/usr/lib/tcl8.6

make

sudo make install

sudo cp /home/pi/tmp/barnyard2-master/etc/barnyard2.conf /nsm/snort/ 

#the /var/log/barnyard2 folder is never used or referenced

#but barnyard2 will error without it existing

sudo mkdir /var/log/barnyard2

sudo chown nsm:nsm /var/log/barnyard2 

sudo touch /nsm/snort/barnyard2.waldo

sudo chown nsm:nsm /nsm/snort/barnyard2.waldo

cd /home/pi/tmp/PF_RING/userland/snort/pfring-daq-module

autoreconf -ivf

./configure

make

sudo make install

# Snort Service
nano /lib/systemd/system/snort.service

	[Unit]
	Description=Snort NIDS Daemon
	After=syslog.target network.target

	[Service]
	Type=simple
	ExecStart=/usr/sbin/snort --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode pas-sive -q -u nsm -g nsm -c /nsm/snort/snort.conf -i eth0
	[Install]
	WantedBy=multi-user.target

systemctl enable snort.service

nano /lib/systemd/system/barnyard2.service

	[Unit]
	Description=Barnyard2 Daemon
	After=syslog.target network.target
	[Service]
	Type=simple
	ExecStart=/usr/sbin/barnyard2 -c /nsm/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /nsm/snort/barnyard2.waldo -g nsm -u nsm
	[Install]
	WantedBy=multi-user.target

systemctl enable barnyard2.service

cp snort_agent.tcl /usr/bin/

cp snort_agent.conf /nsm/snort/

nano /lib/systemd/system/snortagent.service

	[Unit]
	Description=SnortAgent Daemon
	After=syslog.target network.target
	Requires=snort.service
	[Service]
	Type=simple
	ExecStart=/usr/bin/tclsh /usr/bin/snort_agent.tcl -c /nsm/snort/snort_agent.conf
	[Install]
	WantedBy=multi-user.target

systemctl enable snortagent.service	

# Install Zeek

wget https://www.zeek.org/downloads/zeek-3.0.1.tar.gz

tar xvzf zeek-3.0.1.tar.gz

cd zeek-3.0.1

./configure --with-pcap=/usr/local/lib --prefix=/nsm/zeek

make

sudo make install

sudo ln -s /nsm/zeek/bin/zeek /usr/sbin/zeek

sudo ln -s /nsm/zeek/bin/zeekctl /usr/sbin/zeekctl

sudo mkdir /var/log/zeek

sudo mkdir /var/log/zeek/logs

nano /nsm/zeek/etc/networks.cfg

	Configure IP Spaces

nano /nsm/zeek/etc/node.cfg

	[logger]
	type=logger
	host=localhost
	#
	[manager]
	type=manager
	host=localhost
	#
	[proxy]
	type=proxy
	host=localhost
	#
	[worker]
	type=worker
	host=localhost
	interface=eth1
	lb_method=pf_ring
	lb_procs=1
	pin_cpus=0

nano /nsm/zeek/etc/zeekctl.cfg

	MailTo = root@localhost
	MailConnectionSummary = 1
	MinDiskSpace = 5
	MailHostUpDown = 1
	LogRotationInterval = 3600
	LogExpireInterval = 0
	StatsLogEnable = 1
	StatsLogExpireInterval = 0
	StatusCmdShowAll = 0
	CrashExpireInterval = 0
	SitePolicyScripts = local.zeek
	LogDir = /var/log/zeek/logs
	SpoolDir = /nsm/zeek/spool
	CfgDir = /nsm/zeek/etc

sudo nano /lib/systemd/system/zeek.service

	[Unit]
	Description=Zeek
	After=network.target
	[Service]
	ExecStartPre=/usr/sbin/zeekctl cleanup
	ExecStartPre=/usr/sbin/zeekctl check
	ExecStartPre=/usr/sbin/zeekctl install
	ExecStart=/usr/sbin/zeekctl start
	ExecStop=/usr/sbin/zeekctl stop
	RestartSec=10s
	Type=oneshot
	RemainAfterExit=yes
	TimeoutStopSec=600

	[Install]
	WantedBy=multi-user.target

sudo systemctl enable zeek.service

sudo systemctl start zeek.service
		
# Configure SSH – Autossh
ssh-keygen

ssh-copy-id -i /root/.ssh/id_rsa.pub user@server

ssh user@server -for testing

sudo apt install autossh

sudo nano /lib/systemd/system/autossh.service

	[Unit]
	Description=autossh
	Wants=network-online.target
	After=network-online.target
	[Service]
	#Type=simple
	ExecStart=/usr/bin/autossh -M 0 -q -N -o "ServerAliveInterval 60" -o "Server-AliveCountMax 3" -o "ExitOnForwardFailure yes" -i /root/.ssh/id_rsa -L 6050:localhost:6050 admin@192.168.178.62
	Restart=always
	RestartSec=60
	[Install]
	WantedBy=multi-user.target

sudo ln -s /lib/systemd/system/autossh.service /etc/systemd/system/autossh.service

sudo systemctl daemon-reload

sudo systemctl enable autossh

# Install Syslog-NG
sudo apt install syslog-ng

sudo nano /etc/syslog-ng/syslog-ng.conf

	##see syslog.conf

sudo nano /lib/systemd/system/syslog-ng.service

	[Unit]
	Description=System Logger Daemon
	Documentation=man:syslog-ng(8)
	[Service]
	Type=notify
	Sockets=syslog.socket
	ExecStart=/usr/sbin/syslog-ng -F
	ExecReload=/bin/kill -HUP $MAINPID
	StandardOutput=null
	Restart=on-failure
	[Install]
	WantedBy=multi-user.target
	Alias=syslog.service

sudo systemctl daemon-reload

sudo systemctl restart syslog-ng

# (Optional) Install Intel Stack
Register and Create API Key

curl https://packagecloud.io/install/repositories/intelstack/client/script.deb.sh | sudo bash

sudo apt-get install intel-stack-client

sudo -u intel-stack-client -g intel-stack-client intel-stack-client nsm zeek

sudo -u intel-stack-client -g intel-stack-client intel-stack-client api "yourapikey"

sudo chown intel-stack-client:intel-stack-client /opt/intel-stack-client

sudo -u intel-stack-client intel-stack-client config --set=nsm.zeek=true

sudo -u intel-stack-client intel-stack-client config --set zeek.restart=true

sudo -u intel-stack-client -g intel-stack-client intel-stack-client config --#set=zeek.zeekctl.path=/usr/sbin/zeekctl

sudo -u intel-stack-client -g intel-stack-client intel-stack-client config --#set=zeek.path=/nsm/zeek	

sudo touch /etc/sudoers.d/99-intel-stack-client

sudo chmod 0440 /etc/sudoers.d/99-intel-stack-client

sudo nano /etc/sudoers.d/99-intel-stack-client

	# User privilege specification
	agaida  ALL=(ALL:ALL) ALL

sudo -u intel-stack-client -g intel-stack-client intel-stack-client pull

sudo nano /nsm/zeek/share/zeek/site/local.zeek

	@load base/frameworks/intel
	@load frameworks/intel/seen
	@load frameworks/intel/do_notice
	redef Intel::read_files += {
	     "/opt/intel-stack-client/frameworks/intel/master-public.dat"
	};

systemctl restart zeek

# (Optional) Install nProbe
wget http://packages.ntop.org/RaspberryPI/apt-ntop_1.0.190416-469_all.deb

sudo dpkg -i apt-ntop_1.0.190416-469_all.deb

sudo apt-get install nprobe

# (Optional) Additional ICS Zeek Packages
wget https://bootstrap.pypa.io/get-pip.py

python get-pip.py

pip install GitPython

pip install semantic-version

pip install btest

pip install configparser

pip install zkg

ln -s /nsm/zeek/bin/zeek-config /usr/sbin/zeek-config

zkg autoconfig

cd /home/pi/tmp/zeek-3.0.1/aux/bifcl

make

sudo make install

ln -s /nsm/zeek/bin/bifcl /usr/sbin/bifcl

zkg install zeek-plugin-s7comm

zkg install zeek-plugin-profinet

zkg install zeek-plugin-enip

zkg install zeek-plugin-bacnet

zkg install zeek-plugin-tds

sudo nano /nsm/zeek/share/zeek/site/local.zeek

	add "@load packages"
  
# Install Salt
On Sensor:

apt install salt-minion

echo "master: <ServerIP>" | sudo tee -a /etc/salt/minion.d/onionsalt.conf

sudo service salt-minion restart

On Master:

#Edit /opt/onionsalt/salt/top.sls and add the new minion as a "sensor"

#list the salt keys:

sudo salt-key -L

#You should see an unaccepted salt key for the sensor, add it:

sudo salt-key -a '*'

#Verify that the master can communicate with all minions:

sudo salt '*' test.ping
