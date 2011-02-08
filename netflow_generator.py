#!/usr/bin/env python2

# Python NetFlow Collector
#
# Copyright (C) 2011 pynetflow Project
# Author: Choonho Son <choonho@kt.com>
# URL: <http://pynetflow.googlecode.com>
# For license information, see LICENSE.TXT
#

import time
import datetime
import socket
import Queue
import threading
import signal
import struct
import SocketServer
import random
from random import randint
from threading import Thread
from optparse import OptionParser
from dpkt.netflow import *

# Global variable
count = 0
port = 9996
network = []          # [(nw1,subnet1), (nw2,subnet2) ...]
verbose = False
SIZE_OF_HEADER = 24   # Netflow v5 header size
SIZE_OF_RECORD = 48   # Netflow v5 record size
ONEDAY_SECOND = 86400 # 60 second * 60 minute * 24 hours
NUM_OF_TIMELINE_INDEX = 288     # 5 minute slot (86400 / 60*5)
UPLINK = 0            # UPLINK of timeline 
DOWNLINK = 1          # DOWNLINK of timeline
MAX_PCOUNT = 50
MAX_BCOUNT = 300000

NETMASK = {0: socket.inet_aton("255.255.255.255"),
           8: socket.inet_aton("0.255.255.255"),
           16: socket.inet_aton("0.0.255.255"),
           24: socket.inet_aton("0.0.0.255"),
}

# Data Structure of Final Result
DataStructure = {}

# Queue
queue_netflow = Queue.Queue()

# SIGNAL
WORKING = True
LOCK = threading.Lock()
STOP = 0

def debug(value, comment=''):
    if verbose == True:
        print "[DEBUG %s] %s" % (comment, value)

class Signalled(Exception):
    # Finalize queue_netflow
    debug("Finalize queue_netflow")
    #queue_netflow.put(False)


def sigBreak(signum, f):
    global STOP
    LOCK.acquire()
    STOP = 1
    LOCK.release()
    raise Signalled

class Netflow_Generator(Thread):
    def __init__(self, nw, delta=1, interval=1, host='127.0.0.1', port=9997):
        # delta => subnet (1=/24, 2=/16, 3=/8)
        # interval : sleeping time
        threading.Thread.__init__(self)
        self.nw = nw
        self.delta = delta
        self.interval = interval
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 

    def run(self):
        debug("Start Netflow Generator...")
        global count
        while STOP == 0:
            (t_uptime, idletime) = open("/proc/uptime").read().split()
            uptime = int(t_uptime.split(".")[0])
            epoch = int(str(time.time()).split(".")[0])
            debug(epoch,"epoch")
            new_count = random.randint(1,30)
            records = ""
            total_bytes = 0
            for index in range(new_count):
                inout = randint(0,2)
                nip = IPToInt(self.nw)
                sip = randint(nip, nip+255)
                dip = randint(0,255*255*255*255)
                pcount = randint(1, MAX_PCOUNT)
                bcount = randint(100, MAX_BCOUNT)
                total_bytes = total_bytes + bcount
                stime = uptime - randint(1,300)
                etime = stime + randint(1,300)
                sport = randint(0,10000)
                dport = randint(0,10000)
                proto = randint(0,17)
                if inout == 0:
                    debug("uplink")
                    saddr = sip
                    daddr = dip
                else:
                    debug("downlink")
                    saddr = dip
                    daddr = sip

                record = Netflow5.NetflowRecord(src_addr=saddr,dst_addr=daddr,pkts_sent=pcount,bytes_sent=bcount,start_time=stime, end_time=etime,src_port=sport,dst_port=dport,ip_proto=proto)

                records = records + record.pack()
            packet = Netflow5(version=5, sys_uptime=uptime, unix_sec = epoch, data=records)
            #packet = Netflow5(version=5 )
            # Send data
            self.sock.sendto(packet.pack(),(self.host, self.port))
            debug("count:%d KBps:%s" % (count, total_bytes / 1000), "Send")
            count = count + 1
            time.sleep(self.interval)

    def make_record(self, sip,dip, uptime):
        pcount = random.randint(1,MAX_PCOUNT)
        bcount = random.randint(1,MAX_BCOUNT)
        delta = random.randint(1,300)
        stime = uptime - delta
        etime = stime + random.randint(1,300)
        sport = random.randint(0,10000)
        dport = random.randint(0,10000)
        proto = random.randint(0,11)
        return struct.pack('4s4sIIIIffHHBBBBII', socket.inet_aton(sip), socket.inet_aton(dip)\
                               ,0,0,pcount,bcount,stime,etime,sport,dport,0,0,proto,0,0,0)

def IPToInt(ip):
    exp = 3
    intip = 0
    for quad in ip.split("."):
        intip = intip + (int(quad) * (256 ** exp))
        exp = exp - 1
    return intip
                
def random_ip_gen(ip, subnet):
    # random ip generation with subnet
    index = ip.split(".")
    a = random.randint(1,255)
    b = random.randint(0,255)
    c = random.randint(0,255)
    d = random.randint(0,255)
    if subnet == 1:
        return "%s.%s.%s.%s" % (index[0],index[1],index[2],d)
    elif subnet == 2:
        return "%s.%s.%s.%s" % (index[0],index[1],c,d)
    elif subnet == 3:
        return "%s.%s.%s.%s" % (index[0],b,c,d)
    else:
        return "%s.%s.%s.%s" % (a,b,c,d)

def startAnalyzer():
    # start threads
    # new
    thr_netflow_generator = Netflow_Generator("220.123.31.0",1,1,"127.0.0.1", 9996)

    # start Thread first
    thr_netflow_generator.start()

    # signal
    try:
        signal.pause()
    except Signalled:
        pass

    # join
    debug("wait Before Join")
    thr_netflow_generator.join()
    debug("finish join")

def add_network(nw):
    #config setting of monitoring network
    temp=nw.split("/")
    return ( socket.inet_aton(temp[0]), int(temp[1]) )

def parse_config(fname):
    # parse configure file
    # return cofig dictionary
    fp = open(fname,'r')
    config = {}
    for index in fp:
        if index[0] == "#" or index[0] == "\n":
            # Comment line
            continue
        line = index.split("\n")
        content = line[0].split(" ")
        if len(content) > 2:
            config[content[0]] = content[1:]
        else:
            config[content[0]] = content[1]
    print config
    return config


def init():
    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config", help="Load Configure file") 
    parser.add_option("-p", "--port", dest="port", help="Netflow Collection UDP port", default="9996")
    parser.add_option("-n", "--network", dest="network", help="Monitoring Network range")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="Debug options")
    (options, args) = parser.parse_args()

    global verbose
    global port
    global network

    if options.verbose:
        verbose = True
    if options.config:
        config = parse_config(options.config)
        if config.has_key('port'):
            # Port Number
            port = int(config['port'])
        if config.has_key('network'):
            networks = config['network']
            for nw in networks:
                network.append( add_network(nw) )
    # Netflow collector UDP Port
    if options.port:
        port = int(options.port)
        debug(port, "UDP port")
    # Monitoring Network Range
    if options.network:
        nw = options.network
        network.append( add_network(nw) )
        debug(network, "Network Range")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigBreak)
    # Data Struct Initialize
    init()
    # Netflow collection & Analyzer
    startAnalyzer()
