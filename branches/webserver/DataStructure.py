#!/usr/bin/python2.6

# Python NetFlow Collector
#
# Copyright (C) 2011 pynetflow Project
# Author: Choonho Son <choonho@kt.com>
# URL: <http://pynetflow.googlecode.com>
# For license information, see LICENSE.TXT
#

import socket
import time

import matplotlib
matplotlib.use('AGG')
import matplotlib.pyplot as plt

from matplotlib.dates import HourLocator, DateFormatter
from proto import *


hours = HourLocator()  # every hour
hoursFmt = DateFormatter('%H')

DataStructure = {}

FLOW_INDEX = {'saddr':0, 'daddr':1, 'pcount':2, 'bcount':3, 'stime':4, 'elapse':5, 'sport':6, 'dport':7, 'protocol':8}

"""
The Component of DataStructure
1) network
2) slot
3) timeline
4) link
5) flow_t
"""

# Index of flow_t
INDEX_SADDR = 0
INDEX_DADDR = 1
INDEX_PCOUNT = 2
INDEX_BCOUNT = 3
INDEX_STIME = 4
INDEX_ELAPSE = 5
INDEX_SPORT = 6
INDEX_DPORT = 7
INDEX_PROTOCOL = 8

ONEDAY_SECOND = 86400 # 60 second * 60 minute * 24 hours
TIMELINE_PERIOD = 300 # 60 second * 5 minute
NUM_OF_TIMELINE_INDEX = 288

def showDataStructure(type='bcount', interval=24):
    # display DataStructure
    # "time" : [10:00, 10:05, 10:10, ... list of time]
    # "10.1.1.1" : ( [1,2,3,10, ... Bytes], [2,3,1,2, ... Bytes] )
    # "10.1.1.2" : ( [...], [...] )
    # "10.1.1.3" : ( [...], [...] )
    time = []
    result = {}
    for key in DataStructure.keys():
        # for slot
        (slot, subnet) = DataStructure[key]
        ip = socket.inet_ntoa(key)
        
        intip = DottedIPToInt(ip)
        ipCount = 0
        # bytes sum
        print "IP:%s Num of slot:%s" %(ip,  len(slot))
        for timeline in slot:
            # retreive wanted data
            (x, yu, yd) = getTimelineData(timeline, type, interval)
            myip = IntToDottedIP(intip + ipCount)
            # "10.1.1.1", ([list of uplink Bytes], [list of downlink Bytes])
            time = x
            result[myip] = ( yu, yd )
            # next ip
            ipCount = ipCount + 1
    return (time, result)

def report(chart='Bps', interval=24):
    #chart = Bps|Pps
    #type = bcount|pcount
    type = ''
    if chart == 'Bps':
        type='bcount'
    elif chart == 'Pps':
        type='pcount'
    else:
        return "Wrong request: (%s) - chart must be Bps or Pps" % chart

    (xaxis,result) = showDataStructure(type, interval)
    output = "ip\t(sum): %s\n" % reduce(lambda x,y:x+" "+y, xaxis)
    key = result.keys()
    key.sort()
    for ip in key:
        (ulink, dlink) = result[ip]
        output = output + "%s uplink   (%s) : %s\n" % (ip, reduce(lambda x,y: x+y, ulink), map(lambda x: x/300, ulink) )
        output = output + "%s downlink (%s) : %s\n" % (ip, reduce(lambda x,y: x+y, dlink), map(lambda x: x/300, dlink) )
    return output

        
        
        
def getSlot(ip):
    # param ip: network order
    # return Slot from DataStructure
    # which has ip
    for nw in DataStructure.keys():
        # check bitwiseAND
        if bitwiseAND(ip, nw) == nw:
            return DataStructure[nw]
    return (False, "Cannot find slot of %s" % socket.inet_ntoa(ip))

def cur_TIL():
    # return Current Timeline index
    return int ((time.time() % ONEDAY_SECOND) / TIMELINE_PERIOD)

def getDate(TIL, tz="KST"):
    # get timeline index
    # return date(epoch)
    seconds = TIL * TIMELINE_PERIOD
    HM = time.strftime("%H:%M", time.localtime(seconds))
    return HM

def getTimeline(ip):
    # return timeline of ip
    # find Slot
    # param ip: network order
    (slot, subnet) = getSlot(ip)
    if slot == False:
        return False

    nw_index = bitwiseAND(ip, subnet)
    return slot[toInt(nw_index)]


def bitwiseAND(a,b):
    # bitwise a and b
    # bitwise 4 bytes string a,b
    return "%s%s%s%s" % (chr( ord(a[0]) & ord(b[0]) ), chr( ord(a[1]) & ord(b[1]) ), \
                             chr( ord(a[2]) & ord(b[2]) ), chr( ord(a[3]) & ord(b[3]) ) )

def bitwiseOR(a,b):
    # bitwise a and b
    # bitwise 4 bytes string a,b
    return "%s%s%s%s" % (chr( ord(a[0]) | ord(b[0]) ), chr( ord(a[1]) | ord(b[1]) ), \
                             chr( ord(a[2]) | ord(b[2]) ), chr( ord(a[3]) | ord(b[3]) ) )

def toInt(bytes):
    # convert 4 bytes string to integer
    return (ord(bytes[0]) << 24) + (ord(bytes[1]) << 16) + (ord(bytes[2]) << 8) + (ord(bytes[3]))
    
def getBytesFromLink(link):
    # retrieve data from link
    result = 0
    for index in link:
        bcount = index[INDEX_BCOUNT]
        result = result + bcount
    return result

def getPacketsFromLink(link):
    # retrieve data from link
    result = 0
    for index in link:
        pcount = index[INDEX_PCOUNT]
        result = result + pcount
    return result


##################
# Chart APIs
##################
def cht_timeline(type, ip):
    if type == "bcount":
        nip = socket.inet_aton(ip)
        timeline = getTimeline(nip)
        if timeline == False:
            # Return False
            return 
        d_uplink = []
        d_downlink = []
        ctil = cur_TIL()
        print "Current time line:%d" % ctil

        x = [] # xtick
        timeCount =  ctil - 24            # 24 is 2 hour
        for timeCount in range(ctil - 24, ctil +1, 6):
            hour = getDate(timeCount)
            x.append(hour)

        temp = 0
        for (uplink, downlink) in timeline:
            a = getBytesFromLink(uplink)
            b = getBytesFromLink(downlink)
            if a > 0 or b > 0:
                print temp, getDate(temp), a,b
            temp = temp + 1

        for (uplink, downlink) in timeline[ctil - 24:ctil+1]:   # 24 is 2 hour
            d_uplink.append( (getBytesFromLink(uplink) / 300) )   # 300 second, Bps
            d_downlink.append( (getBytesFromLink(downlink) / 300))

        fig = plt.figure()

        ax = fig.add_subplot(111)
        ax.set_title("Realtime traffic of %s" % ip)

        # data
        # auto scale (Bps, KBps)
        if max(d_uplink) >= 10000 or max(d_downlink) >= 10000:   # over 10kbps
            sd_uplink = map (lambda x: x/1000, d_uplink)
            sd_downlink = map (lambda x: x / 1000, d_downlink)
            ylabel = "KBps"
            ax.plot(sd_uplink)
            ax.plot(sd_downlink)
        else:
            ylabel = "Bps"
            ax.plot(d_uplink)
            ax.plot(d_downlink)

        # grid, labels
        ax.set_xticklabels(x)
        ax.grid(True)
        #X,Y Label
        ax.set_ylabel(ylabel)
        ax.set_xlabel("Time")
        ax.legend(("Uplink", "Downlink"),loc='upper left', shadow=True)

        import StringIO, Image
        imgdata = StringIO.StringIO()
        fig.savefig(imgdata, format="png")
        imgdata.seek(0)
        return imgdata


def cht_log(content):
    # log 
    nip = socket.inet_aton(content['ip'])
    timeline = getTimeline(nip)

    if timeline == None:
        return "There is no IP: %s" % content['ip']

    # timestamp
    if content.has_key('ts') == False:
        timestamp = time.time() - 600 # 60 second
    else:
        timestamp = int(content['ts'])

    # index
    r_index = (int(timestamp) % ONEDAY_SECOND) / TIMELINE_PERIOD
    c_index = (int(time.time()) % ONEDAY_SECOND) / TIMELINE_PERIOD

    # limit
    if content.has_key('limit') == False:
        limit = 100
    else:
        limit = int(content['limit'])

    if c_index < r_index:
        c_index = c_index + NUM_OF_TIMELINE_INDEX


    result = []
    for index in range(c_index - r_index + 1):
        fetch_index = (r_index + index) % NUM_OF_TIMELINE_INDEX
        (u_link, d_link) = timeline[fetch_index]
        print u_link, d_link

        link = int(content['link'])
        if link == 0 or link == -1:
            getIPbyTimestamp(u_link, timestamp, result)
        if link == 1 or link == -1:
            getIPbyTimestamp(d_link, timestamp, result)

        result.sort()
        output = toString(result, limit)

    return output

def getTimelineData(timeline, type='bcount', interval = 24):
    # retreive flow data from timeline
    ctil = cur_TIL()
    time_x = []
    y_ulink = []
    y_dlink = []
    tindex = ctil - interval
    for index in range(interval):
        # xlabel
        tindex = ( tindex + 1 ) % NUM_OF_TIMELINE_INDEX
        time_x.append(getDate(tindex))
        # yvalue
        (ulink, dlink) = timeline[tindex] 
        y_ulink.append(getFlowData(ulink, type))
        y_dlink.append(getFlowData(dlink, type))

    return (time_x, y_ulink, y_dlink)

def getFlowData(link, type='bcount'):
    # retreive data from flow_t
    result = 0
    for index in link:
        value = index[FLOW_INDEX[type]]
        result = result + value
    return result
    
def getIPbyTimestamp(link, timestamp, result):
    for flow_t in link:
        # output format [timestamp, saddr, sport, proto, daddr, dport, bcount, pcount]
        if timestamp < flow_t[4]:
            result.append([flow_t[4], flow_t[0], flow_t[6], flow_t[8], flow_t[1], flow_t[7], flow_t[3], flow_t[2]]\
)

def toString(result, limit):
    output = ""
    global PROTO_DIC
    count = len(result)
    if len(result) > limit:
        count = limit

    for index_t in range(count):
        index = result[index_t]
        # format: timestamp srcIP(srcPort)-(PROTO)->dstIP(dstPort) nBytes nPacket
        output = output + "%s %s(%s)-%s->%s(%s) Bytes:%s Packets:%s\n" % \
            (time.strftime("[%H:%M:%S]", time.localtime(float(index[0]))),socket.inet_ntoa(index[1]), index[2], PROTO_DIC[index[3]], \
                 socket.inet_ntoa(index[4]), index[5], index[6], index[7])
    
    print "output:", output
    return output



def IntToDottedIP( intip ):
    octet = ''
    for exp in [3,2,1,0]:
        octet = octet + str(intip / ( 256 ** exp )) + "."
        intip = intip % ( 256 ** exp )
    return(octet.rstrip('.'))
 
def DottedIPToInt( dotted_ip ):
    exp = 3
    intip = 0
    for quad in dotted_ip.split('.'):
        intip = intip + (int(quad) * (256 ** exp))
        exp = exp - 1
    return(intip)
