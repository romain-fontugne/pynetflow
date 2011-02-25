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

def showDataStructure(type1='bcount', interval=24):
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
            (x, yu, yd) = getTimelineData(timeline, type1, None, interval)
            myip = IntToDottedIP(intip + ipCount)
            # "10.1.1.1", ([list of uplink Bytes], [list of downlink Bytes])
            time = x
            result[myip] = ( yu, yd )
            # next ip
            ipCount = ipCount + 1
    return (time, result)

def cht_summary(param):
    # param
    # type1: bcount|pcount
    # type2: sum|detail
    # interval: 24

    # check parameters
    if param.has_key('type1') == False or param.has_key('type2') == False or param.has_key('interval') == False:
        return "Error of parameters : %s" % param

    if param['type1'] != "bcount" and param['type1'] != "pcount":
        return "Error of type1 parameter : %s" % param
    if param['type2'] != "sum" and param['type2'] != "detail":
        return "Error of type2 parameter : %s" % param
    if int(param['interval']) <= 0 and int(param['interval']) > 24:
        return "Error of interval parameter : %s" % param

    (xaxis,result) = showDataStructure(param['type1'], int(param['interval']) )

    # x axis
    key = result.keys()
    ips = map(DottedIPToInt, key)
    ips.sort()
    output = ""
    if param['type2'] == "sum":
        output = "IP\tUplink\tDownlink of Sum\n"
        for ip in ips:
            strip = IntToDottedIP(ip)
            (ulink, dlink) = result[strip]
            output = output + "%s %s %s\n" % (strip, reduce(lambda x,y: x+y, ulink), reduce(lambda x,y:x+y, dlink) )

    elif param['type2'] == "detail":
        output = "IP\t%s\n" % reduce(lambda x,y: x+" "+y, xaxis)
        for ip in ips:
            strip = IntToDottedIP(ip)
            (ulink, dlink) = result[strip]
            output = output + "%s up %s\n" % (strip, reduce(lambda x,y: str(x)+" "+str(y), ulink) )
            output = output + "%s dn %s\n" % (strip, reduce(lambda x,y: str(x)+" "+str(y), dlink) )
    else:
        output = "Error of parameters : %s" % param

    return output

def cht_detail(param):
    # param
    # ip : wanted ip address
    # type1: bcount|pcount
    # link : 0(uplink), 1(downlink), -1: both
    # interval : 0 ~ 24
    timeline = getTimeline( socket.inet_aton(param['ip']) )

    if param.has_key('type2') == False:
        param['type2'] = None
    if param['type2'] == 'None':
        param['type2'] = None

    (x, y1, y2) = getTimelineData( timeline, type1=param['type1'], type2=param['type2'], interval=int(param['interval']) )
    if param['link'] == "0":     #uplink
        return ListToTable([x, y1])
    elif param['link'] == "1":   #downlink
        return ListToTable([x, y2])
    else:                        # both
        return ListToTable([x, y1, y2])
        
        
        
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
        for timeCount in range(ctil - 25, ctil, 6):
            hour = getDate(timeCount)
            x.append(hour)

        (start,end) = (ctil - 24, ctil)
        for index in range(end - start):
            (uplink, downlink) = timeline[start + index]
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

def getTimelineData(timeline, type1='bcount', type2=None, interval = 24):
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
        y_ulink.append(getFlowData(ulink, type1, type2))
        y_dlink.append(getFlowData(dlink, type1, type2))

    return (time_x, y_ulink, y_dlink)

def getFlowData(link, type1='bcount', type2=None):
    # retreive data from flow_t
    result = ""
    if type1 == 'pcount' or type1=='bcount':
        result = 0L

    for index in link:
        value = index[FLOW_INDEX[type1]]
        value2 = None
        if type2 != None:
            wanted_list = type2.split(",")
            wanted_result = []
            for item in wanted_list:
                wanted_result.append( str(index[FLOW_INDEX[item]]) )

        if type(result) == long:
            result = result + value
        else:
            if type1 == "saddr" or type1 == "daddr":
                result = result + " " + socket.inet_ntoa(value)
            else:
                result = result + " " + str(value)

            if type2 != None:
                result = result + " " + ListToString(wanted_result)

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

def ListToString(value):
    return reduce(lambda x,y: str(x)+" "+str(y), value)

def ListToTable( lists ):
    # assum each list has same length
    count = len(lists[0])
    lenlist = len(lists)
    output = ""
    for index in range(count):
        for index2 in lists:
            output = output + str(index2[index]) + " "
        output = output + "\n"

    return output
        
