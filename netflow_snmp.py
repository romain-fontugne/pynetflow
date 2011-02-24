#!/usr/bin/python2.6

# Python NetFlow Collector
#
# Copyright (C) 2011 pynetflow Project
# Author: Choonho Son <choonho@kt.com>
# URL: <http://pynetflow.googlecode.com>
# For license information, see LICENSE.TXT
#

import sys
import re

# global variable
pid_file = "/tmp/netflow_collector.pid"

def getStatus(pid, mib):
    file_path = "/proc/%s/status" % pid
    fp = open(file_path, 'r')
    for line in fp:
        token = re.split("\s+", line)
        if token[0] == mib + ":":
            return token[1]
    # no mib
    return -1

def parse(pid, mib):
    if mib == "status":
        return 1
    else:
        return getStatus(pid, mib)

def getData(mib):
    try:
        fp = open(pid_file,'r')
        pid = fp.read()
        fp.close()
        return parse(pid, mib)
    except:
        return -1

if __name__ == "__main__":
    print getData(sys.argv[1])
