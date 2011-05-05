'''
Created on 2011. 5. 5.

@author: Son
'''

#http://homepage.hispeed.ch/py430/python/daemon.py

import sys, os
import logging
from os.path import dirname, isdir, join, basename, exists
from Constants import PID_DIR

def daemonize(pid_filename=None):
    _basename = basename(pid_filename).split(".")[0]
    pid_file = join(PID_DIR, "%s.pid" % _basename)

    #if already started, quit quietly.
    if exists(pid_file):
        f = open(pid_file)
        pid = f.read().strip()
        f.close()
        if isdir("/proc/%s" % pid):
            logging.info("process('%s') already started with pid=%s." % (_basename, pid))
            sys.exit(0)

    wd = dirname(__file__)
    os.chdir(wd)
    if hasattr(os, "devnull"):
        devnull = os.devnull
    else:
        devnull = "/dev/null"
    sys.stdin = open(devnull, "r")
    sys.stdout = sys.stderr = open(devnull, "w")

    # do the UNIX double-fork magic, see Stevens' "Advanced
    # Programming in the UNIX Environment" for details (ISBN 0201563177)
    try:
        pid = os.fork()
        if pid > 0: # exit first parent
            sys.exit(0)
    except OSError, e:
        print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror)
        sys.exit(1)

    # decouple from parent environment
    #NOTE: if chdir to '/' dirname(__file__) will not work correctly
    #os.chdir("/")   #don't prevent unmounting....
    os.setsid()
    os.umask(0)

    # do a second fork
    try:
        pid = os.fork()
        if pid > 0:
            if pid_file:
                if not isdir(PID_DIR):
                    os.makedirs(PID_DIR)
                f = open(pid_file, 'w')
                f.write("%d\n" % pid)
                f.close()
            sys.exit(0)
    except OSError, e:
        print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror)
        sys.exit(1)

