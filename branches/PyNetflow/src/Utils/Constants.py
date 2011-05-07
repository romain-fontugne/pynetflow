'''
Created on 2011. 5. 5.

@author: Son
'''

from os.path import exists
 
##############################
# TODO: specify project name
##############################
PRJ_NAME = "skeleton"


#runtime dir
PID_DIR                     = '/var/run/%s' % PRJ_NAME
# Not prepared
if exists(PID_DIR) == False:
    PID_DIR="/tmp/%s" % PRJ_NAME
    
SHUTDOWN_FLAG               = "%s/%s.shutdown" % (PID_DIR, PRJ_NAME)
AGENT_SHUTDOWN_MODE_FLAG    = "%s/shutdown_mode" % PID_DIR
LOG_DIR                     = '/var/log/%s' % PRJ_NAME