'''
Created on 2011. 5. 5.

@author: Son
'''

##############################
# TODO: specify project name
##############################
PRJ_NAME = "netflow"


#runtime dir
PID_DIR                     = '/var/run/%s' % PRJ_NAME
SHUTDOWN_FLAG               = "%s/%s.shutdown" % (PID_DIR, PRJ_NAME)
AGENT_SHUTDOWN_MODE_FLAG    = "%s/shutdown_mode" % PID_DIR
LOG_DIR                     = '/var/log/%s' % PRJ_NAME