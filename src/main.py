'''
Created on 2011. 5. 5.

@author: Son (chonho.son@gmail.com)
'''
from os.path import basename
from Utils.Daemon import daemonize
from optparse import OptionParser

import time

# Global variable
_options = None

def server():
    while 1:
        print "daemon"
        time.sleep(1)
        
def main():
    
    # TODO: Option Parser
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="filename", help="configuration file(default:skeleton.ini)")
    parser.add_option("-d", "--daemon", dest="daemon", action="store_true", help="run as background daemon")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true")
    
    global _options
    (_options, args) = parser.parse_args()
    
    # Check daemonize
    pid_filename = basename(__file__).split(".")[0]
    if _options.daemon:
        daemonize(pid_filename)
    
    # TODO: Call main procudure
    server()
    
if __name__ == '__main__':
    main()
    