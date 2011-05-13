'''
Created on 2011. 5. 5.

@author: Son (chonho.son@gmail.com)
'''
from os.path import basename
from optparse import OptionParser
from ConfigParser import ConfigParser

from Utils.Daemon import daemonize
import Utils.Constants as Constants
import time

# Global variable
#_options = None
#_config = None

def server(config):
    while 1:
        print "daemon"
        time.sleep(1)
        
def main():
    
    # TODO: Option Parser
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="filename", help="configuration file(default:skeleton.ini)")
    parser.add_option("-d", "--daemon", dest="daemon", action="store_true", help="run as background daemon")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true")
    
    (options, args) = parser.parse_args()
    
    # Config Parser
    conf = Constants.CONF_FILE
    if options.filename:
        conf = options.filename
    config = ConfigParser(conf)
    
    # Check daemonize
    pid_filename = basename(__file__).split(".")[0]
    if options.daemon:
        daemonize(pid_filename)
    
    # TODO: Call main procudure
    server(config)
    
if __name__ == '__main__':
    main()
    