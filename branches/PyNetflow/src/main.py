'''
Created on 2011. 5. 5.

@author: Son
'''
from os.path import basename
from Utils.Daemon import daemonize

def server():
    while 1:
        print "daemon"
        sleep(1)
        
def main(front):
    pid_filename = basename(__file__).split(".")[0]
    if not front:
        daemonize(pid_filename)
        
if __name__ == '__main__':
    front = False
    if len(sys.argv) > 1:
        if sys.argv[1] == 'front':
            front = True
    main(front)
    