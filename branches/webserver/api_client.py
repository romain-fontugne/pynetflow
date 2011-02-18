import socket
import sys
import time

HOST, PORT = "localhost", 10200

data = "exit"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect( (HOST,PORT) )
cmd = sys.argv[1]
print "Cmd: ", cmd
sock.send(cmd)

recv = sock.recv(1024)
print recv
sock.close()
