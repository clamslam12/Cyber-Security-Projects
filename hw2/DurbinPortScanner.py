import socket
import time
import sys
import os

target = input("Enter Target IP: ")
# scanner for tcp
def tcp_scanner(target, port):
    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)# using ipv4 and tcp
        tcp_sock.connect((target,port))
        tcp_sock.close()
        return True
    except:
        print("Port ", port, "/tcp is closed")  # if exception raised, print that port is closed
        return False
#scanner for udp
def udp_scanner(target, port):
    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# using ipv4 and udp
        tcp_sock.connect((target,port))
        #time.sleep(0.5) #wait for 0.5 secs
        tcp_sock.close()
        return True
    except:
        print("Port ", port, "/udp is closed") #if exception raised, print that port is closed
        return False


try:
    waitTime = input("enter waiting time: ")
    waitTimeF = float(waitTime)
    while True:
        for portNumber in range(1, 1024):
            if tcp_scanner(target, portNumber):  # if false then try the next port
                print("Port ", portNumber, "/tcp is open\n")
                print("waiting for ", waitTime, "seconds")
                time.sleep(waitTimeF)

        for portNum in range(1, 1024):
            if udp_scanner(target, portNum):  # if false then try the next port
                print("Port ", portNum, "/udp is open\n")
                print("waiting for ", waitTime, "seconds")
                time.sleep(waitTimeF)
except KeyboardInterrupt:
    pass











