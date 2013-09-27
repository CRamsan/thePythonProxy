#!/usr/bin/python

import threading
import socket

def test_client():
        client_sock = socket.socket()
        host = 'localhost'
        port = 4444
        client_sock.connect((host,port))
        print(client_sock.recv(1024))
        client_sock.close()

test_client()
