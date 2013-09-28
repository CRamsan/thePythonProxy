#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8

import threading
import socket

class clientRequest:
        def __init__(self, conn, conn_buffer):
                while 1:
                        clientBuffer += conn.recv(BUFFER_LENGTH)
                        end = connBuffer.find('\n')
                        if end!=-1:
                                break
                data = (connBuffer[:end+1]).split()
                self.method = data[0]
                self.path = data[1]
                self.protocol = data [2]


class proxyConn:
                
        def __init__(self, clientConn, timeout):
                self.localConn = conn
                self.remoteConn  = None
                self.connBuffer = ''
                self.timeout = timeout

                self.request = clientRequest(self.localConn, self.connBuffer)
                self._forward()

                self._remoteConn.close()
                self._localConn.close()

        def _forward(self):
                pass

        def _remoteConnect(self, host):
                pass

        def _localConnect(self):
                pass


def startServer(host='localhost', port=4444, IPv6=False, timeout=30):

        # socket settings
        if IPv6:
                socketFamily = socket.AF_INET6
        else:
                socketFamily = socket.AF_INET

        socketType = socket.SOCK_STREAM
        
        # initialize socket
        serverSocket = socket.socket(socketFamily, socketType)
        serverSocket.bind((host, port))
        serverSocket.listen(5)

        while True:
                (clientSocket, address) = serverSocket.accept()
                print("Got connection from ", addr)
                conn.send(b"Connection confirmed!")
                proxy = proxyConn(clientSocket, timeout)
                proxy.run()

if __name__ == '__main__':
        startServer()
