#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGHT = 1024 * 8

import threading
import socket

class ClientRequest:
        def __init__(self, connection, conn_buffer):
                while 1:
                        client_buffer += connection.recv(BUFFER_LENGHT)
                        end = conn_buffer.find('\n')
                        if end!=-1:
                                break
                data = (conn_buffer[:end+1]).split()
                self.method = data[0]
                self.path = data[1]
                self.protocol = data [2]


class ProxyConnection:
                
        def __init__(self, connection, timeout):
                self.local_connection = connection
                self.remote_connection  = None
                self.conn_buffer = ''
                self.timeout = timeout

                self.request = ClientRequest(self.local_connection, self.conn_buffer)

                self._forwarding()

                self._remote_connection.close()
                self._local_connection.close()

        def _forwarding(self):
                pass

        def _remoteConnect(self, host):
                pass

        def _localConnect(self):
                pass

class ServerSocket:

        def __init__(self, sock=None):
                if sock is None:
                        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                        self.sock = sock

        def bind(self, host, port):
                self.sock.bind((host, port))


def start_server(host='localhost', port=4444, IPv6=False, timeout=30, handler=ProxyConnection):
        if IPv6:
                socket_family = socket.AF_INET6
        else:
                socket_family = socket.AF_INET
        
        listen_socket = ServerSocket(socket.socket(socket_family, socket.SOCK_STREAM))
        listen_socket.bind(host, port)
        listen_socket.sock.listen(5)
        while True:
                c, addr = listen_socket.sock.accept()
                print("Got connection from ", addr)
                c.send(b"Connection confirmed!")
                c.close()

def test_client():
        client_sock = socket.socket()
        host = 'localhost'
        port = 4444
        client_sock.connect((host,port))
        print(client_sock.recv(1024))
        client_sock.close()

#        thread_count = 0
#        threading.Thread(target=handler, name="Thread%i" % thread_count, args=(listen_socket.connect(host, port))).start()
#        thread_count += thread_count + 1

if __name__ == '__main__':
        start_server()
        test_client()
