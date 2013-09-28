#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8

import threading
import socket

class client_request:
        def __init__(self, conn, conn_buffer):
                while 1:
                        client_buffer += conn.recv(BUFFER_LENGTH)
                        end = conn_buffer.find('\n')
                        if end!=-1:
                                break
                data = (conn_buffer[:end+1]).split()
                self.method = data[0]
                self.path = data[1]
                self.protocol = data [2]


class proxy_conn:
                
        def __init__(self, client_conn, timeout):
                self.local_conn = conn
                self.remote_conn  = None
                self.conn_buffer = ''
                self.timeout = timeout

                self.request = client_request(self.local_conn, self.conn_buffer)
                self._forward()

                self._remote_conn.close()
                self._local_conn.close()

        def _forward(self):
                pass

        def _remote_connect(self, host):
                pass

        def _local_connect(self):
                pass


def start_server(host='localhost', port=4444, IPv6=False, timeout=30):

        # socket settings
        if IPv6:
                socket_family = socket.AF_INET6
        else:
                socket_family = socket.AF_INET

        socket_type = socket.SOCK_STREAM
        
        # initialize socket
        server_socket = socket.socket(socket_family, socket_type)
        server_socket.bind((host, port))
        server_socket.listen(5)

        while True:
                (client_socket, address) = server_socket.accept()
                print("Got connection from ", address)
                conn_socket.send(b"Connection confirmed!")
                proxy = proxy_conn(client_socket, timeout)
                proxy.start()

if __name__ == '__main__':
        start_server()
