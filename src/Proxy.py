#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8

import threading
import socket

class ClientRequest:

        def __init__(self, local_conn, address):

                self.local_conn = local_conn
                self.socket_family = local_conn.family
                self.socket_type = local_conn.type
                self.address = address
                self.port = 80

                conn_buffer = ''

                # determine HTTP method type and method parameters
                while True:
                        conn_buffer += bytes.decode(local_conn.recv(BUFFER_LENGTH))
                        end = conn_buffer.find('\n')
                        if end != -1: # if newline found, then parse the message
                                break

                print("--- Client -> Proxy Request ---\n", conn_buffer);
                split_request = (conn_buffer[:end+1]).split()
                self.method = split_request[0]
                self.path = split_request[1]
                self.protocol = split_request[2]

        def execute(self):

                try:
                        # connect to remote server
                        host_and_file = self.path[self.path.find('//')+2:]
#                        print("Host+File: ", host_and_file)
                        backslash_index = host_and_file.find('/')
                        host = host_and_file[:backslash_index]
#                        print("Host: ", host)
                        requested_file = host_and_file[backslash_index:]
#                        print("File: ", requested_file)

                        remote_conn = socket.socket(self.socket_family, self.socket_type)
                        remote_conn.connect((host, self.port))
                        print("--- Proxy -> Server Request ---\n%s %s %s\nHost: %s\n" % (self.method, requested_file, self.protocol, host))
                        
                        request = str.encode("%s %s %s\nHost: %s\n\n" % (self.method, requested_file, self.protocol, host))
                        request_length = len(request)

                        total_sent = 0
                        while total_sent < request_length:
                                sent = remote_conn.send(request[total_sent:])
                                if sent == 0:
                                        raise RunTimeError("Socket connection broken.")
                                total_sent = total_sent + sent

                        while True:
                                response = remote_conn.recv(BUFFER_LENGTH)
                                if len(response) > 0:
                                        print("--- Server Response ---\n", bytes.decode(response))
                                        self.local_conn.send(response)
                                else:
                                        break

                        remote_conn.close()
                
                except OSError: 
                        # exit gracefully
                        pass


class ProxyConn:
                
        def __init__(self, client_conn, address, timeout):
                self.client_conn = client_conn
                self.remote_conn  = None
                self.timeout = timeout

                self.request = ClientRequest(self.client_conn, address)
                self._execute_request()

                self.client_conn.close()

        def _execute_request(self):
                self.request.execute()


def start_server(host='localhost', port=4444, IPv6=False, timeout=30):

        # socket settings
        if IPv6:
                socket_family = socket.AF_INET6
        else:
                socket_family = socket.AF_INET

        socket_type = socket.SOCK_STREAM
        
        # initialize socket
        server_socket = socket.socket(socket_family, socket_type)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # remove after testing
        server_socket.bind((host, port))
        server_socket.listen(5)

        while True:
                (client_socket, address) = server_socket.accept()
                print("Connected to ", address, "\n")
                threading.Thread(target=ProxyConn, args=(client_socket, address, timeout)).start()

if __name__ == '__main__':

        if len(sys.argv) > 1:
                start_server(port=argv[1])
        else:
                start_server()
