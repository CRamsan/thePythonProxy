#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8

import threading, socket, sys

class ClientRequest:

        def __init__(self, local_conn, address):

                self.local_conn = local_conn
                self.socket_family = local_conn.family
                self.socket_type = local_conn.type
                self.address = address
                self.port = 80
#                self.client_request = None


                # determine HTTP method type and method parameters
                # while True:
                #         conn_buffer += bytes.decode(local_conn.recv(BUFFER_LENGTH))
                #         end = conn_buffer.find('\n')
                #         if end != -1: # if newline found, then parse the message
                #                 break

                self.client_request = local_conn.recv(BUFFER_LENGTH)

                decoded_client_request = bytes.decode(self.client_request)

                # modify request file URL (and anonymize, if applicable)
                self.modify_request(decoded_client_request)

                # split_request = (conn_buffer[:end+1]).split()
                # self.method = split_request[0]
                # self.path = split_request[1]
                # self.protocol = split_request[2]

                # for i in range(0, len(split_request)):
                #         print(i, ": ", split_request[i])

        def modify_request(self, decoded_request, anonymize=False):

                # part_decoded_request = list(decoded_request.partition("\n"))

                first_newline = decoded_request.find('\n')
                first_line = decoded_request[:first_newline]
                
                if first_line.find('GET') != -1:

                        print("--- Client -> Proxy Request ---\n%s" % (decoded_request))
                        
                        split_first_line = first_line.split()
                        self.method = split_first_line[0]
                        self.path = split_first_line[1]
                        self.protocol = split_first_line[2]

                        host_and_file = self.path[self.path.find('//')+2:]

                        backslash_index = host_and_file.find('/')
                        self.host = host_and_file[:backslash_index]
                        requested_file = host_and_file[backslash_index:]
                
                        modified_first_line = "%s %s %s" % (self.method, requested_file, self.protocol)
                        decoded_request = modified_first_line + decoded_request[first_newline:]
                
                        # part_decoded_request[0] = modified_first_line

                        # for i in range(0,len(part_decoded_request)):
                        #         print(i, ": ", part_decoded_request[i])

                        # self.client_request = str.encode("\n".join(item for item in part_decoded_request))
                        self.client_request = str.encode(decoded_request)

                else:
                        self.method = None

        def execute(self):

                try:
                        # connect to remote server

                        if self.method == 'GET':
                                remote_conn = socket.socket(self.socket_family, self.socket_type)
                                remote_conn.connect((self.host, self.port))
                                print("--- Proxy -> Server Request ---\n%s" % (bytes.decode(self.client_request)))
                        
                                request_length = len(self.client_request)
                                
                                total_sent = 0
                                while total_sent < request_length:
                                        sent = remote_conn.send(self.client_request[total_sent:])
                                        if sent == 0:
                                                raise RunTimeError("Socket connection broken.")
                                        total_sent = total_sent + sent

                                while True:
                                        response = remote_conn.recv(BUFFER_LENGTH)
                                        if len(response) > 0:
                                                print("--- Server Response ---\n%s\n" % repr(response))
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
                print("Proxy connected to client ", address, "\n")
                threading.Thread(target=ProxyConn, args=(client_socket, address, timeout)).start()

if __name__ == '__main__':

        if len(sys.argv) > 1:
                start_server(port=int(sys.argv[1]))
        else:
                start_server()
