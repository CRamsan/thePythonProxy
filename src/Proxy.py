#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8

import threading
import socket
import sys
import re
import signal
import datetime
import hashlib
import pdb

class HttpRequest:
    def __init__(self, decoded_request):
        self.method = (decoded_request).splitlines()[0].split()[0]
        self.request_uri = (decoded_request).splitlines()[0].split()[1]
        self.http_version = (decoded_request).splitlines()[0].split()[2]
        self.request_headers = dict()
        
        tmp = (decoded_request).splitlines()[1:-1]
        for line in tmp:
            self.request_headers[line.split(':')[0]] = line.split(':')[1].strip()
        
        self.message_body = (decoded_request).splitlines()[-1]
        self.request_line = [self.method, self.request_uri, self.http_version]

    def strip_cache_headers(self):
        if 'If-Modified-Since' in self.request_headers:
            del self.request_headers['If-Modified-Since']
        if 'If-None-Match' in self.request_headers:
            del self.request_headers['If-None-Match']
        if 'Cache-Control' in self.request_headers:
            del self.request_headers['Cache-Control']
        
    def strip_user_agent(self):
        del self.request_headers['User-Agent']

    def get_host_name(self):
        host_and_file = self.request_uri[self.request_uri.find('//')+2:]
        backslash_index = host_and_file.find('/')
        return host_and_file[:backslash_index]
        
    def get_modified_request(self):
        modified_request = self.get_modified_request_line()
        modified_request += self.get_request_headers()
        modified_request += self.get_message_body()
        return modified_request
        
    def get_original_request(self):
        original_request = self.get_original_request_line()
        original_request += self.get_request_headers()
        original_request += self.get_message_body()
        return original_request

    def get_original_request_line(self):
        return "%s %s %s \r\n" % (self.method, self.request_uri, self.http_version)
    
    def get_modified_request_line(self):
        host_and_file = self.request_uri[self.request_uri.find('//')+2:]
        backslash_index = host_and_file.find('/')
        self.requested_file = host_and_file[backslash_index:]
        return "%s %s %s \r\n" % (self.method, self.requested_file, self.http_version)
    
    def get_request_headers(self):
        headers_text = ""
        for param in self.request_headers.keys():
            headers_text+= ("%s: %s \r\n" % (param, self.request_headers[param]))
        return headers_text
    
    def get_message_body(self):
        return (self.message_body+"\r\n")
        
class ClientRequest:

    def __init__(self, local_conn, address, strip_cache_headers, strip_user_agent):

        self.local_conn = local_conn
        self.socket_family = local_conn.family
        self.socket_type = local_conn.type
        self.address = address
        self.port = 80
        self.decoded_client_request = HttpRequest(bytes.decode(local_conn.recv(BUFFER_LENGTH)))
        if strip_cache_headers:
            self.decoded_client_request.strip_cache_headers()
        if strip_user_agent:
            self.decoded_client_request.strip_user_agent()
        print("--- Client -> Proxy ---\n%s" % (self.decoded_client_request.get_original_request()))
                    
    def execute(self, lock, cache):
        try:

            host = self.decoded_client_request.get_host_name()
            if self.decoded_client_request.method == 'GET':

                md5hash = hashlib.md5()
                md5hash.update(str.encode(self.decoded_client_request.request_uri))
                request_digest = md5hash.digest()
                response_size = 0
                            
                if request_digest not in cache: # connect to remote server
                    remote_conn = socket.socket(self.socket_family, self.socket_type)
                    remote_conn.connect((host, self.port))
                    print("--- Proxy -> Server Request ---\n%s" % (self.decoded_client_request.get_modified_request()))
                    request_length = len(self.decoded_client_request.get_modified_request())
                                
                    total_sent = 0
                    sent = remote_conn.send(str.encode(self.decoded_client_request.get_modified_request()))

                    response = b''
                    while True:
                        recvd = remote_conn.recv(BUFFER_LENGTH)
                        if len(recvd) > 0:

                            self.local_conn.send(recvd)
                            response += recvd
                        else:
                            break

                    response_size = len(response)
                    print("--- Server Response ---\n%s\n" % repr(response))
                    #pdb.set_trace()
                    
                    remote_conn.close()
                    cache[request_digest] = response
                
                else: #retrieve from cache
                    cached = cache[request_digest]
                    response_size = len(cached)
                    total_sent = 0

                    while total_sent < response_size:
                        sent = self.local_conn.send(cached)
                        total_sent += sent

                    print("---  Served From Cache  --- \n%s\n" % (self.decoded_client_request.request_uri))

                # convert hostname to IP address
                ip = socket.gethostbyname(host)
                
                # acquire lock and write to file
                lock.acquire()
                log_file.write("%s %s %i\n" % (str(datetime.datetime.now()), ip, response_size))
                lock.release()
                
        except OSError: 
            # exit gracefully
            pass

class ProxyConn:
                
    def __init__(self, client_conn, address, strip_cache_headers, strip_user_agent, timeout, lock, cache):
        self.client_conn = client_conn
        self.remote_conn  = None
        self.timeout = timeout
        self.cache = cache

        self.request = ClientRequest(self.client_conn, address, strip_cache_headers, strip_user_agent)
        self.request.execute(lock, cache)

        self.client_conn.close()
        

def start_server(log_file, cache, host='localhost', port=4444, IPv6=False, strip_cache_headers=True, strip_user_agent=True, timeout=30):

    # socket settings
    if IPv6:
        socket_family = socket.AF_INET6
    else:
        socket_family = socket.AF_INET

    socket_type = socket.SOCK_STREAM
        
    try:

        # initialize socket
        server_socket = socket.socket(socket_family, socket_type)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # remove after testing
        server_socket.bind((host, port))
        server_socket.listen(5)

        # create lock file
        lock = threading.Lock()

        while True:
            (client_socket, address) = server_socket.accept()
            print("Proxy connected to client ", address, "\n")
            threading.Thread(target=ProxyConn, args=(client_socket, address, strip_cache_headers, strip_user_agent, timeout, lock, cache)).start()
            
    except KeyboardInterrupt:
        print("Ctrl+C  detected...")
    except:
        print("Unexpected exception detected...")

    print("Closing server socket...")
    server_socket.close()
    print("\nClosing log file...")
    log_file.close()
    print("Goodbye.")
        
log_file = open('proxy.log', 'a')
cache = {}

if __name__ == '__main__':
        
    print("Starting %s." % (PROXY_NAME))

    if len(sys.argv) > 1:
        start_server(log_file, cache, port=int(sys.argv[1]))
    else:
        start_server(log_file, cache)
