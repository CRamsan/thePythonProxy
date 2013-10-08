#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8
CACHE_SIZE = 200000

import threading
import socket
import sys
import re
import os
import select
import signal
import random
import datetime
import hashlib
import pdb
from time import sleep

class Cache:
    '''
    This cache follows a Least-Recently-Used model with all operations running 
    in constant time under optimal circumstances. It consists of queue, implemented
    as a doubly linked list, as well as a dictionary mapping response hash IDs to
    the entries.

    This structure allows to keep track of all the entries in the way of a queue. 
    Each entry is apended at the begining of the queue and when the cache is full
    the last entry is removed. Furthermore, the entry dictionary is used to achieve
    reading operations in constant time.
    '''
    
    def __init__(self, max_size):
        self.first = None
        self.last = None
        self.table = {}
        self.current_size = 0
        self.max_size = max_size
        self.lock = threading.Lock()

    def touch(self, hashid):
        '''
        Move an entry to the front of the queue.
        '''

        if hashid in self.table:

            # Get references for the current entry, as well as the next 
            # and previous ones
            touch_entry = self.table[hashid]
            prev_entry = touch_entry.prev_entry
            next_entry = touch_entry.next_entry
            
            if prev_entry is None :
                print ("Object is already first in cache")
                return

            # remove the reference to the current entry by making 
            # the previous entry point straight to the next entry                                              
            if prev_entry is not None:
                prev_entry.next_entry = next_entry

            # If the entry is not the last one
            if next_entry is not None:
                # remove the reference to the current entry by making 
                # the next entry point straight to the previous entry 
                next_entry.prev_entry = prev_entry

            # moved touched entry to the front
            if self.first is not None:
                next_entry = self.first
                self.first.prev_entry = touch_entry
            prev_entry = None
            self.first = touch_entry

            print("%s moved to front of cache.\n" % (hashid))

    def insert(self, hashid, content, size):
        '''
        Insert a response entry into the queue.
        '''
        
        if hashid not in self.table:
            if(size > self.max_size):
                print ("Object's size is exceeds the limit for this cache")
                return
            else:
                # The item fits in the cache but some items need to be removed first
                if(self.current_size + size > self.max_size):
                    self.lock.acquire()
                    while True:
                        # Get the size and key of the entry to be removed
                        old_last = self.last
                        del_size = old_last.size
                        del_key = old_last.key
                        
                        # Remove the file
                        old_last.delete_file()                    
                        
                        # Move the self.last pointer to the previous entry
                        prev_entry = old_last.prev_entry
                        self.last = prev_entry 
                        
                        # Remove a reference to the previous-last entry from
                        # the dictionary
                        del self.table[del_key]
                        print("%s removed from cache.\n" % (del_key))
                        
                        # The last entry does not have a 'next' entry
                        self.last.next_entry = None
                        
                        # Substract the file size
                        self.current_size -= del_size
                        
                        # Check if new entry will fit after last item was removed
                        if(self.current_size + size <= self.max_size):
                            break
                    self.lock.release()
                    
            # Handle if the cache is empty
            new_first = None
            if self.first is None:
                new_first = self.Entry(hashid, size, None, None)
                self.last = new_first
            else:
                # Set the new entry as the first in the queue
                new_first = self.Entry(hashid, size, None, self.first)
                self.first.prev_entry = new_first
            
            self.first = new_first
            self.table[hashid] = new_first
            self.first.create_file(content)
            self.current_size += size
            print("%s added to cache.\n" % (hashid))

        # If entry is already in queue    
        else:
            self.touch(hashid)
    
    def get(self, hashid):
        '''
        Get the response associated with the hashid,
        by reading it from cache file on disk.
        '''
        content = None
        if hashid in self.table:
            found = self.table[hashid]
            self.touch(hashid)
            content = found.read_file()
        return content
    
    def queue(self):
        '''
        Print the current entries in the queue. Useful for debugging.
        '''
        self.first.print_queue()

    class Entry:
        '''

        A cache entry. Each entry of the cache contains the following attributes:
    
        ``key``
            the name of the file that contains the cached data

        ``size``
            the size in bytes of the content in the file

        ``prev_entry``
            pointer to previous entry

        ``next_entry``
            pointer to next entry

        '''

        def __init__(self, key, size, prev_entry, next_entry):
            self.prev_entry = prev_entry
            self.key = key
            self.size = size
            self.next_entry = next_entry

        def read_file(self):
            '''
            Return the response contained in the file
            associated with this entry.
            '''

            cache_file = open("cache/"+str(self.key), 'rb')
            content = cache_file.read()
            cache_file.close()
            return content
            
        def create_file(self, data):
            '''
            Create a file on disk to store the response
            associated with this entry.
            '''

            cache_file = open("cache/"+str(self.key), 'wb')
            cache_file.write(data)
            cache_file.close()

        def delete_file(self):
            '''
            Delete this entry's cache file from the disk.
            '''

            os.remove("cache/"+str(self.key))            
                        
        def print_queue(self):
            '''
            Print this entry's hashid, as well as the next.
            Useful for debugging.
            '''
            print (self.key)
            if self.next_entry is not None:
                self.next_entry.print_queue()
        
class HttpRequest:
    '''
    An HTTP request. Contains the request headers and body.
    Headers are contained in a dict object.
    '''

    def __init__(self, decoded_request):
        firstline_split = (decoded_request).splitlines()[0].split()
        self.method = firstline_split[0]
        self.request_uri = firstline_split[1]
        self.http_version = firstline_split[2]
        self.request_headers = dict()

        tmp = (decoded_request).splitlines()[1:-1]
        for line in tmp:
            if line != "":
                colon_index = line.find(':')
                self.request_headers[line[0:colon_index]] = line[colon_index+1:]
        
        self.message_body = (decoded_request).splitlines()[-1]
        self.request_line = [self.method, self.request_uri, self.http_version]

    def strip_cache_headers(self):
        '''
        Strip the headers related to caching, since this will
        be performed by the proxy.
        '''

        if 'If-Modified-Since' in self.request_headers:
            del self.request_headers['If-Modified-Since']
        if 'If-None-Match' in self.request_headers:
            del self.request_headers['If-None-Match']
        if 'Cache-Control' in self.request_headers:
            del self.request_headers['Cache-Control']

    def set_connection_close(self):
        '''
        Set the HTTP request to use a non-persistent connection.
        '''

        if 'Connection' in self.request_headers:
                self.request_headers['Connection'] = 'close'
        if 'Proxy-Connection' in self.request_headers:
                self.request_headers['Proxy-Connection'] = 'close'
        
    def strip_user_agent(self):
        '''
        Strip the user agent header, for increased anonymity.
        '''

        del self.request_headers['User-Agent']

    def get_host_name(self):
        '''
        Get the host name associated with this HTTP request.
        '''

        host_and_file = self.request_uri[self.request_uri.find('//')+2:]
        backslash_index = host_and_file.find('/')
        return host_and_file[:backslash_index]

    def get_port(self):
        '''
        Get the port this HTTP request should use. Default to port 80,
        if not specified.
        '''

        host = self.get_host_name()
        i = host.find(':')
        if i != -1:
            return int(host[i+1:])
        else:
            return 80
        
    def get_modified_request(self):
        '''
        Return the HTTP request, modified for transmission
        from the proxy to the server.
        '''

        modified_request = self.get_modified_request_line()
        modified_request += self.get_request_headers()
        modified_request += self.get_message_body()
        return modified_request
        
    def get_original_request(self):
        '''
        Return the HTTP request, as originally received from
        the client.
        '''
        
        original_request = self.get_original_request_line()
        original_request += self.get_request_headers()
        original_request += self.get_message_body()
        return original_request

    def get_original_request_line(self):
        '''
        Get the initial line of the original request.
        '''

        return "%s %s %s \r\n" % (self.method, self.request_uri, self.http_version)
    
    def get_modified_request_line(self):
        '''
        Get the inital line of the modified request. In this modified version, the host 
        is stripped from the request URI.
        '''

        host_and_file = self.request_uri[self.request_uri.find('//')+2:]
        backslash_index = host_and_file.find('/')
        self.requested_file = host_and_file[backslash_index:]
        return "%s %s %s \r\n" % (self.method, self.requested_file, self.http_version)
    
    def get_request_headers(self):
        '''
        Return all headers as a single string.
        '''

        headers_text = ""
        for param in self.request_headers.keys():
            headers_text+= ("%s: %s \r\n" % (param, self.request_headers[param]))
        return headers_text
    
    def get_message_body(self):
        '''
        Return the message body of the request.
        '''
        
        return (self.message_body+"\r\n")
        
class ClientRequest:
    '''
    A client request. Contains information on the client, as well as the actual
    HTTP request made.
    '''

    def __init__(self, local_conn, address, strip_cache_headers, strip_user_agent):

        self.local_conn = local_conn
        self.socket_family = local_conn.family
        self.socket_type = local_conn.type
        self.address = address

        local_request  = local_conn.recv(BUFFER_LENGTH)

        # if empty, throw exception
        if local_request == b'':
            raise InvalidRequest("Request is empty.")

        self.decoded_client_request = HttpRequest(bytes.decode(local_request))
        self.port = self.decoded_client_request.get_port()

        # strip cache and user-agent headers, if applicable
        if strip_cache_headers:
            self.decoded_client_request.strip_cache_headers()
        if strip_user_agent:
            self.decoded_client_request.strip_user_agent()

        # use non-persistent HTTP connection
        self.decoded_client_request.set_connection_close()
            
        print("--- Client -> Proxy Request ---\n%s" % (self.decoded_client_request.get_original_request()))
                    
    def execute(self, log, cache):
        '''
        Execute the client request. If the proxy cache contains the response for the request,
        forward this response back directly from the cache. Otherwise, contact the server
        to retrieve the information.
        '''

        try:
            # the md5hash of the modified request is used as the request ID
            md5hash = hashlib.md5()
            md5hash.update(str.encode(self.decoded_client_request.get_modified_request()))
            request_digest = md5hash.hexdigest()
            response_size = 0

            host = self.decoded_client_request.get_host_name()

            # if request has been cached, return the response to the client directly from the cache
            if  self.decoded_client_request.method == 'GET' and request_digest in cache.table:

                cached = cache.get(request_digest)
                response_size = len(cached)
                total_sent = 0

                while total_sent < response_size:
                    sent = self.local_conn.send(cached)
                    total_sent += sent

                print("%s forwarded from cache.\n" % (request_digest))

            else: 
                # get the information from the server
                remote_conn = socket.socket(self.socket_family, self.socket_type)
                remote_conn.connect((host, self.port))
                remote_conn.settimeout(10.0) # time out after 10 seconds

                if  self.decoded_client_request.method == 'CONNECT':
                    self.local_conn.send(HTTP_VERSION+' 200 Connection established\nProxy-agent: %s\n\n'%PROXY_NAME)
                else:
                    # method is 'GET'
                    print("--- Proxy -> Server Request ---\n%s" % (self.decoded_client_request.get_modified_request()))
                    request_size = len(self.decoded_client_request.get_modified_request())                            
                    total_sent = 0

                    # send the request to the server
                    while total_sent < request_size:
                        sent = remote_conn.send(str.encode(self.decoded_client_request.get_modified_request()))
                        total_sent += sent

                # send the response to the client
                response = b''
                while True:
                    recvd = remote_conn.recv(BUFFER_LENGTH)
                    if len(recvd) > 0:
                        self.local_conn.send(recvd)
                        response += recvd
                    else:
                        break

                response_size = len(response)
                print("--- Server Response Fowarded ---\n")
                remote_conn.close()

                # add response to cache
                if  self.decoded_client_request.method == 'GET' :
                    cache.insert(request_digest, response, response_size)
                            
            # convert hostname to IP address
            ip = socket.gethostbyname(host)
            
            # acquire lock and write to file
            log.append(ip, response_size)

        except:
            # exit gracefully
            if cache.lock.locked():
                cache.lock.release()

class ProxyConn:
    '''
    A proxy connection, between a client and server. This creates the request data structures
    and then executes the request.
    '''
                
    def __init__(self, client_conn, address, strip_cache_headers, strip_user_agent, timeout, log, cache):
        self.client_conn = client_conn
        self.remote_conn  = None
        self.timeout = timeout
        self.cache = cache

        try:
            self.request = ClientRequest(self.client_conn, address, strip_cache_headers, strip_user_agent)
            self.request.execute(log, cache)
        except InvalidRequest:
            pass

        self.client_conn.close()

class InvalidRequest(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Log:
    '''
    The proxy log, consisting of the log file and the log lock.
    '''

    def __init__(self):
        self.log_file = open('proxy.log', 'a')
        self.log_lock = threading.Lock()

    def close(self):
        self.log_file.close()

    def append(self, ip, response_size):
        '''
        Acquire the log lock and then append the request/response information.
        '''
        self.log_lock.acquire()
        self.log_file.write("%s %s %i\n" % (str(datetime.datetime.now()), ip, response_size))
        self.log_lock.release()

def start_server(host='localhost', port=4444, IPv6=False, strip_cache_headers=True, strip_user_agent=True, timeout=30):
    '''
    Start the proxy server socket and spawn ProxyConnections for each incoming client conneciton.
    '''

    # socket settings
    if IPv6:
        socket_family = socket.AF_INET6
    else:
        socket_family = socket.AF_INET

    socket_type = socket.SOCK_STREAM

    # initialize log and cache
    log = Log()
    cache = Cache(CACHE_SIZE)
        
    try:
        # initialize socket
        server_socket = socket.socket(socket_family, socket_type)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # may be removed in production setting
        server_socket.bind((host, port))
        server_socket.listen(5)

        while True:
            (client_socket, address) = server_socket.accept()
            print("Proxy connected to client ", address, "\n")
            threading.Thread(target=ProxyConn, args=(client_socket, address, strip_cache_headers, strip_user_agent, timeout, log, cache)).start()
            
    except KeyboardInterrupt:
        print("Ctrl+C  detected...")
    except:
        print("Unexpected exception detected...")

    print("Closing server socket...")
    server_socket.close()
    print("\nClosing log file...")
    log.close()
    print("Goodbye.")

if __name__ == '__main__':        

    if not os.path.exists('cache'):
        os.makedirs('cache')
    
    print("Starting %s." % (PROXY_NAME))
    if len(sys.argv) > 1:
        start_server(port=int(sys.argv[1]))
    else:
        start_server()
