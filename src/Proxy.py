#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8

import threading
import socket
import sys
import re
import os
import signal
import random
import datetime
import hashlib
import pdb

'''
This cache follows a Least-Recently-Used model with all operations running 
in constant time under optimal circumstances.

Each entry of the cache is a 3-tuple containing: 
[Pointer_to_previous_entry, [key, size], Pointer_to_next_entry]
'key' is used as the name of the file that contains the cached data
'size' is the size in bytes of the content in the file

This structure allows to keep track of all the entries in the way of a queue.
Each entry is apended at the begining of the queue and when the cache is full
the last entry is removed

There is also a dictionary that will keep track of each entry, with this we can
achieve reading operations in constant time.
'''

class Cache:
    
    class Entry:
        def __init__(self, key, size, previous_entry, next_entry):
            self.previous_entry = previous_entry
            self.key = key
            self.size = size
            self.next_entry = next_entry

        def read_file(self):
            cache_file = open("cache/"+str(self.key), 'rb')
            content = cache_file.read()
            return content
            
        def create_file(self, data):
            cache_file = open("cache/"+str(self.key), 'wb')
            cache_file.write(data)

        def delete_file(self):
            os.remove("cache/"+str(self.key))            
                        
        def print_queue(self):
            print (self.key)
            if self.next_entry != None:
                self.next_entry.print_queue()
    
    def __init__(self, max_size):
        self.first = None
        self.last = None
        self.table = {}
        self.current_size = 0
        self.max_size = max_size
    
    def put(self, uri, content, size, create=True):
        if uri not in self.table:
            if(size > self.max_size):
                print ("Object's size is exceeds the limit for this cache")
                return
            else:
                # The item fits in the cache but some items need to be removed first
                if(create and self.current_size + size > self.max_size):
                    while True:
                        #Get the size and key of the entry to be removed
                        del_size = self.last.size
                        del_key = self.last.key
                        #Remove the file
                        self.last.delete_file()                    
                        #Move the self.last pointer to the previous entry
                        pre_entry = self.last.previous_entry
                        self.last = pre_entry 
                        #Remove a reference to the previous-last entry from
                        #the dictionary
                        del self.table[del_key]
                        #The last entry does not have a 'next' entry
                        self.last.next_entry = None
                        #Substract the file size
                        self.current_size -= del_size
                        # Check if new entry will fit after last item was removed
                        if(self.current_size + size <= self.max_size):
                            break
                    
            # Handle if the cache is empty
            if self.first == None:
                new_first = self.Entry(uri, size, None, None)
                self.first = new_first
                self.last = new_first
                self.table[uri] = new_first
                print ("First object added to the cache")                
            else:
                #Set the new entry as the first in the queue
                new_first = self.Entry(uri, size, None, self.first)
                self.first.previous_entry = new_first
                self.table[uri] = new_first
                self.first = new_first
                print ("Object set as first in the cache")
            
            #create=False means the file does not need to be created.
            if create:
                self.first.create_file(content)
                self.current_size += size
        #If entry is already in queue    
        else:
            #Get references for the current entry, as well as the next 
            #and previous ones
            old_entry = self.table[uri]
            pre_entry = old_entry.previous_entry
            next_entry = old_entry.next_entry
            
            if pre_entry == None :
                print ("Object is already first in cache")
                return
            
            #If the entry is not the last one
            if next_entry != None :
                #remove the reference to the current entry by making 
                #the next entry point straight to the previous entry 
                next_entry.previous_entry = pre_entry
            else:
                #Move the self.last pointer one position and remove the 
                #reference to the current pointer
                new_last = self.last.previous_entry
                self.last = new_last
                self.last.next_entry = None

            #remove the reference to the current entry by making 
            #the previous entry point straight to the next entry                                  
            pre_entry.next_entry = next_entry
            
            #remove the last reference to the current entry by removing
            #the respective entry in the dictionary
            del self.table[uri]

            #The object is still cached on disk but we have removed all 
            #references in-memory. Now we will add the entry again, set 
            #the create flag to denote that the file does not need to be
            #created again 
            print ("Object is getting poked")
            self.put(uri,content,size,False)
    
    def get(self, uri):
        if uri in self.table:
            found = self.table[uri]
            self.put(uri,None,found.size)
            return found.read_file()
    
    def queue(self):
        self.first.print_queue()
        
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
                request_digest = md5hash.hexdigest()
                response_size = 0
                
                if cache.get(request_digest) == None : # connect to remote server
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
                                    
                    remote_conn.close()
                    cache.put(request_digest, response, response_size)
                
                else: #retrieve from cache
                    cached = cache.get(request_digest)
                    response_size = len(cached)
                    sent = self.local_conn.send(cached)

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
cache = Cache(10000)

if __name__ == '__main__':        

    if not os.path.exists('cache'):
        os.makedirs('cache')
    
    print("Starting %s." % (PROXY_NAME))
    if len(sys.argv) > 1:
        start_server(log_file, cache, port=int(sys.argv[1]))
    else:
        start_server(log_file, cache)
