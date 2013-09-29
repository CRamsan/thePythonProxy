#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGTH = 1024 * 8

import threading, socket, sys, re, signal, datetime, hashlib

class ClientRequest:

    def __init__(self, local_conn, address, strip_cache_headers, strip_user_agent):

        self.local_conn = local_conn
        self.socket_family = local_conn.family
        self.socket_type = local_conn.type
        self.address = address
        self.port = 80
        self.strip_cache_headers = strip_cache_headers
        self.strip_user_agent = strip_user_agent

        self.client_request = local_conn.recv(BUFFER_LENGTH)

        decoded_client_request = bytes.decode(self.client_request)

        # modify request file URL (and anonymize, if applicable)
        self.modify_request(decoded_client_request)

    def modify_request(self, decoded_request):

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
            self.requested_file = host_and_file[backslash_index:]
                
            modified_first_line = "%s %s %s" % (self.method, self.requested_file, self.protocol)
            decoded_request = modified_first_line + decoded_request[first_newline:]

            # changed "Connection: keep-alive" to "Connection: close" (with 'keep-alive', the recv() from the remote server would take forever,
            # since it would block until the remote server closed the connection). Another way to fix the problem would be to actually 
            # handle a 'keep-alive' connection properly, but this works for now
            decoded_request = re.sub(r'Connection: keep-alive', 'Connection: close', decoded_request, flags=(re.IGNORECASE | re.MULTILINE) )

            if self.strip_cache_headers:
                # strip 'If-Modified-Since', 'If-None-Match', and 'Cache-Control' fields
                decoded_request = re.sub(r'If-Modified-Since:.*?\n', '', decoded_request, flags=(re.IGNORECASE | re.MULTILINE))
                decoded_request = re.sub(r'If-None-Match:.*?\n', '', decoded_request, flags=(re.IGNORECASE | re.MULTILINE))
                decoded_request = re.sub(r'Cache-Control:.*?\n', '', decoded_request, flags=(re.IGNORECASE | re.MULTILINE))

            if self.strip_user_agent:
                # strip 'User-Agent' field
                decoded_request = re.sub(r'User-Agent:.*?\n', '', decoded_request, flags=(re.IGNORECASE | re.MULTILINE))

            self.client_request = str.encode(decoded_request)                        

        else:
            self.method = None

    def execute(self, lock, cache):

        try:
            
            if self.method == 'GET':

                md5hash = hashlib.md5()
                md5hash.update(self.client_request)
                request_digest = md5hash.digest()
                response_size = 0
            
                # convert hostname to IP address
                ip = socket.gethostbyname(self.host)
                
                if request_digest not in cache: # connect to remote server
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
                    cache[request_digest] = response
                
                else: #retrieve from cache
                    cached = cache[request_digest]
                    response_size = len(cached)
                    total_sent = 0

                    while total_sent < response_size:
                        sent = self.local_conn.send(cached)
                        total_sent += sent

                    print("** %s%s served from cache.\n" % (self.host, self.requested_file))

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
