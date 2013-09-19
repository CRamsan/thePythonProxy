#!/usr/bin/python2

import socket
import thread
import select

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGHT = 1024 * 8

class ProxyConnection:
   def __init__(self, connection, address, timeout):
      self.client = connection
      self.client_buffer = ''
      self.timeout = timeout
      data = self.get_base_header()
      self.method = data[0]
      self.path = data[1]
      self.protocol = data[2]
      self.process()      
      self.client.close()
      self.target.close()

   def get_base_header(self):
      while 1:
         self.client_buffer += self.client.recv(BUFFER_LENGHT)
         end = self.client_buffer.find('\n')
         if end != -1:
            break
      print '%s'%self.client_buffer[:end]
      data = (self.client_buffer[:end+1]).split()
      self.client_buffer = self.client_buffer[end+1:]
      return data

   def process(self):
      self.path = self.path[7:]
      i = self.path.find('/')
      host = self.path[:i]
      path = self.path[i:]
      self.remoteConnect(host)
      self.target.send('%s %s %s\n'%(self.method, path, self.protocol)+self.client_buffer)
      self.client_buffer = ''
      self.localConnect()


   def remoteConnect(self, host):
      i = host.find(':')
      if i!=-1:
         port = int(host[i+1:])
         host = host[:i]
      else:
         port = 80
      (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
      self.target = socket.socket(soc_family)
      self.target.connect(address)

   def localConnect(self):
      time_out_max = self.timeout
      socs = [self.client, self.target]
      count = 0
      while 1:
         count += 1
         (recv, _, error) = select.select(socs, [], socs, 3)
         if error:
            break
         if recv:
            for in_ in recv:
               data = in_.recv(BUFFER_LENGHT)
               if in_ is self.client:
                  out = self.target
               else:
                  out = self.client
               if data:
                  out.send(data)
                  count = 0
            if count == time_out_max:
               break

def start(host='localhost', port=1234, IPv6=False, timeout=30, handler=ProxyConnection):
   if IPv6==True:
      soc_family=socket.AF_INET6
   else:
      soc_family=socket.AF_INET
   soc = socket.socket(soc_family)
   soc.bind((host, port))
   print "Listening on %s:%d."%(host, port)
   soc.listen(0)
   while 1:
      thread.start_new_thread(handler, soc.accept()+(timeout,))

if __name__ == '__main__':
   start()
