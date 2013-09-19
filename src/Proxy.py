#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGHT = 1024 * 8

class ProxyConnection:
   def __init__(self, connection, address, timeout):
      pass

   def get_base_header(self):
      pass

   def process(self):
      pass

   def remoteConnect(self, host):
      pass

   def localConnect(self):
      pass

def start(host='localhost', port=1234, IPv6=False, timeout=30, handler=ProxyConnection):
   pass

if __name__ == '__main__':
   start()
