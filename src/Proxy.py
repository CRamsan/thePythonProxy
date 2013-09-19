#!/usr/bin/python

PROXY_NAME = 'Perry, the Python Proxy'
HTTP_VERSION = 'HTTP/1.1'
BUFFER_LENGHT = 1024 * 8

import threading
import socket

class ProxyConnection:
	def __init__(self, connection, address, timeout):
		self.local_connection = connection
		self.remote_connection  = None
		self.conn_buffer = ''
		self.timeout = timeout

		data = self._get_base_header()
		self.method = data[0]
		self.path = data[1]
		self.protocol = data [2]

		self._forwarding()

		self._remote_connection.close()
		self._local_connection.close()

	def _get_base_header(self):
		pass

	def _forwarding(self):
		pass

	def _remoteConnect(self, host):
		pass

	def _localConnect(self):
		pass

def start(host='localhost', port=1234, IPv6=False, timeout=30, handler=ProxyConnection):
	if IPv6:
		socket_family = socket.AF_INET6
	else:
		socket_family = socket.AF_INET
	
	listen_socket = socket(family=socket_family, sockaddr=(host, port))
	
	while True:
		Thread(target=handler,args=(listen_socket.connect()+timeout)).start()

if __name__ == '__main__':
	start()
