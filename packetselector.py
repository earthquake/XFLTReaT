# MIT License

# Copyright (c) 2017 Balazs Bucsay

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

if "packetselector.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

# This is the engine of the whole communication. Every packet that arrives to 
# the tunnel will be carefully selected. In case the destination IP matches, it
# will be redirected (written) to the appropriate client pipe.

import threading
import os
import select
import struct
import socket

from client import Client

class PacketSelector(threading.Thread):
	clients = None

	def __init__(self, tunnel):
		threading.Thread.__init__(self)
		self.timeout = 1.0 # seems to be a good value for timeout
		self.clients = []
		self.tunnel = tunnel
		self._stop = False

	# return client list
	def get_clients(self):

		return self.clients

	# add new client to the client list
	def add_client(self, client):
		self.clients.append(client)

		return

	# This function is called when a client object has to be replaced.
	# That could happen when the client connection was reset, or there is a
	# duplicated config with the same private IP.
	def replace_client(self, old_client, new_client):
		if old_client in self.clients:
			self.clients.remove(old_client)
			self.clients.append(new_client)
			try:
				old_client.get_pipe_w_fd().close()
			except:
				pass
			try:
				old_client.get_pipe_r_fd().close()
			except:
				pass
			try:
				socket.close(old_client.get_socket())
			except:
				pass

	# removing client from the client list
	def delete_client(self, client):
		if client in self.clients:
			self.clients.remove(client)

		return


	# This function should run since the framework was started. It runs in an
	# infinite loop to read the packets off the tunnel.
	# When an IPv4 packet was found that will be selected and checked whether
	# it addresses a client in the client list. If a client was found, then the
	# packet will be written on that pipe.
	def run(self):
		rlist = [self.tunnel]
		wlist = []
		xlist = []

		while not self._stop:
			try:
				readable, writable, exceptional = select.select(rlist, wlist, xlist, self.timeout)
			except select.error, e:
				print e
				break

			for s in readable:
				# is there anything on the tunnel interface?
				if s is self.tunnel:
					# yes there is, read the packet or packets off the tunnel
					message = os.read(self.tunnel, 4096)
					while True:
						# dumb check, but seems to be working. The packet has 
						# to be longer than 4 and it must be IPv4
						if (len(message) < 4) and (message[0:1] != "\x45"): #Only care about IPv4
							break
						packetlen = struct.unpack(">H", message[2:4])[0]
						if packetlen == 0:
							break
						# is the rest less than the packet length?
						if packetlen > len(message):
							# in case it is less, we need to read more
							message += os.read(self.tunnel, 4096)
						readytogo = message[0:packetlen]
						message = message[packetlen:]
						# looking for client
						for c in self.clients:
							if c.get_private_ip_addr() == readytogo[16:20]:
								# client found, writing packet on client's pipe
								os.write(c.get_pipe_w(), readytogo)
								# flushing, no buffering please
								c.get_pipe_w_fd().flush()

		return

	# stop the so called infinite loop
	def stop(self):
		self._stop = True

		return