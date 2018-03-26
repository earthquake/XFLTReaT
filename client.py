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

if "client.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)


import Queue

# python 2.7 hack to have inheritance. Without the metaclass, the inhericance
# fails
__metaclass__ = type
class Client():
	def __init__(self):
		self.public_ip_addr = None
		self.public_src_port = None
		self.private_ip_addr = None
		self.socket = None
		self.pipe_r = None
		self.pipe_w = None
		self.pipe_r_fd = None
		self.pipe_w_fd = None
		self.stopfp = None
		#TODO
		self.authenticated = False
		self.encryption_key = None

	# setting the public IP address of the client
	def set_public_ip_addr(self, public_ip_addr):
		self.public_ip_addr = public_ip_addr

		return

	# getting the public IP address of the client
	def get_public_ip_addr(self):
		return self.public_ip_addr


	# setting the public source port of the client
	def set_public_src_port(self, public_src_port):
		self.public_src_port = public_src_port

		return

	# getting the public source port of the client
	def get_public_src_port(self):
		return self.public_src_port


	# setting the private IP address of the client
	def set_private_ip_addr(self, private_ip_addr):
		self.private_ip_addr = private_ip_addr

		return

	# getting the private IP address of the client
	def get_private_ip_addr(self):
		return self.private_ip_addr


	# setting the socket for the client
	def set_socket(self, socket):
		self.socket = socket

		return

	# getting the socket for the client
	def get_socket(self):
		return self.socket

	# setting the file descriptor numbers of the pipes (these are used to 
	# replace the need of direct accessing the tunnel interface)
	def set_pipes_fdnum(self, pipe_r, pipe_w):
		self.pipe_r = pipe_r
		self.pipe_w = pipe_w

		return

	# get readable pipe file descriptor number
	def get_pipe_r(self):
		return self.pipe_r

	# get writeable pipe file descriptor number
	def get_pipe_w(self):
		return self.pipe_w

	# setting the file descriptors of the pipes (these are used to replace the
	# need of direct accessing the tunnel interface)
	def set_pipes_fd(self, pipe_r_fd, pipe_w_fd):
		self.pipe_r_fd = pipe_r_fd
		self.pipe_w_fd = pipe_w_fd

		return

	# get readable pipe file descriptor
	def get_pipe_r_fd(self):
		return self.pipe_r_fd

	# get writeable pipe file descriptor
	def get_pipe_w_fd(self):
		return self.pipe_w_fd

	# TODO
	# set client authenticated (True/False)
	def set_authenticated(self, value):
		self.authenticated = value

	# get client's authentication status:
	# True:  authenticated
	# False: not authenticated
	def get_authenticated(self):
		return self.authenticated

	# function pointer to the module's stop()
	def set_stopfp(self, stopfp):
		self.stopfp = stopfp

	# if stateless and stop() saved, call it
	def call_stopfp(self):
		if self.stopfp:
			self.stopfp()