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

if "Stateless_module.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading

#local files
import modules.Generic_module as Generic_module
from interface import Interface
import controlchannel
import client
import common
import encryption
import threading
import checks

class Stateless_module(Generic_module.Generic_module):
	def __init__(self):
		super(Stateless_module, self).__init__()
		self.checks = checks.Checks()
		self.timeout = 1.0
		self.controlchannel = controlchannel.ControlChannel()

		# control message handlers
		self.cmh_struct  = {
			# num : [string to look for, function, server(1) or client(0), return on success, return on failure]
			# return value meanings: True  - module continues
			#						 False - module thread terminates
			# in case of Stateless modules, the whole module terminates if the return value is False
			0  : [common.CONTROL_CHECK, 		self.controlchannel.cmh_check_query, 1, True, True],
			1  : [common.CONTROL_CHECK_RESULT, 	self.controlchannel.cmh_check_check, 0, True, False],
			2  : [common.CONTROL_INIT, 			self.controlchannel.cmh_init, 1, True, True],
			3  : [common.CONTROL_INIT_DONE, 	self.controlchannel.cmh_init_done, 0, True, False],
			4  : [common.CONTROL_LOGOFF, 		self.controlchannel.cmh_logoff, 1, True, False],
			5  : [common.CONTROL_DUMMY_PACKET, 	self.controlchannel.cmh_dummy_packet, 1, True, True],
		}

		# reading/writing packets can be different based on the OS
		self.packet_writer = self.packet_writer_default
		self.packet_reader = self.packet_reader_default
		# different communication function for Unix and Windows
		self.communication = self.communication_unix

		# setting up for Windows
		if self.os_type == common.OS_WINDOWS:
			self.packet_writer = self.packet_writer_win
			self.communication = self.communication_win
			self.packet_reader = None

		# setting up for MacOS(X)
		if self.os_type == common.OS_MACOSX:
			self.packet_writer = self.packet_writer_mac
			self.packet_reader = self.packet_reader_mac

		return

	# hacky solution to decide from non-transport modules whether this module
	# is stateless or stateful
	def is_caller_stateless(self):
		return 1

	# is the new cmh list already in the control message handler structure?
	def is_in_cmh_already(self, _list):
		if len(_list) and len(self.cmh_struct):
			found = False
			for l in self.cmh_struct:
				if self.cmh_struct[l] == _list[0]:
					found = True

		return found

	# merging control message handlers into the Stateless' cmh list
	def merge_cmh(self, _list):
		if self.is_in_cmh_already(_list):
			return
		size = len(self.cmh_struct)
		for entry in _list:
			self.cmh_struct[size+entry] = _list[entry]

	# This function writes the packet to the tunnel.
	# Windows version of the packet writer
	def packet_writer_win(self, packet):
		import pywintypes
		import win32file

		overlapped_write = pywintypes.OVERLAPPED()
		win32file.WriteFile(self.tunnel, packet, overlapped_write)
		return

	# on MacOS(X) utun, all packets needs to be prefixed with 4 specific bytes
	def packet_writer_mac(self, packet):
		packet = "\x00\x00\x00\x02"+packet
		os.write(self.tunnel, packet)

	# default packet writer for Linux
	def packet_writer_default(self, packet):
		os.write(self.tunnel, packet)

	# This function reades the packet from the tunnel.
	# on MacOS(X) utun, all packets needs to be prefixed with 4 specific bytes
	# this will take off the prefix if that is needed
	# first_read True: discard the first 4 bytes / utun related
	# serverorclient 1: server, there is no 4byte prefix, it comes fro the PS
	#				 0: client, it comes from the tunnel iface directly
	def packet_reader_mac(self, tunnel, first_read, serverorclient):
		packet = os.read(tunnel, 4096)
		if first_read and not serverorclient:
			packet = packet[4:]
		return packet

	# for Linux and other unices
	# Windows is handled from the communication() unfortunately
	def packet_reader_default(self, tunnel, first_read, serverorclient):
		packet = os.read(tunnel, 4096)
		return packet

	# function to transform packets back and forth.
	# encryption, encodings anything that should be done on the packet and 
	# should be easily variable based on the config
	def transform(self, details, packet, encrypt):
		if details.get_encrypted():
			if encrypt:
				return details.get_module().encrypt(details.get_shared_key(), packet)
			else:
				return details.get_module().decrypt(details.get_shared_key(), packet)
		else:
			return packet

	# if non-transport modules (encryption, authentication) need to modify
	# some data between recv() and send(), this function should be used
	def modify_additional_data(self, additional_data, serverorclient):
		return additional_data

	# looking for client, based on the private IP
	def lookup_client_priv(self, msg):
		client_private_ip = msg[16:20]

		for c in self.clients:
			if c.get_private_ip_addr() == client_private_ip:
				return c

		return None

	# find client object based on public details (IP, identifier, etc.)
	def lookup_client_pub(self, additional_data):
		addr = additional_data[0]
		client_public_ip = socket.inet_aton(addr[0])

		for c in self.clients:
			if (c.get_public_ip_addr() == client_public_ip) and (c.get_public_src_port() == addr[1]):
				return c

		return None

	# find the encryption details of the client
	def get_client_encryption(self, additional_data):
		if self.serverorclient:
			# server mode
			# select client, based on public details
			c = self.lookup_client_pub(additional_data)
			if c:
				# if found, return object's encryption details
				return c.get_encryption()
			else:
				# this must be a new client, creating new encryption object
				e = encryption.Encryption_details()
				e.set_module(self.encryption_module)
				return e
		else:
			# client mode
			return self.encryption

	# set up the Client object for a new client
	def init_client(self, control_message, additional_data):
		addr = additional_data[0]
		client_local = client.Client()

		# stripping out the private IP from the message
		client_private_ip = control_message[0:4]
		# saving public IP address and port
		client_public_source_ip = socket.inet_aton(addr[0])
		client_public_source_port = addr[1]

		# If this private IP is already used, the server removes that client.
		# For example: client reconnect on connection reset, duplicated configs
		# and yes, this can be used to kick somebody off the tunnel

		# close client related pipes
		for c in self.clients:
			# find and remove client from module's list
			if c.get_private_ip_addr() == client_private_ip:
				save_to_close = c
				self.clients.remove(c)
				if c.get_pipe_r() in self.rlist:
					if self.os_type == common.OS_WINDOWS:
						# removing client related elements from lists
						idx = 0
						while self.rlist[idx] != c.get_pipe_r():
							idx += 1
						if idx < len(self.rlist):
							self.olist = self.olist[:idx] + self.olist[idx+1:]
							self.elist = self.elist[:idx] + self.elist[idx+1:]
							self.mlist = self.mlist[:idx] + self.mlist[idx+1:]
						else:
							self.olist = self.olist[:idx]
							self.elist = self.elist[:idx]
							self.mlist = self.mlist[:idx]

						self.ulist.remove(idx)
					self.rlist.remove(c.get_pipe_r())

		found = False
		for c in self.packetselector.get_clients():
			# find and remove client from packetselector's list
			if c.get_private_ip_addr() == client_private_ip:
				found = True
				self.packetselector.delete_client(c)

		# If client was created but not added to the PacketSelector, then the
		# pipes still need to be closed. This could happen when the authenti-
		# cation fails or gets interrupted.
		if not found:
			if self.os_type == common.OS_WINDOWS:
				import win32file

				try:
					win32file.CloseHandle(save_to_close.get_pipe_r())
					win32file.CloseHandle(save_to_close.get_pipe_w())
				except:
					pass
			else:
				try:
					save_to_close.get_pipe_r_fd().close()
					save_to_close.get_pipe_w_fd().close()
				except:
					pass


		# creating new pipes for the client
		if self.os_type == common.OS_WINDOWS:
			import win32pipe
			import win32file
			import pywintypes
			import win32event

			import win32api
			import winerror

			overlapped = pywintypes.OVERLAPPED()
			# setting up nameslot
			mailslotname = "\\\\.\\mailslot\\XFLTReaT_{0}".format(socket.inet_ntoa(client_private_ip))

			mailslot_r = win32file.CreateMailslot(mailslotname, 0, -1, None)
			if (mailslot_r == None) or (mailslot_r == win32file.INVALID_HANDLE_VALUE):
				internal_print("Invalid handle - mailslot", -1)
				sys.exit(-1)

			mailslot_w = win32file.CreateFile(mailslotname, win32file.GENERIC_WRITE,
				win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE, None, win32file.OPEN_EXISTING,
				win32file.FILE_ATTRIBUTE_NORMAL | win32file.FILE_FLAG_OVERLAPPED, None)
			if (mailslot_w == None) or (mailslot_w == win32file.INVALID_HANDLE_VALUE):
				internal_print("Invalid handle - readable pipe", -1)
				sys.exit(-1)

			client_local.set_pipes_fdnum(mailslot_r, mailslot_w)

		else:
			pipe_r, pipe_w = os.pipe()
			client_local.set_pipes_fdnum(pipe_r, pipe_w)
			client_local.set_pipes_fd(os.fdopen(pipe_r, "r"), os.fdopen(pipe_w, "w"))

		# set connection related things and authenticated to True
		client_local.set_public_ip_addr(client_public_source_ip)
		client_local.set_public_src_port(client_public_source_port)
		client_local.set_private_ip_addr(client_private_ip)

		client_local.get_encryption().set_module(self.encryption.get_module())
		self.encryption = client_local.get_encryption()

		if self.encryption.get_module().get_step_count():
			# add encryption steps
			self.merge_cmh(self.encryption.get_module().get_cmh_struct())

		if self.authentication.get_step_count():
			# add authentication steps
			self.merge_cmh(self.authentication.get_cmh_struct())

		client_local.set_initiated(True)
		self.clients.append(client_local)

		return

	# removing client from lists
	def remove_initiated_client(self, control_message, additional_data):
		c = self.lookup_client_pub(additional_data)
		if c:
			# from packetselector, clients list and rlist
			self.packetselector.delete_client(c)
			if c.get_authenticated():
				if self.os_type == common.OS_WINDOWS:
					# removing client related elements from lists
					idx = 0
					while self.rlist[idx] != c.get_pipe_r():
						idx += 1
					if idx < len(self.rlist):
						self.olist = self.olist[:idx] + self.olist[idx+1:]
						self.elist = self.elist[:idx] + self.elist[idx+1:]
						self.mlist = self.mlist[:idx] + self.mlist[idx+1:]
					else:
						self.olist = self.olist[:idx]
						self.elist = self.elist[:idx]
						self.mlist = self.mlist[:idx]
					if idx in self.ulist:
						self.ulist.remove(idx)
				self.rlist.remove(c.get_pipe_r())
			self.clients.remove(c)

		return

	# client side
	# after the init was done, this function is called 
	def post_init_client(self, control_message, additional_data):
		if not self.encryption.get_module().get_step_count():
			# no encryption
			self.post_encryption_client(control_message, additional_data)
		else:
			# add encryption steps
			self.merge_cmh(self.encryption.get_module().get_cmh_struct())
			# get and send encryption initialization message
			message = self.encryption.get_module().encryption_init_msg()
			self.send(common.CONTROL_CHANNEL_BYTE, message, self.modify_additional_data(additional_data, 0))

		return


	# server side
	# after the init was done, this function is called 
	# PLACEHOLDER for future needs
	def post_init_server(self, control_message, additional_data):

		return

	# client side
	# after the encryption part was done, this function is called
	def post_encryption_client(self, control_message, additional_data):
		if not self.authentication.get_step_count():
			# no encryption
			self.post_authentication_client()
		else:
			# add encryption steps
			self.merge_cmh(self.authentication.get_cmh_struct())
			# get and send encryption initialization message

			message = self.authentication.authentication_init_msg()
			self.send(common.CONTROL_CHANNEL_BYTE, message, self.modify_additional_data(additional_data, 0))
		

		return

	# server side
	# after the encryption part was done, this function is called
	# PLACEHOLDER for future needs
	def post_encryption_server(self, control_message, additional_data):

		return

	# client side
	# after the authentication part was done, this function is called
	def post_authentication_client(self, control_message, additional_data):
		self.authenticated = True

		return

	# server side
	# if the client was initiated (first step was not skipped), then set
	# the authenticated flag to True, add to packetselector and allow access
	# the read only pipe (packets selected for the client)
	def post_authentication_server(self, control_message, additional_data):
		c = self.lookup_client_pub(additional_data)
		if c.get_initiated():
			c.set_authenticated(True)
			self.packetselector.add_client(c)
			if c.get_pipe_r() not in self.rlist:
				self.rlist.append(c.get_pipe_r())
				if self.os_type == common.OS_WINDOWS:
					# creating objects and adding to corresponding lists
					import win32event
					import win32file
					import pywintypes

					hEvent_pipe = win32event.CreateEvent(None, 0, 0, None) # for reading from the pipe
					overlapped_pipe = pywintypes.OVERLAPPED()
					overlapped_pipe.hEvent = hEvent_pipe
					message_buffer = win32file.AllocateReadBuffer(4096)
					self.olist.append(overlapped_pipe)
					self.elist.append(hEvent_pipe)
					self.mlist.append(message_buffer)
					self.ulist.append(len(self.elist)-1)
			return True

		return False

	# PLACEHOLDER: prolog for the communication
	# What comes here: anything that should be set up before the actual
	# communication
	def communication_initialization(self):
		self.clients = []
		return

	# PLACEHOLDER: check function
	# What comes here: generate challenge and send to the server
	def do_check(self):

		return

	# PLACEHOLDER: authentication to the server
	# What comes here: generate authentication message and send to the server
	def do_hello(self):

		return

	# PLACEHOLDER: logoff function
	# What comes here: send message to the server about leaving
	def do_logoff(self):

		return

	# PLACEHOLDER: implementation of wrapping and sending message
	# What comes here: marking message (control or data), transforming (see
	# transform()), prepending with length, sending on the appropriate channel
	def send(self, channel_type, message, additional_data):

		return

	# PLACEHOLDER: implementation of recvieving and unpacking the message
	# What comes here: reading the first two bytes to determine length, reading
	# the full packet, transforming it to the original format (see transform())
	def recv(self):

		return

	# PLACEHOLDER: cleanup
	# What comes here: close() all sockets, do everything that should be done
	# to prepare for the exit process
	def cleanup(self):

		return

	# PLACEHOLDER: communication function
	# What comes here: this is the tricky part, where everything is handled 
	# that matters.
	# for unices
	def communication_unix(self, is_check):

		return

	# for windows
	def communication_win(self, is_check):

		return
