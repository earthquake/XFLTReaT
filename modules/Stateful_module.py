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

if "Stateful_module.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading


#local files
from Generic_module import Generic_module
from interface import Interface
import controlchannel
import client
import common
import threading
import checks

class Stateful_thread(threading.Thread):
	def __init__(self):
		super(Stateful_thread, self).__init__()
		self.os_type = common.get_os_type()
		self.checks = checks.Checks()
		self.controlchannel = controlchannel.ControlChannel()

		# control message handlers
		self.cmh_struct  = {
			# num : [string to look for, function, server(1) or client(0), return on success, return on failure]
			# return value meanings: True  - module continues
			#						 False - module thread terminates
			# in case of Stateless modules, the whole module terminates if the return value is False
			0  : [common.CONTROL_CHECK, 		self.controlchannel.cmh_check_query, 1, True, False],
			1  : [common.CONTROL_CHECK_RESULT, 	self.controlchannel.cmh_check_check, 0, True, False],
			2  : [common.CONTROL_AUTH, 			self.controlchannel.cmh_auth, 1, True, False],
			3  : [common.CONTROL_AUTH_OK, 		self.controlchannel.cmh_auth_ok, 0, True, False],
			4  : [common.CONTROL_AUTH_NOTOK, 	self.controlchannel.cmh_auth_not_ok, 0, True, False],
			5  : [common.CONTROL_LOGOFF, 		self.controlchannel.cmh_logoff, 1, False, False]
		}

		self.packet_writer = self.packet_writer_default
		self.packet_reader = self.packet_reader_default
		self.communication = self.communication_unix

		if self.os_type == common.OS_WINDOWS:
			self.packet_writer = self.packet_writer_win
			self.communication = self.communication_win
			self.packet_reader = None

		if self.os_type == common.OS_MACOSX:
			self.packet_writer = self.packet_writer_mac
			self.packet_reader = self.packet_reader_mac

		return

	def auth_ok_setup(self, additional_data):
		self.tunnel_r = self.tunnel_w
		return


	def setup_authenticated_client(self, control_message, additional_data):
		common.init_client_stateful(control_message, self.client_addr, self.client, self.packetselector, self.stop)
		self.client.set_socket(self.comms_socket)
		self.tunnel_r = self.client.get_pipe_r()
		self.packetselector.add_client(self.client)
		self.authenticated = self.client.get_authenticated()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH_OK, additional_data)

		return

	def remove_authenticated_client(self, additional_data):
		# module should remove the client on server side in cleanup()
		return

	# This function writes the packet to the tunnel.
	# Windows version of the packet writer
	def packet_writer_win(self, packet):
		import pywintypes
		import win32file

		overlapped_write = pywintypes.OVERLAPPED()
		win32file.WriteFile(self.tunnel_w, packet, overlapped_write)
		return

	# on MacOS(X) utun, all packets needs to be prefixed with 4 specific bytes
	def packet_writer_mac(self, packet):
		packet = "\x00\x00\x00\x02"+packet
		os.write(self.tunnel_w, packet)

	# default packet writer for Linux
	def packet_writer_default(self, packet):
		os.write(self.tunnel_w, packet)

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
	def packet_reader_default(self, tunnel, first_read, serverorclient):
		packet = os.read(tunnel, 4096)
		return packet

	# TODO: placeholder function to transform packets back and forth.
	# encryption, encodings anything that should be done on the packet and 
	# should be easily variable based on the config
	def transform(self, packet, encrypt):

		return packet

	# PLACEHOLDER: prolog for the communication
	# What comes here: anything that should be set up before the actual
	# communication
	def communication_initialization(self):

		return

	# Main function of the thread. Communication setup and actual communication
	def run(self):
		self.communication_initialization()
		self.communication(False)

		return

	# PLACEHOLDER: check function
	# What comes here: generate challenge and send to the server
	def do_check(self):

		return

	# PLACEHOLDER: authentication to the server
	# What comes here: generate authentication message and send to the server
	def do_auth(self):

		return

	# PLACEHOLDER: logoff function
	# What comes here: send message to the server about leaving
	def do_logoff(self):

		return

	# stop thread and exit as soon as possible
	def stop(self):
		self._stop = True

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
	def communication_unix(self, is_check):

		return

	# for windows
	def communication_win(self, is_check):

		return


class Stateful_module(Generic_module):

	module_name = "Stateful module to inherit"
	module_configname = "NONE"
	module_description = """This is a skeleton module to inherit for all 
		Stateful modules for example: TCP, SOCKS etc. The common functions
		are coded in this, so most of the code duplication will be solved with
		this."""

	def __init__(self):
		super(Stateful_module, self).__init__()

		return

	# PLACEHOLDER: sanity check against the configuration
	# if some of the values in the config are missing or invalid
	# then it should return False
	def sanity_check(self):
		
		return True

	# PLACEHOLDER: server part of the module
	# What comes here: setup, bind, listen, accept, fork/thread, cleanup
	def serve(self):

		return

	# PLACEHOLDER: client part of the module
	# What comes here: setup, connect, cleanup
	def connect(self):

		return

	# PLACEHOLDER: check part of the module	
	# What comes here: setup, connect, check, cleanup
	def check(self):

		return

	# PLACEHOLDER: cleanup
	# What comes here: close() all sockets, do everything that should be done
	# to prepare for the exit process
	def cleanup(self):

		return
