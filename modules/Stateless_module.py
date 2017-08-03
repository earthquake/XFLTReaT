import sys

if "Stateless_module.py" in sys.argv[0]:
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

class Stateless_module(Generic_module):
	def __init__(self):
		super(Stateless_module, self).__init__()
		self.timeout = 3.0
		self.controlchannel = controlchannel.ControlChannel()

		# control message handlers
		self.cmh_struct  = {
			# num : [string to look for, function, server(1) or client(0), return on success, return on failure]
			# return value meanings: True  - module continues
			#						 False - module thread terminates
			# in case of Stateless modules, the whole module terminates if the return value is False
			0  : [common.CONTROL_CHECK, 		self.controlchannel.cmh_check_query, 1, True, True],
			1  : [common.CONTROL_CHECK_RESULT, 	self.controlchannel.cmh_check_check, 0, True, False],
			2  : [common.CONTROL_AUTH, 			self.controlchannel.cmh_auth, 1, True, True],
			3  : [common.CONTROL_AUTH_OK, 		self.controlchannel.cmh_auth_ok, 0, True, False],
			4  : [common.CONTROL_AUTH_NOTOK, 	self.controlchannel.cmh_auth_not_ok, 0, True, False],
			5  : [common.CONTROL_LOGOFF, 		self.controlchannel.cmh_logoff, 1, True, False],
			6  : [common.CONTROL_DUMMY_PACKET, 	self.controlchannel.cmh_dummy_packet, 1, True, True]
		}

		return

	def auth_ok_setup(self):

		return

	def setup_authenticated_client(self, control_message, additional_data):
		addr = additional_data # UDP specific
		client_local = client.Client()
		common.init_client_stateless(control_message, addr, client_local, self.packetselector, self.clients)
		self.clients.append(client_local)
		self.packetselector.add_client(client_local)
		if client_local.get_pipe_r() not in self.rlist:
			self.rlist.append(client_local.get_pipe_r())
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH_OK, additional_data)

		return

	def remove_authenticated_client(self, additional_data):
		addr = additional_data # UDP specific
		c = common.lookup_client_pub(self.clients, addr)
		if c:
			self.packetselector.delete_client(c)
			self.rlist.remove(c.get_pipe_r())
			common.delete_client_stateless(self.clients, c)

		return

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

	# PLACEHOLDER: implementation of wrapping and sending message
	# What comes here: marking message (control or data), transforming (see
	# transform()), prepending with length, sending on the appropriate channel

	def send(self, type, message, additional_data):

		return

	# PLACEHOLDER: implementation of recvieving and unpacking the message
	# What comes here: reading the first two bytes to determine length, reading
	# the full packet, transforming it to the original format (see transform())
	def recv(self):

		return

	# PLACEHOLDER: communication function
	# What comes here: this is the tricky part, where everything is handled 
	# that matters.
	def communication(self, is_check):

		return

	def sanity_check(self):
		
		return

	# PLACEHOLDER: server part of the module
	# What comes here: setup, bind, listen, accept, fork/thread, cleanup
	def serve(self):

		return

	# PLACEHOLDER: client part of the module
	# What comes here: setup, connect, cleanup
	def client(self):

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
