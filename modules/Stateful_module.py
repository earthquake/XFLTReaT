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

class Stateful_thread(threading.Thread):
	def __init__(self):
		super(Stateful_thread, self).__init__()
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
			5  : [common.CONTROL_LOGOFF, 		self.controlchannel.cmh_logoff, 1, True, False]
		}

		return

	def auth_ok_setup(self):
		self.tunnel_r = self.tunnel_w
		return


	def setup_authenticated_client(self, control_message, additional_data):
		common.init_client_stateful(control_message, self.client_addr, self.client, self.packetselector)
		self.client.set_socket(self.comms_socket)
		self.tunnel_r = self.client.get_pipe_r()
		self.packetselector.add_client(self.client)
		self.authenticated = self.client.get_authenticated()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH_OK, additional_data)

		return

	def remove_authenticated_client(self, additional_data):

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

	def send(self, type, message, additional_data):

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

	# PLACEHOLDER: handling control messages
	# What comes here: All control messages have to be handled here
	def handle_control_messages(self, message, serverorclient, additional_data):

		return

	# PLACEHOLDER: communication function
	# What comes here: this is the tricky part, where everything is handled 
	# that matters.
	def communication(self, is_check):

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
