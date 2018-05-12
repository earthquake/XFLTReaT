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

if "auth_none.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import socket
import struct

import common
import Generic_authentication_module

class Authentication_module(Generic_authentication_module.Generic_authentication_module):
	def __init__(self):
		super(Authentication_module, self).__init__()

		self.cmh_struct_authentication  = {
			# num : [string to look for, function, server(1) or client(0), return on success, return on failure]
			# return value meanings: True  - module continues
			#						 False - module thread terminates
			# in case of Stateless modules, the whole module terminates if the return value is False
			0  : ["XFLT>AUTH!", 		self.authentication_step_1, 1, True, False],
			1  : ["XFLT>AUTH_OK", 		self.authentication_step_2_ok, 0, True, False],
			2  : ["XFLT>AUTH_NOTOK", 	self.authentication_step_2_not_ok, 0, True, False, False]
		}

		self.client_step_count = 1
		self.server_step_count = 1

		return

	def authentication_init_msg(self):
		return self.cmh_struct_authentication[0][0]

	# auth: authentication request received, authenticate client
	def authentication_step_1(self, module, message, additional_data, cm):
		module.post_authentication_server(message[len(self.cmh_struct_authentication[0][0]):], additional_data)
		common.internal_print("Client authenticated", 1)

		module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_authentication[1][0], additional_data)

		return module.cmh_struct[cm][3]

	# auth_ok: auth succeded on server, client authenticated
	def authentication_step_2_ok(self, module, message, additional_data, cm):
		module.post_authentication_client(message[len(self.cmh_struct_authentication[1][0]):], additional_data)
		common.internal_print("Authentication succeed for: {0}".format(module.module_name), 1)

		return module.cmh_struct[cm][3]

	# auth_notok: auth failed on server, client exits
	def authentication_step_2_not_ok(self, module, message, additional_data, cm):
		common.internal_print("Authentication failed for: {0}".format(module.module_name), -1)
		module.remove_initiated_client(message, additional_data)

		return module.cmh_struct[cm][4+module.is_caller_stateless()]