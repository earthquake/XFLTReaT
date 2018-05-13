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

if "controlchannel.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)


import common

class ControlChannel():
	# control messages are handled here
	# check: solve the challenge and send back the result to the client
	# check_check: does the result match the expectation?
	# auth: authentication request received, authenticate client
	# auth_ok: auth succeded on server, client authenticated
	# auth_notok: auth failed on server, client exits
	# logoff: break the loop, cleanup will delete client, exiting thread
	# return values: True: keep the communication loop
	#				 False: break the loop and exit the thread

	# this function checks which control message should be called based on the
	# message. The control message handler table can be found in all modules
	# either in inherited (the parent has it) or hardcoded form.
	def handle_control_messages(self, module, message, additional_data):
		# go over the control message handlers
		for cm in range(len(module.cmh_struct)):
			# check whether it is a server or client handler
			if (message[0:len(module.cmh_struct[cm][0])] == module.cmh_struct[cm][0]) and (module.serverorclient == module.cmh_struct[cm][2]):
				return module.cmh_struct[cm][1](module, message, additional_data, cm)

		return True

	# check: solve the challenge and send back the result to the client
	def cmh_check_query(self, module, message, additional_data, cm):
		result = module.checks.check_default_calculate_challenge(message[len(common.CONTROL_CHECK):])
		common.internal_print("Module check requested for: {0}".format(module.module_name))
		module.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK_RESULT+result, additional_data)

		return module.cmh_struct[cm][4]

	# check_check: does the result match the expectation?
	def cmh_check_check(self, module, message, additional_data, cm):
		if message[len(common.CONTROL_CHECK_RESULT):] != module.check_result:
			common.internal_print("Module check failed for: {0}".format(module.module_name), -1)
		else:
			common.internal_print("Module check succeed for: {0}".format(module.module_name), 1)

		return module.cmh_struct[cm][4]

	def cmh_init(self, module, message, additional_data, cm):
		common.internal_print("Client initialization started: {0}".format(module.module_name))
		module.init_client(message[len(common.CONTROL_INIT):], additional_data)
		module.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_INIT_DONE, module.modify_additional_data(additional_data, 1))

		module.post_init_server(message, additional_data)

		return module.cmh_struct[cm][3]

	def cmh_init_done(self, module, message, additional_data, cm):
		module.post_init_client(message, additional_data)

		return module.cmh_struct[cm][3]

	# logoff: break the loop, cleanup will delete client, exiting thread
	def cmh_logoff(self, module, message, additional_data, cm):
		module.remove_initiated_client(message, additional_data)
		common.internal_print("Client logged off: {0}".format(module.module_name))

		return module.cmh_struct[cm][3]

	# dummy packet: send dummy packet to the server. For protocols that needs
	# to be queued. As many responses as many requests.
	def cmh_dummy_packet(self, module, message, additional_data, cm):
		common.internal_print("Dummy packet arrived as requested", 0, module.verbosity, common.DEBUG)

		return module.cmh_struct[cm][4]
