# MIT License

# Copyright (c) 2018 Balazs Bucsay

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

if "Generic_authentication_module.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import os

__metaclass__ = type
class Generic_authentication_module():
	def __init__(self):
		self.step_counter = 0
		self.cmh_struct_authentication  = {}

		return

	# return the control message handler structure
	def get_cmh_struct(self):
		return self.cmh_struct_authentication

	# return the number of steps
	def get_step_count(self):
		return len(self.cmh_struct_authentication)

	# return first message to start the process
	# client sends to server, server handles based on cmh struct
	def authentication_init_msg(self):
		return self.cmh_struct_authentication[0][0]

	# sanity check for the configuration
	def sanity_check(self, config):
		return True

	# initialization function - do not mix up with __init__()
	# this function is called from the xfltreat.py just after the sanity_check()
	def init(self, config, servermode):
		return True
