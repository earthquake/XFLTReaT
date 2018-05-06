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

if "Generic_encryption_module.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import os

import common

__metaclass__ = type
class Generic_encryption_module():
	def __init__(self):
		self.step_counter = 0
		self.cmh_struct_encryption  = {}

		return

	# add fingerprint to the known_hosts file
	def add_fingerprint(self, remoteserverip, pubkey_hash):
		f = open("misc/known_hosts", "a+")
		f.write(remoteserverip+";"+pubkey_hash+"\n")
		f.close()

		return True

	# check if the fingerprint is in the known_hosts file
	# return 2 - if error or not found
	#		 1 - if host found, but fingerprint does not match
	#		 0 - if host and fingerprint matches
	def check_fingerprint(self, remoteserverip, pubkey_hash):
		if not os.path.exists("misc/known_hosts"):
			return 2

		f = open("misc/known_hosts", "r")
		for line in f.readlines():
			line = line.replace("\r", "").replace("\n", "")
			if line == remoteserverip+";"+pubkey_hash:
				# found and trusted
				return 0
			if line.split(";")[0] == remoteserverip:
				# found but different
				return 1

		# not found
		return 2

	# return the control message handler structure
	def get_cmh_struct(self):
		return self.cmh_struct_encryption

	# guess what, this is the function that encrypts the data
	# should you need more variables, use the key as an array
	def encrypt(self, key, plaintext):
		return plaintext	

	# decryption function
	# should you need more variables, use the key as an array
	def decrypt(self, key, ciphertext):
		return ciphertext

	# return the number of steps
	def get_step_count(self):
		return len(self.cmh_struct_encryption)

	# return first message to start the process
	# client sends to server, server handles based on cmh struct
	def encryption_init_msg(self):
		return self.cmh_struct_encryption[0][0]

	# sanity check for the configuration
	def sanity_check(self, config):
		return True

	# initialization function - do not mix up with __init__()
	# this function is called from the xfltreat.py just after the sanity_check()
	def init(self, config, servermode):
		return True
