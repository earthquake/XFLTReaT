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

if "icmp_proto.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import struct
import math
import queue
# local modules
import client

class ICMP_Proto():

	ICMP_ECHO_REQUEST  = 8
	ICMP_ECHO_RESPONSE = 0

	def __init__(self):

		return

	def checksum(self, packet):
		chksum = 0
		odd = len(packet) % 2

		for i in range(0, len(packet)-odd, 2):
			chksum += struct.unpack("<H", packet[i:i+2])[0]

		if odd:
			chksum += struct.unpack("<B", packet[i+2:i+3])[0]

		chksum = ((chksum >> 16) & 0xffff) + (chksum & 0xffff)
		chksum += (chksum >> 16) & 0xffff

		return ~(chksum) & 0xffff

	def create_packet(self, type, identifier, sequence, data):
		#packet = struct.pack("<BBHHH", type, 0, 0, identifier, sequence) + data
		#packet = struct.pack("<BBHHH", type, 0, self.checksum(packet), identifier, sequence) + data

		packet = struct.pack("<BBHH", type, 0, 0, identifier) + struct.pack(">H", sequence) + data
		packet = struct.pack("<BBHH", type, 0, self.checksum(packet), identifier) + struct.pack(">H", sequence) + data

		return packet

class ICMP_Client(client.Client):
	def __init__(self):
		super(ICMP_Client, self).__init__()
		#ICMP
		self.ICMP_received_identifier = -1
		self.ICMP_sent_identifier = -1
		self.ICMP_received_sequence = -1
		self.ICMP_sent_sequence = -1
		#Queue
		self.q = queue.queue()


	#QUEUING
	def queue_put(self, value):
		self.q.put(value)

	def queue_get(self):
		return self.q.get()

	def queue_length(self):
		return self.q.qsize()

	#ICMP
	def set_ICMP_received_identifier(self, value):
		self.ICMP_received_identifier = value

		return

	def get_ICMP_received_identifier(self):
		return self.ICMP_received_identifier

	def set_ICMP_received_sequence(self, value):
		self.ICMP_received_sequence = value

		return

	def get_ICMP_received_sequence(self):
		return self.ICMP_received_sequence


	def set_ICMP_sent_identifier(self, value):
		self.ICMP_sent_identifier = value

		return

	def get_ICMP_sent_identifier(self):
		return self.ICMP_sent_identifier

	def set_ICMP_sent_sequence(self, value):
		self.ICMP_sent_sequence = value

		return

	def get_ICMP_sent_sequence(self):
		return self.ICMP_sent_sequence

	# function pointer to the module's stop()
	# placeholder, no need for this since this is a Stateless module
	def set_stopfp(self, stopfp):

		return

	# if stateless and stop() saved, call it
	# placeholder, no need for this since this is a Stateless module
	def call_stopfp(self):

		return