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

if "websocket_proto.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import struct
import base64
import os
import hashlib
import re

class WebSocket_Proto():
	def __init__(self):
		return

	def upgrade(self, url, hostname, port, version):
		upgrade_request  = "GET http://{0}:{1}/{2} HTTP/1.1\r\n".format(hostname, port, url)
		upgrade_request += "Host: {0}:{1}\r\n".format(hostname, port)
		upgrade_request += "Upgrade: websocket\r\n"
		upgrade_request += "Connection: Upgrade\r\n"
		upgrade_request += "Origin: {0}:{1}\r\n".format(hostname, port)
		upgrade_request += "Sec-WebSocket-Key: {0}\r\n".format(base64.b64encode(os.urandom(16)))
		upgrade_request += "Sec-WebSocket-Protocol: chat, superchat\r\n"
		upgrade_request += "Sec-WebSocket-Version: {0}\r\n\r\n".format(version)

		return upgrade_request

	def get_handshake_init(self, request):
		r = re.compile("Sec-WebSocket-Key: ([0-9a-zA-Z=/+]*)")
		res = r.search(request)
		if res:
			res = r.search(request).group(1)
		return res

	def calculate_handshake(self, handshake_init):
		magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		h = hashlib.sha1()
		h.update(handshake_init+magic_string)
		return base64.b64encode(h.digest())

	def switching_protocol(self, handshake):
		switching_reponse  = "HTTP/1.1 101 Switching Protocols\r\n"
		switching_reponse += "Upgrade: websocket\r\n"
		switching_reponse += "Connection: Upgrade\r\n"
		switching_reponse += "Sec-WebSocket-Accept: {0}\r\n\r\n".format(handshake)

		return switching_reponse
	'''
	Frame format:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
	'''
	def build_message(self, serverorclient, opcode, data):
		if serverorclient:
			header = struct.pack(">BBH", ((1<<7) | (opcode & 0xF)), 126, len(data))
		else:
			header = struct.pack(">BBHI", ((1<<7) | (opcode & 0xF)), 0x80 | 126, len(data), 0)

		return header+data

	def is_masked(self, header):
		if ord(header[1:2]) & 0x80:
			return True
		return False

	def get_length_type(self, header):
		if len(header) != 2:
			return -1

		length = struct.unpack(">BB", header)[1] & 0x7F
		if length < 126:
			return 0
		if length == 126:
			return 1
		if length == 127:
			return 2

		return -1

	def get_header_length(self, masked, length_type):
		mask = 0
		if masked:
			mask = 4 
		if length_type == 0:
			return 2 + mask
		if length_type == 1:
			return 4 + mask
		if length_type == 2:
			return 10 + mask

	def get_data_length(self, header, masked, length_type):
		mask = 0
		if masked:
			mask = 4
		header = header[0:len(header)-mask]
		if length_type == 0:
			length = struct.unpack(">BB", header)[1] & 0x7F
			if length > 125:
				return -1
			else:
				return length

		if length_type == 1:
			length = struct.unpack(">HH", header)[1]
			return length

		if length_type == 2:
			length_tmp = struct.unpack(">HII", header)
			return (length_tmp[1] << 32 | length_tmp[2])

		return -1

	def get_data(self, data, header_length, data_length):
		if len(data) != (header_length + data_length):
			return ""

		return data[header_length:header_length+data_length]
