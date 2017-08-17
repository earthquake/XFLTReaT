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

if "socks_proto.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import struct
import math
import socket

import common

#TODO socks5 ipv6 and others

class SOCKS_proto():

	# SOCKS 4 constants
	SOCKS4_VERSION = 4
	SOCKS4_CD = 1
	SOCKS4_RESPONSES = []
	SOCKS4_RESPONSES_STR = []
	SOCKS4_RESPONSES.append("\x5a")
	SOCKS4_RESPONSES_STR.append("request granted")
	SOCKS4_RESPONSES.append("\x5b")
	SOCKS4_RESPONSES_STR.append("request rejected or failed")
	SOCKS4_RESPONSES.append("\x5c")
	SOCKS4_RESPONSES_STR.append("request failed because client is not running identd (or not reachable from the server")
	SOCKS4_RESPONSES.append("\x5d")
	SOCKS4_RESPONSES_STR.append("request failed because client's identd could not confirm the user ID string in the request")

	SOCKS4_OK = "\x00"

	# SOCKS 5 constants
	SOCKS5_VERSION = 5
	SOCKS5_CD = 1
	SOCKS5_AUTH_METHODS = []

	SOCKS5_REJECT_METHODS = "\xFF"
	SOCKS5_ADDR_TYPE = []
	SOCKS5_ADDR_TYPE.append(1) # ipv4
	SOCKS5_ADDR_TYPE.append(3) # domain
	SOCKS5_ADDR_TYPE.append(4) # ipv6

	SOCKS5_RESPONSES = []
	SOCKS5_RESPONSES_STR = []
	SOCKS5_RESPONSES.append("\x00") 
	SOCKS5_RESPONSES_STR.append("request granted")
	SOCKS5_RESPONSES.append("\x01")
	SOCKS5_RESPONSES_STR.append("general failure")
	SOCKS5_RESPONSES.append("\x02")
	SOCKS5_RESPONSES_STR.append("connection not allowed by ruleset")
	SOCKS5_RESPONSES.append("\x03")
	SOCKS5_RESPONSES_STR.append("network unreachable")
	SOCKS5_RESPONSES.append("\x04")
	SOCKS5_RESPONSES_STR.append("host unreachable")
	SOCKS5_RESPONSES.append("\x05")
	SOCKS5_RESPONSES_STR.append("connection refused by destination host")
	SOCKS5_RESPONSES.append("\x06")
	SOCKS5_RESPONSES_STR.append("TTL expired")
	SOCKS5_RESPONSES.append("\x07")
	SOCKS5_RESPONSES_STR.append("command not supported / protocol error")
	SOCKS5_RESPONSES.append("\x08")
	SOCKS5_RESPONSES_STR.append("address type not supported")


	SOCKS5_CD = 1

	def __init__(self):
		self.populate_auth_methods()

		return

	# in case you implement more auth methods, please add here
	def populate_auth_methods(self):
		self.SOCKS5_AUTH_METHODS = {
			0  : ["\x00", self.auth_noauth],
			1  : ["\x02", self.auth_userpass]
		}

		return

	# AUTH FUNCTIONS
	# return True  - if auth succeed
	# return False - if auth failed
	def auth_noauth(self, config, server_socket):

		return True

	def auth_userpass(self, config, server_socket):
		username = config.get("SOCKS", "usernamev5")
		password = config.get("SOCKS", "passwordv5")
		auth = "\x01" + chr(len(username)) + username + chr(len(password)) + password
		server_socket.send(auth)

		response = server_socket.recv(2)
		if (len(response) != 2) or (response[0:1] != "\x01"):
			common.internal_print("Connection failed through the proxy server: Username/Password auth failed", -1)
			return False

		if response[1:2] != "\x00":
			common.internal_print("Connection failed through the proxy server: Username/Password auth failed", -1)
			return False

		return True

