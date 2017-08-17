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

if "encoding.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import math
import base64

class id():
	def get_name(self):
		return "Plaintext"

	def encode(self, text):
		return text

	def decode(self, text):
		return text

	def get_maximum_length(self, cap):
		return cap

class Base64_DNS():
	def get_name(self):
		return "Base64 DNS"

	def encode(self, text):
		return base64.b64encode(text).replace("=","").replace("/", "-")

	def decode(self, text):
		if len(text) % 4:
			text += "="*(4-(len(text)%4))
		return base64.b64decode(text.replace("-", "/"))

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 4))*3
		remn = int(math.floor(((cap % 4)/4.0)*3))
		return full + remn

class Base64():
	def get_name(self):
		return "Base64"

	def encode(self, text):
		return base64.b64encode(text).replace("=","")

	def decode(self, text):
		if len(text) % 4:
			text += "="*(4-(len(text)%4))
		try:
			return base64.b64decode(text)
		except:
			return ""

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 4))*3
		remn = int(math.floor(((cap % 4)/4.0)*3))
		return full + remn

class Base32():
	def get_name(self):
		return "Base32"

	def encode(self, text):
		return base64.b32encode(text).replace("=","")

	def decode(self, text):
		if len(text) % 8:
			text += "="*(8-(len(text)%8))
		try:
			return base64.b32decode(text)
		except:
			return ""

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 8))*5
		remn = int(math.floor(((cap % 8)/8.0)*5))
		return full + remn

class Base16():
	def get_name(self):
		return "Base16"

	def encode(self, text):
		return base64.b16encode(text)

	def decode(self, text):
		try:
			return base64.b16decode(text)
		except:
			return ""

	def get_maximum_length(self, cap):
		return int(math.floor(cap/2))
