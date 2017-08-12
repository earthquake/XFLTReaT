import sys

if "encoding.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import math
import base64

class Base64():
	def encode(self, text):
		return base64.b64encode(text).replace("=","")

	def decode(self, text):
		if len(text) % 4:
			text += "="*(4-(len(text)%4))
		return base64.b64decode(text)

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 4))*3
		remn = int(math.floor(((cap % 4)/4.0)*3))
		return full + remn

class Base32():
	def encode(self, text):
		return base64.b32encode(text).replace("=","")

	def decode(self, text):
		if len(text) % 8:
			text += "="*(8-(len(text)%8))
		return base64.b32decode(text)

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 8))*5
		remn = int(math.floor(((cap % 8)/8.0)*5))
		return full + remn

class Base16():
	def encode(self, text):
		return base64.b16encode(text)

	def decode(self, text):
		return base64.b16decode(text)

	def get_maximum_length(self, cap):
		return int(math.floor(cap/2))
