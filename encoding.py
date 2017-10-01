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
import struct
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

class Base85_DNS():
	def get_name(self):
		return "Base85 DNS"

	def encode(self, text):
		return base64.b85encode(text).replace("=","")

	def decode(self, text):
		if len(text) % 4:
			text += "="*(4-(len(text)%4))
		return base64.b85decode(text)

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 4))*3
		remn = int(math.floor(((cap % 4)/4.0)*3))
		return full + remn

class Base64_DNS():
	def get_name(self):
		return "Base64 DNS"

	def encode(self, text):
		return base64.b64encode(text).replace("=","").replace("/", "-").replace("+", "_")

	def decode(self, text):
		if len(text) % 4:
			text += "="*(4-(len(text)%4))
		return base64.b64decode(text.replace("-", "/").replace("_", "+"))

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
		return base64.b32encode(text).replace("=","").lower()

	def decode(self, text):
		if len(text) % 8:
			text += "="*(8-(len(text)%8))
		try:
			return base64.b32decode(text.upper())
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
		return base64.b16encode(text).lower()

	def decode(self, text):
		try:
			return base64.b16decode(text.upper())
		except:
			return ""

	def get_maximum_length(self, cap):
		return int(math.floor(cap/2))

class ASCII85():
	def get_name(self):
		return "ASCII 85"

	def encode(self, text):
		encoded_text = ""
		if len(text) % 4:
			text += "\x00"*(4-(len(text)%4))
		for i in range(0, len(text)/4):
			c = struct.unpack(">I", text[i*4:(i+1)*4])[0]
			N0 = (c/52200625) % 85 + 33
			N1 = (c/614125) % 85 + 33
			N2 = (c/7225) % 85 + 33
			N3 = (c/85) % 85 + 33
			N4 = c % 85 + 33

			encoded_text += chr(N0)+chr(N1)+chr(N2)+chr(N3)+chr(N4)

		return encoded_text.replace(".","{")

	def decode(self, text):
		if len(text) % 5:
			return None

		decoded_text = ""
		text = text.replace("{",".")
		for i in range(0, len(text)/5):
			encoded_text = text[i*5:(i+1)*5]

			N0 = ord(encoded_text[0]) - 33
			N1 = ord(encoded_text[1]) - 33
			N2 = ord(encoded_text[2]) - 33
			N3 = ord(encoded_text[3]) - 33
			N4 = ord(encoded_text[4]) - 33
			c = N0*52200625 + N1*614125 + N2*7225 + N3*85 + N4

			decoded_text += struct.pack(">I", c)
		return decoded_text

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 5))*4
		return full

# taken from: https://github.com/aberaud/base91-python
# Base91 encode/decode for Python 2 and Python 3
#
# Copyright (c) 2012 Adrien Beraud
# Copyright (c) 2015 Guillaume Jacquenot
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of Adrien Beraud, Wisdom Vibes Pte. Ltd., nor the names
#     of its contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
class Base91():
	def __init__(self):
		# modified table . -> ''
		self.base91_alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '#', '$',
			'%', '&', '(', ')', '*', '+', ',', '\'', '/', ':', ';', '<', '=',
			'>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"']

		self.decode_table = dict((v,k) for k,v in enumerate(self.base91_alphabet))

	def get_name(self):
		return "Base91"

	def decode(self, encoded_str):
	    ''' Decode Base91 string to a bytearray '''
	    v = -1
	    b = 0
	    n = 0
	    out = bytearray()
	    for strletter in encoded_str:
	        if not strletter in self.decode_table:
	            continue
	        c = self.decode_table[strletter]
	        if(v < 0):
	            v = c
	        else:
	            v += c*91
	            b |= v << n
	            n += 13 if (v & 8191)>88 else 14
	            while True:
	                out += struct.pack('B', b&255)
	                b >>= 8
	                n -= 8
	                if not n>7:
	                    break
	            v = -1
	    if v+1:
	        out += struct.pack('B', (b | v << n) & 255 )
	    return out

	def encode(self, bindata):
	    ''' Encode a bytearray to a Base91 string '''
	    b = 0
	    n = 0
	    out = ''
	    for count in range(len(bindata)):
	        byte = bindata[count:count+1]
	        b |= struct.unpack('B', byte)[0] << n
	        n += 8
	        if n>13:
	            v = b & 8191
	            if v > 88:
	                b >>= 13
	                n -= 13
	            else:
	                v = b & 16383
	                b >>= 14
	                n -= 14
	            out += self.base91_alphabet[v % 91] + self.base91_alphabet[v // 91]
	    if n:
	        out += self.base91_alphabet[b % 91]
	        if n>7 or b>90:
	            out += self.base91_alphabet[b // 91]
	    return out

	def get_maximum_length(self, cap):
		return int(float(cap)*(1/1.2306))


class Base128():
	def __init__(self):
		# iodined tested values
		self.base128_alphabet = ""
		self.base128_alphabet  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		self.base128_alphabet += "\xbc\xbd\xbe\xbf"
		self.base128_alphabet += "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
		self.base128_alphabet += "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
		self.base128_alphabet += "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
		self.base128_alphabet += "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd"
		self.base128_alphabet = list(self.base128_alphabet)

		self.base128_revalphabet = [0] * 256
		for i in range(0, 128):
			c = ord(self.base128_alphabet[i])
			self.base128_revalphabet[c] = i

	def get_name(self):
		return "Base128"

	def encodeblock(self, block):
		blen = len(block)
		out = ""
		if blen < 7:
			block += "\x00"
			blen += 1

		out += self.base128_alphabet[ord(block[0:1]) >> 1]
		out += self.base128_alphabet[(((ord(block[0:1]) & 0x01) << 6) & 0xFF) | ((ord(block[1:2]) >> 2) & 0xFF)]
		if blen > 2:
			out += self.base128_alphabet[(((ord(block[1:2]) & 0x03) << 5) & 0xFF) | ((ord(block[2:3]) >> 3) & 0xFF)]
		if blen > 3:
			out += self.base128_alphabet[(((ord(block[2:3]) & 0x07) << 4) & 0xFF) | ((ord(block[3:4]) >> 4) & 0xFF)]
		if blen > 4:
			out += self.base128_alphabet[(((ord(block[3:4]) & 0x0F) << 3) & 0xFF) | ((ord(block[4:5]) >> 5) & 0xFF)]
		if blen > 5:
			out += self.base128_alphabet[(((ord(block[4:5]) & 0x1F) << 2) & 0xFF) | ((ord(block[5:6]) >> 6) & 0xFF)]
		if blen > 6:
			out += self.base128_alphabet[(((ord(block[5:6]) & 0x3F) << 1) & 0xFF) | ((ord(block[6:7]) >> 7) & 0xFF)]
			out += self.base128_alphabet[ord(block[6:7]) & 0x7F]

		return out

	def decodeblock(self, block):
		blen = len(block)
		out = ""

		if blen < 8:
			block += "a"
			blen += 1

		out += chr(((self.base128_revalphabet[ord(block[0:1])] << 1) & 0xFF) | ((self.base128_revalphabet[ord(block[1:2])] >> 6) & 0xFF))
		if blen > 2:
			out += chr(((self.base128_revalphabet[ord(block[1:2])] << 2) & 0xFF) | ((self.base128_revalphabet[ord(block[2:3])] >> 5) & 0xFF))
		if blen > 3:
			out += chr(((self.base128_revalphabet[ord(block[2:3])] << 3) & 0xFF) | ((self.base128_revalphabet[ord(block[3:4])] >> 4) & 0xFF))
		if blen > 4:
			out += chr(((self.base128_revalphabet[ord(block[3:4])] << 4) & 0xFF) | ((self.base128_revalphabet[ord(block[4:5])] >> 3) & 0xFF))
		if blen > 5:
			out += chr(((self.base128_revalphabet[ord(block[4:5])] << 5) & 0xFF) | ((self.base128_revalphabet[ord(block[5:6])] >> 2) & 0xFF))
		if blen > 6:
			out += chr(((self.base128_revalphabet[ord(block[5:6])] << 6) & 0xFF) | ((self.base128_revalphabet[ord(block[6:7])] >> 1) & 0xFF))
		if blen > 7:
			out += chr(((self.base128_revalphabet[ord(block[6:7])] << 7) & 0xFF) | (self.base128_revalphabet[ord(block[7:8])] & 0xFF))

		return out


	def encode(self, text):
		result = ""
		for i in range(0,int(math.ceil(float(len(text)) / 7.0))):
			result += self.encodeblock(text[i*7:(i+1)*7])

		if result[-1:] == "a":
			result = result[:-1]
		return result

	def decode(self, text):
		result = ""
		for i in range(0,int(math.ceil(float(len(text)) / 8.0))):
			result += self.decodeblock(text[i*8:(i+1)*8])
		return result

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 8))*7
		remn = int(math.floor(((cap % 8)/8.0)*7))
		return full + remn
