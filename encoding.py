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
	print("[-] Instead of poking around just try: python xfltreat.py --help")
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
		return base64.b85encode(text).replace(b"=",b"")

	def decode(self, text):
		if len(text) % 4:
			text += b"="*(4-(len(text)%4))
		return base64.b85decode(text)

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 4))*3
		remn = int(math.floor(((cap % 4)/4.0)*3))
		return full + remn

class Base64_DNS():
	def get_name(self):
		return "Base64 DNS"

	def encode(self, text):
		return base64.b64encode(text).replace(b"=",b"").replace(b"/", b"-").replace(b"+", b"_")

	def decode(self, text):
		if len(text) % 4:
			text += b"="*(4-(len(text)%4))
		return base64.b64decode(text.replace(b"-", b"/").replace(b"_", b"+"))

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 4))*3
		remn = int(math.floor(((cap % 4)/4.0)*3))
		return full + remn

class Base64():
	def get_name(self):
		return "Base64"

	def encode(self, text):
		return base64.b64encode(text).replace(b"=",b"")

	def decode(self, text):
		if len(text) % 4:
			text += b"="*(4-(len(text)%4))
		try:
			return base64.b64decode(text)
		except:
			return b""

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 4))*3
		remn = int(math.floor(((cap % 4)/4.0)*3))
		return full + remn

class Base32():
	def get_name(self):
		return "Base32"

	def encode(self, text):
		return base64.b32encode(text).replace(b"=",b"").lower()

	def decode(self, text):
		if len(text) % 8:
			text += b"="*(8-(len(text)%8))
		try:
			return base64.b32decode(text.upper())
		except:
			return b""

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
			return b""

	def get_maximum_length(self, cap):
		return int(math.floor(cap/2))

class ASCII85():
	def get_name(self):
		return "ASCII 85"

	def encode(self, text):
		encoded_text = b""
		if len(text) % 4:
			text += b"\x00"*(4-(len(text)%4))
		for i in range(0, len(text)/4):
			c = struct.unpack(">I", text[i*4:(i+1)*4])[0]
			N0 = (c/52200625) % 85 + 33
			N1 = (c/614125) % 85 + 33
			N2 = (c/7225) % 85 + 33
			N3 = (c/85) % 85 + 33
			N4 = c % 85 + 33

			encoded_text += chr(N0)+chr(N1)+chr(N2)+chr(N3)+chr(N4)

		return encoded_text.replace(b".",b"{")

	def decode(self, text):
		if len(text) % 5:
			return None

		decoded_text = b""
		text = text.replace(b"{",b".")
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
		self.base91_alphabet = [b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M',
			b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z',
			b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm',
			b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
			b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'!', b'#', b'$',
			b'%', b'&', b'(', b')', b'*', b'+', b',', b'\'', b'/', b':', b';', b'<', b'=',
			b'>', b'?', b'@', b'[', b']', b'^', b'_', b'`', b'{', b'|', b'}', b'~', b'"']

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
			strbytes = bytes([strletter])
			if not strbytes in self.decode_table:
				continue
			c = self.decode_table[strbytes]
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
		out = b""
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
		self.base128_alphabet = b""
		self.base128_alphabet += b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		self.base128_alphabet += b"\xbc\xbd\xbe\xbf"
		self.base128_alphabet += b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
		self.base128_alphabet += b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
		self.base128_alphabet += b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
		self.base128_alphabet += b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd"
		self.base128_alphabet = bytearray(list(self.base128_alphabet))

		self.base128_revalphabet = [0] * 256
		for i in range(0, 128):
			#c = ord(self.base128_alphabet[i])
			self.base128_revalphabet[self.base128_alphabet[i]] = i

	def get_name(self):
		return "Base128"

	def encodeblock(self, block):
		blen = len(block)
		out = b""

		out += bytes([self.base128_alphabet[block[0] >> 1]])
		if blen > 1:
			out += bytes([self.base128_alphabet[(((block[0] & 0x01) << 6) & 0xFF) | ((block[1] >> 2) & 0xFF)]])
		else:
			out += bytes([self.base128_alphabet[(((block[0] & 0x01) << 6) & 0xFF)]])
			return out

		if blen > 2:
			out += bytes([self.base128_alphabet[(((block[1] & 0x03) << 5) & 0xFF) | ((block[2] >> 3) & 0xFF)]])
		else:
			out += bytes([self.base128_alphabet[(((block[1] & 0x03) << 5) & 0xFF)]])
			return out

		if blen > 3:
			out += bytes([self.base128_alphabet[(((block[2] & 0x07) << 4) & 0xFF) | ((block[3] >> 4) & 0xFF)]])
		else:
			out += bytes([self.base128_alphabet[(((block[2] & 0x07) << 4) & 0xFF)]])
			return out

		if blen > 4:
			out += bytes([self.base128_alphabet[(((block[3] & 0x0F) << 3) & 0xFF) | ((block[4] >> 5) & 0xFF)]])
		else:
			out += bytes([self.base128_alphabet[(((block[3] & 0x0F) << 3) & 0xFF)]])
			return out

		if blen > 5:
			out += bytes([self.base128_alphabet[(((block[4] & 0x1F) << 2) & 0xFF) | ((block[5] >> 6) & 0xFF)]])
		else:
			out += bytes([self.base128_alphabet[(((block[4] & 0x1F) << 2) & 0xFF)]])
			return out

		if blen > 6:
			out += bytes([self.base128_alphabet[(((block[5] & 0x3F) << 1) & 0xFF) | ((block[6] >> 7) & 0xFF)]])
			out += bytes([self.base128_alphabet[block[6] & 0x7F]])
		else:
			out += bytes([self.base128_alphabet[(((block[5] & 0x3F) << 1) & 0xFF)]])
			return out

		return out

	def decodeblock(self, block):
		blen = len(block)
		out = b""

		if blen < 8:
			block += b"a"

		out += bytes([((self.base128_revalphabet[block[0]] << 1) & 0xFF) | ((self.base128_revalphabet[block[1]] >> 6) & 0xFF)])
		if blen > 2:
			out += bytes([((self.base128_revalphabet[block[1]] << 2) & 0xFF) | ((self.base128_revalphabet[block[2]] >> 5) & 0xFF)])
		if blen > 3:
			out += bytes([((self.base128_revalphabet[block[2]] << 3) & 0xFF) | ((self.base128_revalphabet[block[3]] >> 4) & 0xFF)])
		if blen > 4:
			out += bytes([((self.base128_revalphabet[block[3]] << 4) & 0xFF) | ((self.base128_revalphabet[block[4]] >> 3) & 0xFF)])
		if blen > 5:
			out += bytes([((self.base128_revalphabet[block[4]] << 5) & 0xFF) | ((self.base128_revalphabet[block[5]] >> 2) & 0xFF)])
		if blen > 6:
			out += bytes([((self.base128_revalphabet[block[5]] << 6) & 0xFF) | ((self.base128_revalphabet[block[6]] >> 1) & 0xFF)])
		if blen > 7:
			out += bytes([((self.base128_revalphabet[block[6]] << 7) & 0xFF) | (self.base128_revalphabet[block[7]] & 0xFF)])

		return out

	def encode(self, text):
		result = b""
		for i in range(0,int(math.ceil(float(len(text)) / 7.0))):
			result += self.encodeblock(text[i*7:(i+1)*7])

		return result

	def decode(self, text):
		result = b""
		for i in range(0,int(math.ceil(float(len(text)) / 8.0))):
			result += self.decodeblock(text[i*8:(i+1)*8])
		return result

	def get_maximum_length(self, cap):
		full = int(math.floor(cap / 8))*7
		remn = int(math.floor(((cap % 8)/8.0)*7))
		return full + remn