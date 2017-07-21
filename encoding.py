import base64

class Encodings():
	def base64(self, text, encode = True):
		if encode:
			return base64.b64encode(text)
		else:
			return base64.b64decode(text)

	def base32(self, text, encode = True):
		if encode:
			return base64.b32encode(text)
		else:
			return base64.b32decode(text)

	def base16(self, text, encode = True):	
		if encode:
			return base64.b16encode(text)
		else:
			return base64.b16decode(text)