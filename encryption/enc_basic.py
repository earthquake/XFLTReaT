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

if "enc_basic.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import os
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import UnsupportedAlgorithm

import common
import Generic_encryption_module

class Encryption_module(Generic_encryption_module.Generic_encryption_module):
	def __init__(self):
		super(Encryption_module, self).__init__()
		self.cmh_struct_encryption  = {
			# num : [string to look for, function, server(1) or client(0), return on success, return on failure]
			# return value meanings: True  - module continues
			#						 False - module thread terminates
			# in case of Stateless modules, the whole module terminates if the return value is False
			0  : ["XFLT>ECDHd1", 	self.encryption_step_1, 1, True, False, True],
			1  : ["XFLT>ECDHd2", 	self.encryption_step_2, 0, True, False, False],
			2  : ["XFLT>ECDHd3", 	self.encryption_step_3, 1, True, False, True],
			3  : ["XFLT>ECDHd4", 	self.encryption_step_4, 0, True, False, False],
			4  : ["XFLT>ECDHd5", 	self.encryption_step_5, 1, True, False, True],
		}

		self.client_step_count = 2
		self.server_step_count = 3

		self.server_public_key_file = "misc/public_key.pem"
		self.server_private_key_file = "misc/private_key.pem"
		self.curve = ec.SECP256K1()

		return

	def encrypt(self, shared_key, plaintext):
		# the nonce should be 16 bytes long random data, but because of the 
		# small message size, we just get 4bytes and use it 4 times (extend).
		# This is ugly, makes the encryption more vulnerable, but if you need
		# something strong, please use the enhanced encryption module.
		nonce = os.urandom(4)
		extended_nonce = nonce*4
		algorithm = algorithms.ChaCha20(shared_key, extended_nonce)
		cipher = Cipher(algorithm, mode=None, backend=default_backend())
		encryptor = cipher.encryptor()

		return nonce+encryptor.update(plaintext)

	def decrypt(self, shared_key, ciphertext):
		# the nonce should be 16 bytes long random data, but because of the 
		# small message size, we just get 4bytes and use it 4 times (extend).
		# This is ugly, makes the encryption more vulnerable, but if you need
		# something strong, please use the enhanced encryption module.
		nonce = ciphertext[0:4]
		extended_nonce = nonce*4
		algorithm = algorithms.ChaCha20(shared_key, extended_nonce)
		cipher = Cipher(algorithm, mode=None, backend=default_backend())
		decryptor = cipher.decryptor()

		return decryptor.update(ciphertext[4:])

	# server side.
	# Sending the pre-generated public key from the file to the client for 
	# verification purposes + key exchange
	def encryption_step_1(self, module, message, additional_data, cm):
		common.internal_print("Encryption initialization started: {0}".format(module.module_name))
		pbk = self.server_public_key.public_numbers().encode_point()[1:]
		module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_encryption[1][0]+pbk, module.modify_additional_data(additional_data, 1))

		return module.cmh_struct[cm][3]

	# client side.
	# Server public key received. Checking if it is known by the client.
	# Generating a public/private key pair and sending back the public key to
	# the client. Shared key derived from the public key and saved.
	# Encryption is on from this point, shared key is used.
	def encryption_step_2(self, module, message, additional_data, cm):
		server_public_key_stream = message[len(self.cmh_struct_encryption[1][0]):]

		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(server_public_key_stream)
		pubkey_hash = base64.b64encode(digest.finalize())

		ip = module.config.get("Global", "remoteserverip")
		fingerprint = self.check_fingerprint(ip, pubkey_hash)
		if fingerprint == 2:
			# text was shamelessly copied from OpenSSH
			common.internal_print("The authenticity of host '{0}' can't be established.".format(ip), 1)
			common.internal_print("Server's key fingerprint is SHA256: {0}".format(base64.b64encode(pubkey_hash)), 1)
			answer = ""
			while (answer != "yes") and (answer != "no"):
				answer = raw_input("Are you sure you want to continue connecting? (yes/no) ")
			if answer == "yes":
				if not self.add_fingerprint(ip, pubkey_hash):
					common.internal_print("Error opening known_hosts file.", -1)
					return module.cmh_struct[cm][4+module.is_caller_stateless()]
			else:
				common.internal_print("Exiting...", -1)
				return module.cmh_struct[cm][4+module.is_caller_stateless()]

		if fingerprint == 1:
			common.internal_print("The fingerprint has changed for the server. If you don't trust this network,\nthis can be a Man-in-The-Middle attack!", -1)
			common.internal_print("Exiting...", -1)
			return module.cmh_struct[cm][4+module.is_caller_stateless()]

		try:
			public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(self.curve, "\x04"+server_public_key_stream)
		except:
			common.internal_print("Erroneous key received from the server. Are you sure you are using the same settings on both sides?", -1)
			return module.cmh_struct[cm][4+module.is_caller_stateless()]

		server_public_key = public_numbers.public_key(default_backend())

		client_private_key = ec.generate_private_key(self.curve, default_backend())
		module.encryption.set_shared_key(client_private_key.exchange(ec.ECDH(), server_public_key))

		pbk = client_private_key.public_key().public_numbers().encode_point()[1:]
		module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_encryption[2][0]+pbk, module.modify_additional_data(additional_data, 0))

		module.encryption.set_encrypted(True)

		return module.cmh_struct[cm][3]

	# server side.
	# Client's public key received, key exchanged.
	# A new ephemeral key pair is generated, public key is sent to the client.
	# This is to use a new, disposable key for every session
	def encryption_step_3(self, module, message, additional_data, cm):
		client_public_key_stream = message[len(self.cmh_struct_encryption[2][0]):]
		try:
			public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(self.curve, "\x04"+client_public_key_stream)
		except:
			common.internal_print("Erroneous key received from the client. Are you sure you are using the same settings on both sides?", -1)
			return module.cmh_struct[cm][4+module.is_caller_stateless()]

		client_public_key = public_numbers.public_key(default_backend())


		# TODO: make a lookup client wrapper to hide differences
		c = module.lookup_client_pub(additional_data)
		c.get_encryption().set_shared_key(self.server_private_key.exchange(ec.ECDH(), client_public_key))

		server_ephemeral_private_key = ec.generate_private_key(self.curve, default_backend())
		server_ephemeral_public_key = server_ephemeral_private_key.public_key()

		# no need to save, but who knows?!
		c.get_encryption().set_private_key(server_ephemeral_private_key)
		c.get_encryption().set_public_key(server_ephemeral_public_key)

		c.get_encryption().set_encrypted(True)

		pbk = server_ephemeral_public_key.public_numbers().encode_point()[1:]
		module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_encryption[3][0]+pbk, module.modify_additional_data(additional_data, 1))

		return module.cmh_struct[cm][3]

	# client side.
	# Server's ephemeral receveid, client generates an ephemeral keypair as
	# well. Client sends its ephemeral's public key to the server.
	# Since this is the last client side function called, we invoke the 
	# next step that is most probably the authentication, defined in the 
	# post_encryption_client() function.
	def encryption_step_4(self, module, message, additional_data, cm):
		server_ephemeral_public_key_stream = message[len(self.cmh_struct_encryption[3][0]):]

		try:
			public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(self.curve, "\x04"+server_ephemeral_public_key_stream)
		except:
			common.internal_print("Erroneous key received from the server. Are you sure you are using the same settings on both sides?", -1)
			return module.cmh_struct[cm][4+module.is_caller_stateless()]

		server_ephemeral_public_key = public_numbers.public_key(default_backend())

		client_ephemeral_private_key = ec.generate_private_key(self.curve, default_backend())
		client_ephemeral_public_key = client_ephemeral_private_key.public_key()

		module.encryption.set_private_key(client_ephemeral_private_key)
		module.encryption.set_public_key(client_ephemeral_public_key)

		pbk = client_ephemeral_public_key.public_numbers().encode_point()[1:]
		module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_encryption[4][0]+pbk, module.modify_additional_data(additional_data, 0))

		module.encryption.set_shared_key(client_ephemeral_private_key.exchange(ec.ECDH(), server_ephemeral_public_key))
		module.post_encryption_client(message[len(self.cmh_struct_encryption[3][0]):], additional_data)

		common.internal_print("Encryption key agreed with the server.", 1)

		return module.cmh_struct[cm][3]

	# server side.
	# Client's ephemeral public key received. Key exchanged and saved.
	def encryption_step_5(self, module, message, additional_data, cm):
		client_ephemeral_public = message[len(self.cmh_struct_encryption[4][0]):]

		c = module.lookup_client_pub(additional_data)

		try:
			public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(self.curve, "\x04"+client_ephemeral_public)
		except:
			common.internal_print("Erroneous key received from the client. Are you sure you are using the same settings on both sides?", -1)
			return module.cmh_struct[cm][4+module.is_caller_stateless()]

		client_ephemeral_public_key = public_numbers.public_key(default_backend())

		server_ephemeral_private_key = c.get_encryption().get_private_key()
		c.get_encryption().set_shared_key(server_ephemeral_private_key.exchange(ec.ECDH(), client_ephemeral_public_key))

		module.post_encryption_server(message[len(self.cmh_struct_encryption[4][0]):], additional_data)

		common.internal_print("Encryption key agreed with the client.", 1)

		return module.cmh_struct[cm][3]

	# checking for the key file values in the config
	def sanity_check(self, config):
		if config.has_option("Encryption", "public_key"):
			self.public_key_file = config.get("Encryption", "public_key")

		if config.has_option("Encryption", "private_key"):
			self.private_key_file = config.get("Encryption", "private_key")

		return True

	# initializing the module.
	# client mode:
	#	- nothing to do
	# server mode:
	#	- checking if the public and private key exists (server mode)
	#	- reading the files into memory
	#	- parsing the keys
	def init(self, config, servermode):
		try:
			extended_nonce = os.urandom(4)*4
			algorithm = algorithms.ChaCha20("0"*32, extended_nonce)
			cipher = Cipher(algorithm, mode=None, backend=default_backend())
			decryptor = cipher.decryptor()
		except UnsupportedAlgorithm:
			common.internal_print("OpenSSL library is outdated. Please update.", -1)
			return False
		except:
			common.internal_print("Something went wrong with the cryptography engine. Most probably OpenSSL related.", -1)
			return False

		if servermode:
			if not (os.path.exists(self.server_public_key_file) or os.path.exists(self.server_private_key_file)):
				common.internal_print("Both public and private key is missing. This must be the first run. Generating keys...", 1)

				private_key = ec.generate_private_key(self.curve, default_backend())
				privkey_ser = private_key.private_bytes(serialization.Encoding.PEM,
				                                     serialization.PrivateFormat.TraditionalOpenSSL,
				                                     serialization.NoEncryption())
				pubkey_ser = private_key.public_key().public_bytes(serialization.Encoding.PEM,
				                                     serialization.PublicFormat.SubjectPublicKeyInfo)

				p = open(self.server_public_key_file, "w+")
				p.write(pubkey_ser)
				p.close()

				oldmask = os.umask(0366)
				p = open(self.server_private_key_file, "w+")
				p.write(privkey_ser)
				p.close()
				os.umask(oldmask)

			if not (os.path.exists(self.server_public_key_file) and os.path.exists(self.server_private_key_file)):
				common.internal_print("Private or public key does not exist. Please make sure you have both or delete the existing one.", -1)
				return False

			# load keys from files
			f = open(self.server_private_key_file, "r")
			serialized_private = f.read()
			f.close()

			f = open(self.server_public_key_file, "r")
			serialized_public = f.read()
			f.close()

			# load private and public keys from files
			try:
				self.server_public_key = serialization.load_pem_public_key(serialized_public, backend=default_backend())
			except:
				common.internal_print("Error parsing '{0}' as a public key.".format(self.server_public_key_file), -1)
				return False
			try:
				self.server_private_key = serialization.load_pem_private_key(serialized_private, password=None, backend=default_backend())
			except:
				common.internal_print("Error parsing '{0}' as a private key.".format(self.server_private_key_file), -1)
				return False

			return True
		else:
			return True

		return False