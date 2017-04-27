import sys

if "client.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)


import Queue

# python 2.7 hack to have inheritance, without the metaclass, the inhericance
# fails
__metaclass__ = type
class Client():
	def __init__(self):
		self.public_ip_addr = None
		self.public_src_port = None
		self.private_ip_addr = None
		self.moduleId = None
		self.socket = None
		self.pipe_r = None
		self.pipe_w = None
		self.pipe_r_fd = None
		self.pipe_w_fd = None
		#TODO
		self.authenticated = False
		self.encryption_key = None

	def set_public_ip_addr(self, public_ip_addr):
		self.public_ip_addr = public_ip_addr

		return

	def get_public_ip_addr(self):
		return self.public_ip_addr


	def set_public_src_port(self, public_src_port):
		self.public_src_port = public_src_port

		return

	def get_public_src_port(self):
		return self.public_src_port


	def set_private_ip_addr(self, private_ip_addr):
		self.private_ip_addr = private_ip_addr

		return

	def get_private_ip_addr(self):
		return self.private_ip_addr


	def set_socket(self, socket):
		self.socket = socket

		return

	def get_socket(self):
		return self.socket


	def set_moduleId(self, moduleId):
		self.moduleId = moduleId

		return

	def get_moduleId(self):
		return self.moduleId


	def set_pipes_fdnum(self, pipe_r, pipe_w):
		self.pipe_r = pipe_r
		self.pipe_w = pipe_w

		return

	def get_pipe_r(self):
		return self.pipe_r

	def get_pipe_w(self):
		return self.pipe_w

	def set_pipes_fd(self, pipe_r_fd, pipe_w_fd):
		self.pipe_r_fd = pipe_r_fd
		self.pipe_w_fd = pipe_w_fd

		return

	def get_pipe_r_fd(self):
		return self.pipe_r_fd

	def get_pipe_w_fd(self):
		return self.pipe_w_fd

	# TODO
	def set_authenticated(self, value):
		self.authenticated = value

	def get_authenticated(self):
		return self.authenticated