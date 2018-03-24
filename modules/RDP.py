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

if "RDP.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading


#local files
import TCP_generic
import client
import common

class RDP_thread(TCP_generic.TCP_generic_thread):
	def __init__(self, threadID, serverorclient, tunnel, packetselector, comms_socket, placeholder, auth_module, verbosity, config, module_name):
		super(RDP_thread, self).__init__(threadID, serverorclient, tunnel, packetselector, comms_socket, placeholder, auth_module, verbosity, config, module_name)
		threading.Thread.__init__(self)
		self._stop = False
		self.threadID = threadID
		self.tunnel_r = None
		self.tunnel_w = tunnel
		self.packetselector = packetselector
		self.comms_socket = comms_socket
		self.client_addr = placeholder
		self.auth_module = auth_module
		self.verbosity = verbosity
		self.serverorclient = serverorclient
		self.config = config
		self.module_name = module_name
		self.check_result = None
		self.timeout = 3.0
		self.partial_message = ""
		self.client = None
		self.authenticated = False

		global pywintypes, win32api, win32file, win32event, winerror
		import pywintypes
		import win32api
		import win32file
		import win32event
		import winerror

		return

	def communication_initialization(self):
		self.client = client.Client()
		self.client.set_socket(self.comms_socket)

		return

	# check request: generating a challenge and sending it to the server
	# in case the answer is that is expected, the targer is a valid server
	def do_check(self):
		message, self.check_result = self.checks.check_default_generate_challenge()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, None)

		return

	# basic authentication support. mostly placeholder for a proper 
	# authentication. Time has not come yet.
	def do_auth(self):
		message = self.auth_module.send_details(self.config.get("Global", "clientip"))
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH+message, None)

		return

	# Polite signal towards the server to tell that the client is leaving
	# Can be spoofed? if there is no encryption. Who cares?
	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, None)

		return

	def send(self, channel_type, message, additional_data):
		if channel_type == common.CONTROL_CHANNEL_BYTE:
			transformed_message = self.transform(common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(common.DATA_CHANNEL_BYTE+message, 1)

		common.internal_print("RDP sent: {0}".format(len(transformed_message)), 0, self.verbosity, common.DEBUG)


		overlapped_write = pywintypes.OVERLAPPED()
		try:
			win32file.WriteFile(self.comms_socket, struct.pack(">H", len(transformed_message))+transformed_message, overlapped_write)
		except Exception as e:
			raise


	def recv(self, read_message):
		messages = []
		message = self.partial_message + read_message

		if len(message) < 2:
			return messages

		while True:
			length = struct.unpack(">H", message[0:2])[0]+2
			if len(message) >= length:
				messages.append(self.transform(message[2:length], 0))
				common.internal_print("RDP read: {0}".format(len(messages[len(messages)-1])), 0, self.verbosity, common.DEBUG)
				self.partial_message = ""
				message = message[length:]
			else:
				self.partial_message = message
				break

			if len(message) < 2:
				self.partial_message = message
				break

		return messages

	def cleanup(self):
		try:
			common.internal_print("Shutting down module: RDP Dynamic Virtual Channel")
			common.internal_print("Please exit XFLTReaT...")
			win32api.CloseHandle(self.comms_socket)
		except Exception as e:
			pass

		if self.serverorclient:
			self.packetselector.delete_client(self.client)

	def communication_win(self, is_check):
		# event, overlapped struct for the pipe or tunnel
		hEvent_pipe = win32event.CreateEvent(None, 0, 0, None) # for reading from the pipe
		overlapped_pipe = pywintypes.OVERLAPPED()
		overlapped_pipe.hEvent = hEvent_pipe

		# event, overlapped struct for the pipe or tunnel
		hEvent_rdp = win32event.CreateEvent(None, 0, 0, None) # for reading from the pipe
		overlapped_rdp = pywintypes.OVERLAPPED()
		overlapped_rdp.hEvent = hEvent_rdp

		# buffer for the packets
		message_readfile_pipe = win32file.AllocateReadBuffer(4096)
		message_readfile_rdp = win32file.AllocateReadBuffer(4096)

		# showing if we already async reading or not
		read_pipe = True
		read_rdp = False
		first_run = True

		while not self._stop:
			try:
				if not self.tunnel_r:
					# user is not authenticated yet, so there is no pipe
					# only checking the socket for data
					hr, _ = win32file.ReadFile(self.comms_socket, message_readfile_rdp, overlapped_rdp)
					if (hr == winerror.ERROR_IO_PENDING):
						rc = win32event.WaitForSingleObject(hEvent_rdp, int(self.timeout*1000))
						read_rdp = True
					else:
						raise
						rc = 0
				else:
				# client mode so we have the socket and tunnel as well
				# or the client authenticated and the pipe was created
					if read_pipe or first_run:
						# no ReadFile was called before or finished, so we
						# are calling it again
						first_run = False
						hr, _ = win32file.ReadFile(self.tunnel_r, message_readfile_pipe, overlapped_pipe)

					if read_rdp:
						# no ReadFile was called before or finished, so we
						# are calling it again
						hr, _ = win32file.ReadFile(self.comms_socket, message_readfile_rdp, overlapped_rdp)

					if (hr == winerror.ERROR_IO_PENDING):
						# well, this was an async read, so we need to wait
						# until it happens
						rc = win32event.WaitForMultipleObjects([hEvent_rdp, hEvent_pipe], 0, int(self.timeout*1000))
						if rc == winerror.WAIT_TIMEOUT:
							# timed out, just rerun and wait
							continue
					else:
						if hr != 0:
							common.internal_print("RDP ReadFile failed: {0}".format(hr), -1)
							raise

				if rc < 0x80: # STATUS_ABANDONED_WAIT_0
					if rc == 0:
						read_rdp = True
						read_pipe = False
						# socket got signalled
						# skipping header (8):length of read
						messages = self.recv(message_readfile_rdp[8:overlapped_rdp.InternalHigh]) # SLOW?
						for message in messages:
							# looping through the messages from socket
							if len(message) == 0:
								# this could happen when the socket died or
								# partial message was read.
								continue

							if common.is_control_channel(message[0:1]):
								# parse control messages
								if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], None):
									continue
								else:
									# If the module is stopped right away, then
									# the channel will be closing down as well.
									# Because of the buffering the message will
									# not be sent. That is why we need to sleep
									time.sleep(0.5)
									self.stop()
									break

							if self.authenticated:
								try:
									# write packet to the tunnel
									self.packet_writer(message[len(common.CONTROL_CHANNEL_BYTE):])
								except OSError as e:
									print e # wut?
								except Exception as e:
									if e.args[0] == 995:
										common.internal_print("Interface disappered, exiting thread: {0}".format(e), -1)
										self.stop()
										continue
									print e
					if rc == 1:
						read_rdp = False
						read_pipe = True
						# pipe/tunnel got signalled
						if (overlapped_pipe.InternalHigh < 4) or (message_readfile_pipe[0:1] != "\x45"): #Only care about IPv4
							# too small which should not happen or not IPv4, so we just drop it.
							continue

						# reading out the packet from the buffer and discarding the rest
						readytogo = message_readfile_pipe[0:overlapped_pipe.InternalHigh]
						self.send(common.DATA_CHANNEL_BYTE, readytogo, None)

			except win32api.error as e:
				if e.args[0] == 233:
					# No process is on the other end of the pipe.
					self._stop = True
					common.internal_print("Client disconnected from the pipe.", -1)
					continue
				common.internal_print("RDP Exception: {0}".format(e), -1)

		self.cleanup()

		return True

class RDP(TCP_generic.TCP_generic):

	module_name = "RDP Dynamic Virtual Channel"
	module_configname = "RDP"
	module_description = """Using a dedicated Dynamic Virtual Channel in the 
		active RDP session to tunnel data over the RDP connection instead of 
		opening a new TCP/UDP/other channel that might be filtere by a firewall.
		"""
	module_os_support = common.OS_WINDOWS

	def __init__(self):
		super(RDP, self).__init__()
		self.server_socket = None

		return

	def OpenDynamicChannel(self, channelname, priority):
		# C+Python = OMG...
		global pywintypes
		import ctypes.wintypes
		import ctypes
		import pywintypes
		import win32api

		wts = ctypes.windll.LoadLibrary("Wtsapi32.dll")

		hWTSHandle = wts.WTSVirtualChannelOpenEx(0xFFFFFFFF, channelname, 0x00000001 | priority)
		if not hWTSHandle:
			common.internal_print("Opening channel failed: {0}".format(win32api.GetLastError()), -1)
			return None

		WTSVirtualFileHandle = 1
		vcFileHandlePtr = ctypes.pointer(ctypes.c_int())
		length = ctypes.c_ulong(0)

		if not wts.WTSVirtualChannelQuery(hWTSHandle, WTSVirtualFileHandle, ctypes.byref(vcFileHandlePtr), ctypes.byref(length)):
			wts.WTSVirtualChannelClose(hWTSHandle)
			common.internal_print("Channel query: {0}".format(win32api.GetLastError()), -1)
			return None

		common.internal_print("Connected to channel: {0}".format(channelname))

		return pywintypes.HANDLE(vcFileHandlePtr.contents.value)


	def stop(self):
		self._stop = True

		if self.threads:
			for t in self.threads:
				t.stop()

		return

	def sanity_check(self):
		if not self.config.has_option(self.get_module_configname(), "serverport"):
			common.internal_print("'serverport' option is missing from '{0}' section".format(self.get_module_configname()), -1)

			return False

		try:
			convert = int(self.config.get(self.get_module_configname(), "serverport"))
		except:
			common.internal_print("'serverport' is not an integer in '{0}' section".format(self.get_module_configname()), -1)
			return False

		if not self.config.has_option(self.get_module_configname(), "channelname"):
			common.internal_print("'channelname' option is missing from '{0}' section".format(self.get_module_configname()), -1)

			return False

		if not self.config.has_option(self.get_module_configname(), "priority"):
			common.internal_print("'priority' option is missing from '{0}' section".format(self.get_module_configname()), -1)

			return False

		priority = self.config.get(self.get_module_configname(), "priority")
		if priority not in ("real", "high", "medium", "low"):
			common.internal_print("'priority' in '{0}' section has to be set to one of the following options: real, high, medium, low".format(self.get_module_configname()), -1)

			return False			


		return True


	def serve(self):
		client_socket = server_socket = None
		self.threads = []
		threadsnum = 1

		common.internal_print("Starting module: {0} on channel {1}".format(self.get_module_name(), self.config.get(self.get_module_configname(), "channelname")))
		
		priority = 4
		prio = self.config.get(self.get_module_configname(), "serverport")
		if prio == "real":
			priority = 6
		if prio == "high":
			priority = 4
		if prio == "medium":
			priority = 2
		if prio == "low":
			priority = 0

		hDVC = self.OpenDynamicChannel(self.config.get(self.get_module_configname(), "channelname"), priority)
		if not hDVC:
			return

		threadsnum = threadsnum + 1
		thread = RDP_thread(threadsnum, 1, self.tunnel, self.packetselector, hDVC, ("0.0.0.0", 0), self.auth_module, self.verbosity, self.config, self.get_module_name())
		thread.start()
		self.threads.append(thread)

		return

	def connect(self):
		common.internal_print("This is a server mode only module.", -1)

		return

	def check(self):
		common.internal_print("This is a server mode only module.", -1)

		return


		