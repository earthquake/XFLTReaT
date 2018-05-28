#!/usr/bin/env python
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

import time
import socket
import sys
import getopt
import os
import inspect
import threading
import errno
import ConfigParser


#local files
import common
# check if the OS is supported
if not common.os_support():
	sys.exit(-1)
# check requirements (python modules) whether or not installed
if not common.check_modules_installed():
	if (not "--ignore-dependencies" in sys.argv) and(not "--help" in sys.argv) and (not "-h" in sys.argv):
		sys.exit(-1)

from modules.Generic_module import Generic_module
from modules.Stateful_module import Stateful_module
from modules.Stateless_module import Stateless_module
from interface import Interface
from packetselector import PacketSelector
import encryption
import authentication

class XFLTReaT:

	# print usage when needed
	def usage(self):
		print("[*] Usage: python xfltreat [options]:\n"\
			"Options:\n"\
			"  -h\t--help\t\t\tusage of the tool (this help)\n"\
			"  -s\t--server\t\tturn on server mode (default)\n"\
			"  -c\t--client\t\tturn on client mode\n"\
			"  \t--check\t\t\tcheck modules on server side\n"\
			"  \t--config\t\tspecify config file (default: xfltreat.conf)\n"\
			"  \t--split\t\t\tsplit tunnel mode (specify scope in config)\n"\
			"  \t--ignore-dependencies\tignoring missing dependencies\n"\
			"  \t--verbose\t\t1 = verbose mode\n"\
			"  \t\t\t\t2 = debug mode")

		return

	# nicest banner ever.
	def banner(self):
		print(""\
			",--.   ,--.,------.,--.,--------.,------.                ,--------. \n"\
			" \  `.'  / |  .---'|  |'--.  .--'|  .--. ' ,---.  ,--,--.'--.  .--' \n"\
			"  .'    \  |  `--, |  |   |  |   |  '--'.'| .-. :' ,-.  |   |  |    \n"\
			" /  .'.  \ |  |`   |  '--.|  |   |  |\  \ \   --.\ '-'  |   |  |    \n"\
			"'--'   '--'`--'    `-----'`--'   `--' '--' `----' `--`--'   `--'    \n"\
			"Balazs Bucsay [[@xoreipeip]]\n")
		return

	def __init__(self):
		self.verbosity = 0
		self.configfile = "xfltreat.conf"
		self.servermode = 0
		self.clientmode = 0
		self.checkmode = 0
		self.splitmode = 0 # split tunnelling
		self.ignoredependencies = 0 # ignoring missing dependencies

		self.short = "hsc"
		self.long = ["help", "server", "client", "check", "split", "config=", "verbose=", "ignore-dependencies"]

		# modules that should not be loaded
		self.forbidden_modules = ["Generic_module", "Stateful_module", "Stateless_module"]
		self.forbidden_modules_instance = [Generic_module, Stateful_module, Stateless_module]

		self.authentication = authentication.Authentication()
		self.encryption = encryption.Encryption()

	def run(self, argv):
		self.banner()
		try:
			opts, args = getopt.getopt(argv, self.short, self.long)
		except getopt.GetoptError:
			self.usage()
			sys.exit(-1)

		for opt, arg in opts:
			if opt in ("-h", "--help"):
				self.usage()
				sys.exit(0)
			elif opt in ("-s", "--server"):
				self.servermode = 1
			elif opt in ("-c", "--client"):
				self.clientmode = 1
			elif opt in ("--check"):
				self.checkmode = 1
			elif opt in ("--config"):
				self.configfile = arg
			elif opt in ("--split"):
				self.splitmode = 1
			elif opt in ("--ignore-dependencies"):
				common.internal_print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", -1)
				common.internal_print("!IGNORING MISSING DEPENDENCIES, THIS COULD RESULT IN UNHANDLED EXCEPTIONS!", -1)
				common.internal_print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", -1)
				self.ignoredependencies = 1
			elif opt in ("--verbose"):
				try:
					self.verbosity = int(arg)
				except:
					common.internal_print("Invalid verbose value: {0}".format(arg), -1)
					sys.exit(-1)

		if not common.get_privilege_level():
			common.internal_print("The tool needs superuser or admin privileges. Run as root or Administrator.", -1)
			sys.exit(-1)

		# set the servermode when it was not specified expicitly
		if (not self.clientmode and not self.checkmode):
			self.servermode = 1

		# checking for the config file
		if not os.path.isfile(self.configfile):
			common.internal_print("config file missing!", -1)
			sys.exit(-1)
		
		# Looking for and parsing config file.
		common.internal_print("Parsing config file")
		config = ConfigParser.ConfigParser()
		try:
			config.read(self.configfile)
		except:
			common.internal_print("Invalid or malformed configuration file specified", -1)
			sys.exit(-1)

		# sanity check on configuration, exit on error
		if not common.config_sanity_check(config, (self.servermode)):
			sys.exit(-1)

		# load authentication module
		auth_module = self.authentication.load_auth_module(config)

		# sanity check for the auth module
		if not auth_module.sanity_check(config):
			sys.exit(-1)

		# initialize authentication
		if not auth_module.init(config, self.servermode):
			sys.exit(-1)

		# load encryption module
		encryption_module = self.encryption.load_encryption_module(config)

		# sanity check for the encryption module
		if not encryption_module.sanity_check(config):
			sys.exit(-1)

		# initialize encryption
		if not encryption_module.init(config, self.servermode):
			sys.exit(-1)

		if self.splitmode:
			self.scope = common.parse_scope_file(config.get("Global", "scope"))
			if self.scope == []:
				common.internal_print("Split tunnelling mode enabled, but no scope was defined or entries were invalid", -1)
				sys.exit(-1)

		# Check system config for routing. If the OS was not set up for IP 
		# forwarding then we need to exit.
		if self.servermode:
			if not common.check_router_settings(config):
				sys.exit(-1)

		# Loading modules from modules/ directory
		# 1. listing and loading all modules except forbidden ones
		common.internal_print("Loading all modules from 'modules' directory")
		for module in os.listdir("./modules/"):
			if module == '__init__.py' or module[-3:] != '.py' or (module[:-3] in self.forbidden_modules):
				continue
			module_list = __import__("modules."+module[:-3], locals(), globals())

		modules = []
		for m in dir(module_list):
			# 2. going thru all the modules
			if m != 'Generic_module' and m[:2] != "__":
				module_attributes = getattr(module_list, m)
				# 3. get the classes from the modules
				module_classes = [c for c in module_attributes.__dict__.values() if inspect.isclass(c)]
				# 4. select classes that are XFLTReaT modules
				real_modules = [c for c in module_classes if (issubclass(c, Generic_module) and (c not in self.forbidden_modules_instance))]
				for r in real_modules:
					# 5. actual instantiation of a module
					try:
						modules.append(r())
					except Exception as e:
						if self.ignoredependencies:
							common.internal_print("This module cannot be used without the dependencies installed: {0}".format(m), -1)
							pass
						else:
							raise

		# if the module is enabled from config, we store it in modules_enabled[]
		modules_enabled = []
		for m in modules:
			enabled = "no"
			# is there any section in the config for the module?
			if not config.has_section(m.get_module_configname()):
				common.internal_print("No section in config for module: {0}".format(m.get_module_configname()), -1)
				continue
			
			# is the 'enabled' option there for the module?
			if not config.has_option(m.get_module_configname(), "enabled"):
				common.internal_print("No option 'enabled' in config for module: {0}".format(m.get_module_configname()), -1)
				sys.exit(-1)

			enabled = config.get(m.get_module_configname(), "enabled")
			
			if enabled == "yes":
				# looks like the module is enabled, adding to modules_enabled[]
				modules_enabled.append(m)

		# check if more than one module is enabled for client mode
		if self.clientmode and (len(modules_enabled)>1):
			common.internal_print("In client mode only one module can be used.", -1)
			sys.exit(-1)

		if not len(modules_enabled):
			common.internal_print("No modules were enabled in configuration", -1)
			sys.exit(-1)

		# One Interface to rule them all, One Interface to find them,
		# One Interface to bring them all and in the darkness bind them
		common.internal_print("Setting up interface")
		interface = Interface()

		# Setting up interface related things for server mode
		if self.servermode:
			server_tunnel = interface.tun_alloc(config.get("Global", "serverif"), interface.IFF_TUN|interface.IFF_NO_PI)
			interface.set_ip_address(config.get("Global", "serverif"), 
				config.get("Global", "serverip"), config.get("Global", "serverip"), config.get("Global", "servernetmask"))
			interface.set_mtu(config.get("Global", "serverif"), int(config.get("Global", "mtu")))

			# start thread with socket-interface related pipes
			ps = PacketSelector(server_tunnel)
			ps.start()

		# Setting up interface related things for client mode
		if self.clientmode:
			client_tunnel = interface.tun_alloc(config.get("Global", "clientif"), interface.IFF_TUN|interface.IFF_NO_PI)
			interface.set_ip_address(config.get("Global", "clientif"), 
				config.get("Global", "clientip"), config.get("Global", "serverip"), config.get("Global", "clientnetmask"))
			if not self.splitmode:
				interface.set_default_route(config.get("Global", "remoteserverip"), config.get("Global", "clientip"), config.get("Global", "serverip"))
			else:
				interface.set_split_route(self.scope, config.get("Global", "serverip"))
			interface.set_mtu(config.get("Global", "clientif"), int(config.get("Global", "mtu")))
			common.internal_print("Please use CTRL+C to exit...")

		module_threads = []
		module_thread_num = 0

		for m in modules_enabled:
			# Executing module in server mode
			if self.servermode:
				module_thread_num = module_thread_num + 1
				if m.__init_thread__(module_thread_num, config, server_tunnel, ps, auth_module, encryption_module, self.verbosity):
					m.start()
					module_threads.append(m)

			# Executing module in check mode
			if self.checkmode:
				interface.check_default_route()
				if m.__init_thread__(0, config, None, None, None, None, self.verbosity):
					try:
						m.check()
					except KeyboardInterrupt:
						pass

			# Executing module in client mode
			if self.clientmode:
				try:
					remoteserverip = config.get("Global", "remoteserverip")
					if not config.has_section(m.get_module_configname()):
						common.internal_print("No section in config for module: {0}".format(m.get_module_configname()), -1)
						continue

					# if the module requires an indirect connection (proxy, 
					# dns) then we need to amend the routing table
					intermediate_hop = m.get_intermediate_hop(config)

					if config.has_option("Global", "overriderouter"):
						if common.is_ipv4(config.get("Global", "overriderouter")):
							intermediate_hop = config.get("Global", "overriderouter")

					if intermediate_hop and (not self.splitmode):
						remoteserverip = intermediate_hop
						interface.set_intermediate_route(config.get("Global", "remoteserverip"), remoteserverip)

					# init "thread" for client mode, this will not be run in a thread.
					if m.__init_thread__(0, config, client_tunnel, None, auth_module, encryption_module, self.verbosity):
						# run in client mode
						m.connect()

						# client finished, closing down tunnel and restoring routes
					interface.close_tunnel(client_tunnel)

					if self.splitmode:
						interface.del_split_route(self.scope, config.get("Global", "serverip"))
					else:
						interface.restore_routes(remoteserverip, config.get("Global", "clientip"), config.get("Global", "serverip"))
				except KeyboardInterrupt:
					# CTRL+C was pushed
					interface.close_tunnel(client_tunnel)

					if self.splitmode:
						interface.del_split_route(self.scope, config.get("Global", "serverip"))
					else:
						interface.restore_routes(remoteserverip, config.get("Global", "clientip"), config.get("Global", "serverip"))
					pass
				except socket.error as e:
					# socket related error
					interface.close_tunnel(client_tunnel)

					if self.splitmode:
						interface.del_split_route(self.scope, config.get("Global", "serverip"))
					else:
						interface.restore_routes(remoteserverip, config.get("Global", "clientip"), config.get("Global", "serverip"))
					if e.errno == errno.ECONNREFUSED:
						common.internal_print("Socket does not seem to answer.", -1)
					else:
						common.internal_print("Socket died, probably the server went down. ({0})".format(e.errno), -1)
				except:
					interface.close_tunnel(client_tunnel)

					if self.splitmode:
						interface.del_split_route(self.scope, config.get("Global", "serverip"))
					else:
						interface.restore_routes(remoteserverip, config.get("Global", "clientip"), config.get("Global", "serverip"))
					raise

		# No modules are running
		if not module_threads:
			common.internal_print("Exiting...")
			if self.servermode:
				ps.stop()
		else:
			try:
				time.sleep(0.5)
				common.internal_print("Please use CTRL+C to exit...")
				# found no better solution to keep the main thread and catch CTRL+C
				# if you know any, you know how to tell me ;)
				while True:
					time.sleep(1000)
			except KeyboardInterrupt:
				common.internal_print("Interrupted. Exiting...")
				ps.stop()
				for t in module_threads:
					t.stop()

		# give one sec to clean up for modules, otherwise some objects just
		# disapper and cannot be closed properly like the tunnel interface
		try:
			time.sleep(1.0)
		except KeyboardInterrupt:
			common.internal_print("Are you really this impatient????", -1)
			pass

# main function
if __name__ == "__main__":
		xfltreat = XFLTReaT()
		xfltreat.run(sys.argv[1:])


