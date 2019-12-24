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

if "dns_proto.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import struct
import socket
import queue
import math

# local modules
import client
import common


class DNS_Client(client.Client):
	def __init__(self):
		super(DNS_Client, self).__init__()
		self.userid = None
		self.query_queue = DNS_Queue() # queue for queries < incoming
		self.repeated_queue = DNS_Queue() # same as query_queue but a bit longer expiry for repeated questions
		self.cache_queue = DNS_Queue() 
		self.answer_queue = DNS_Queue() # queue for answers > outgoing
		
		self.apacket_number = 0
		self.qfragments = {}
		self.qlast_fragments = {}
		self.recordtype = None
		self.encoding_class = None
		self.encoding_needed = True

	def set_userid(self, userid):
		self.userid = userid

	def get_userid(self):
		return self.userid

	def get_query_queue(self):
		return self.query_queue

	def get_cache_queue(self):
		return self.cache_queue

	def get_answer_queue(self):
		return self.answer_queue

	def get_repeated_queue(self):
		return self.repeated_queue

	def get_apacket_number(self):
		return self.apacket_number

	def set_apacket_number(self, apacket_number):
		self.apacket_number = apacket_number
		return

	def get_qfragments(self):
		return self.qfragments

	def get_qlast_fragments(self):
		return self.qlast_fragments

	def get_recordtype(self):
		return self.recordtype

	def set_recordtype(self, recordtype):
		self.recordtype = recordtype
		return

	def get_upload_encoding_class(self):
		return self.upload_encoding_class

	def set_upload_encoding_class(self, upload_encoding_class):
		self.upload_encoding_class = upload_encoding_class
		return

	def get_download_encoding_class(self):
		return self.download_encoding_class

	def set_download_encoding_class(self, download_encoding_class):
		self.download_encoding_class = download_encoding_class
		return

class DNS_Queue:

	def __init__(self):
		self.__item_pool = []

	def is_item1(self, item):
		for _item in self.__item_pool:
			if _item[1] == item:
				return True

		return False

	def is_item2(self, item):
		for _item in self.__item_pool:
			if _item[2] == item:
				return True

		return False

	def is_item_full(self, item):
		for _item in self.__item_pool:
			if _item == item:
				return True

		return False
	
	def replace(self, what, to):
		for i in range(len(self.__item_pool)):
			if self.__item_pool[i][2] == what:
				self.__item_pool[i] = to
				return
		return

	def replace_with_increase(self, what, to):
		for i in range(len(self.__item_pool)):
			if self.__item_pool[i][2] == what:
				to = to[0:4] + (self.__item_pool[i][4] + 1,)
				self.__item_pool[i] = to
				return
		return

	def qsize(self):

		return len(self.__item_pool)

	#TOCTOU?
	def how_many_expired(self, expire):
		expired = 0
		for _item in self.__item_pool:
			#if (_item[0] < expire) or (_item[4] == 2):
			if (_item[4] == 2):
				expired += 1

		return expired

	def get_an_expired(self, expire):
		for _item in self.__item_pool:
			#if (_item[0] < expire) or (_item[4] == 2):
			if (_item[4] == 2):
				self.__item_pool.remove(_item)
				return _item

	def remove_expired(self, expire):
		items_to_remove = []
		for _item in self.__item_pool:
			if _item[0] < expire:
				items_to_remove.append(_item)

		for _item in items_to_remove:
			self.__item_pool.remove(_item)
		return

	def put(self, item):

		return self.__item_pool.append(item)

	def get(self):
		item = self.__item_pool[0]
		self.__item_pool.remove(item)

		return item

	def get_last(self):
		item = self.__item_pool[len(self.__item_pool)-1]
		self.__item_pool.remove(item)

		return item


	def get_specific(self, pn, fn):
		for item_ in self.__item_pool:
			if (item_[1] == pn) and (item_[2] == fn):
				self.__item_pool.remove(item_)
				return item_[3]

		return None

	def remove_specific(self, pn, fn):
		for item_ in self.__item_pool:
			if (item_[0] == pn) and (item_[1] == fn):
				self.__item_pool.remove(item_)
				return

		return 

class DNS_common():
	def __init__(self):
		self.userid_alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789"

	#def create_fragment_header(self, channel_bit, userid, packet_num, fragment_num, last_fragment):
	def create_fragment_header(self, channel_bit, packet_num, fragment_num, last_fragment):
		if last_fragment:
			last_fragment = 0x01
		else:
			last_fragment = 0x00

		return struct.pack(">H", (int.from_bytes(channel_bit, "big") << 8) | ((packet_num & 0x3FF) << 5) | ((fragment_num & 0x0F) << 1) | last_fragment)

	def get_channel_byte_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 8) & 0x80

	def get_userid_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 12) & 0x07

	def get_packet_number_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 5) & 0x3FF

	def get_fragment_number_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 1) & 0x0F

	def is_last_fragment(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num & 0x01) == 0x01

	def get_character_from_userid(self, userid):
		if userid < len(self.userid_alphabet):
			return bytes([self.userid_alphabet[userid]])

		return bytes([self.userid_alphabet[0]])

	def get_userid_from_character(self, userid):
		for i in range(0, len(self.userid_alphabet)):
			if self.userid_alphabet[i:i+1] == userid:
				return i

		return -1

	def get_userid_length(self):
		return len(self.userid_alphabet)

	# get default nameserver to know where to send packets
	# config file can override this.
	def get_nameserver(self):
		if common.get_os_type() == common.OS_LINUX:
			f = open("/etc/resolv.conf", "r")
			content = f.read()
			f.close()
			for line in content.split("\n"):
				if line.replace(" ", "").replace("\t", "")[0:1] == "#":
					continue
				if line.find("nameserver") != -1:
					break

			nameserver = line[line.find("nameserver")+len("nameserver "):len(line)+line.find("nameserver")]
			if common.is_ipv4(nameserver) or common.is_ipv6(nameserver):
				return nameserver
			else:
				return None

	# in case a "bind" structured zone file is given, the zone will be 
	# constructed from it. The module will work as a DNS server, will answer
	# specifically to these queries.
	# this function parses the file and builds up an internal array
	# most probably buggy as hell. TODO?!
	def parse_zone_file(self, filename):
		ttl = ""
		domain = ""
		origin = ""
		ttl = ""
		zone = []
		j = 0

		f = open(filename, "r")
		content = f.read()
		if ("$ORIGIN" not in content) or ("$TTL" not in content):
			common.internal_print("Error: invalid zone file, $ORIGIN/$TTL is missing", -1)
			return (origin, ttl, zone)
		f.close()
		while (content.find("\t") != -1) or (content.find("  ") != -1):
			content = content.replace("\t", " ")
			content = content.replace("  ", " ")

		lines = content.split("\n")

		i = 0
		while i < len(lines):
			entry = []

			if lines[i][0:1] == ";":
				i += 1
				continue

			if lines[i] == "":
				i += 1
				continue

			if lines[i][0:len("$ORIGIN ")] == "$ORIGIN ":
				origin = lines[i][len("$ORIGIN "):]
				i += 1
				continue

			if lines[i][0:len("$TTL ")] == "$TTL ":
				ttl = lines[i][len("$TTL "):]
				i += 1
				continue

			if lines[i][0:len("@ IN SOA ")] == "@ IN SOA ":
				entry.append("SOA")
				entry.append("")
				p = lines[i][len("@ IN SOA "):]
				entry.append(p[0:p.find(" ")-1])
				p = p[p.find(" ")+1:]
				entry.append(p[0:p.find(" ")-1])

				entry.append(int(lines[i+1].split(" ")[1]))
				entry.append(int(lines[i+2].split(" ")[1]))
				entry.append(int(lines[i+3].split(" ")[1]))
				entry.append(int(lines[i+4].split(" ")[1]))
				entry.append(int(lines[i+5].split(" ")[1]))
				zone.append(entry)

				j += 1
				i += 6
				continue

			if lines[i][0:1] == " ":
				splitted = lines[i].split(" ")
				if splitted[2] == "MX":
					zone.append([splitted[2], "", splitted[3].encode('ascii'), splitted[4].encode('ascii')])
				else:
					zone.append([splitted[2], "", splitted[3].encode('ascii')])

				i += 1
				continue

			splitted = lines[i].split(" ")
			zone.append([splitted[2], splitted[0].encode('ascii'), splitted[3].encode('ascii')])
			i += 1
			continue

		return (origin.encode('ascii'), ttl, zone)


class DNS_Proto():
	def __init__(self):
		self.response_codes = ["", 
			"Query error: Format error - the DNS server does not support this format (maybe the query was too long)",
			"Query error: Server failure - the DNS server failed (maybe the response was too long, or the server is not running)",
			"Burning packets on server side",
			"Query error: Not implemented - the DNS does not support the record type",
			"Query error: Refused - DNS server is not willing to answer. (can the DNS server be used as relay?)",
			"Other error, malformed request/response, etc."]

		self.RR_types = {
			0 : ["", None, None, None, None], # answer with no answers
			1 : ["A", self.build_record_A, self.pack_record_hostname, self.unpack_record_hostname, self.calc_max_throughput_A],
			2 : ["NS", self.build_record_NS, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    3 : ["MD", None, None, None, None],
		    4 : ["MF", None, None, None, None],
		    5 : ["CNAME", self.build_record_CNAME, self.pack_record_hostname, self.unpack_record_hostname, self.calc_max_throughput_CNAME],
		    6 : ["SOA", self.build_record_SOA, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    7 : ["MB", None, None, None, None],
		    8 : ["MG", None, None, None, None],
		    9 : ["MR", None, None, None, None],
		    10 : ["NULL", self.build_record_NULL, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    11 : ["WKS", None, None, None, None],
		    12 : ["PTR", None, None, None, None],
		    13 : ["HINFO", None, None, None, None],
		    14 : ["MINFO", None, None, None, None],
		    15 : ["MX", None, None, None, None],
		    16 : ["TXT", None, None, None, None],
		    17 : ["RP", None, None, None, None],
		    18 : ["AFSDB", None, None, None, None],
		    19 : ["X25", None, None, None, None],
		    20 : ["ISDN", None, None, None, None],
		    21 : ["RT", None, None, None, None],
		    22 : ["NSAP", None, None, None, None],
		    23 : ["NSAP-PTR", None, None, None, None],
		    24 : ["SIG", None, None, None, None],
		    25 : ["KEY", None, None, None, None],
		    26 : ["PX", None, None, None, None],
		    27 : ["GPOS", None, None, None, None],
		    28 : ["AAAA", None, None, None, None],
		    29 : ["LOC", None, None, None, None],
		    30 : ["NXT", None, None, None, None],
		    31 : ["EID", None, None, None, None],
		    32 : ["NIMLOC", None, None, None, None],
		    33 : ["SRV", None, None, None, None],
		    34 : ["ATMA", None, None, None, None],
		    35 : ["NAPTR", None, None, None, None],
		    36 : ["KX", None, None, None, None],
		    37 : ["CERT", None, None, None, None],
		    38 : ["A6", None, None, None, None],
		    39 : ["DNAME", None, None, None, None],
		    40 : ["SINK", None, None, None, None],
		    41 : ["OPT", None, None, None, None],
		    42 : ["APL", None, None, None, None],
		    43 : ["DS", None, None, None, None],
		    44 : ["SSHFP", None, None, None, None],
		    45 : ["IPSECKEY", None, None, None, None],
		    46 : ["RRSIG", None, None, None, None],
		    47 : ["NSEC", None, None, None, None],
		    48 : ["DNSKEY", None, None, None, None],
		    49 : ["DHCID", None, None, None, None],
		    50 : ["NSEC3", None, None, None, None],
		    51 : ["NSEC3PARAM", None, None, None, None],
		    52 : ["TLSA", None, None, None, None],
		    53 : ["SMIMEA", None, None, None, None],
		    #54 : ["Unassigned", None, None, None, None],
		    55 : ["HIP", None, None, None, None],
		    56 : ["NINFO", None, None, None, None],
		    57 : ["RKEY", None, None, None, None],
		    58 : ["TALINK", None, None, None, None],
		    59 : ["CDS", None, None, None, None],
		    60 : ["CDNSKEY", None, None, None, None],
		    61 : ["OPENPGPKEY", None, None, None, None],
		    62 : ["CSYNC", None, None, None, None],
		    ## TEST
		    #63-98 : ["Unassigned", None, None, None, None],
		    99 : ["SPF", None, None, None, None],
		    100 : ["UINFO", None, None, None, None],
		    101 : ["UID", None, None, None, None],
		    102 : ["GID", None, None, None, None],
		    103 : ["UNSPEC", None, None, None, None],
		    104 : ["NID", None, None, None, None],
		    105 : ["L32", None, None, None, None],
		    106 : ["L64", None, None, None, None],
		    107 : ["LP", None, None, None, None],
		    108 : ["EUI48", None, None, None, None],
		    109 : ["EUI64", None, None, None, None],
		    ## TEST
		    #110-248 : ["Unassigned", None, None, None, None],
		    249 : ["TKEY", None, None, None, None],
		    250 : ["TSIG", None, None, None, None],
		    251 : ["IXFR", None, None, None, None],
		    252 : ["AXFR", None, None, None, None],
		    253 : ["MAILB", None, None, None, None],
		    254 : ["MAILA", None, None, None, None],
		    255 : ["*", self.build_record_ANY, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    256 : ["URI", None, None, None, None],
		    257 : ["CAA", None, None, None, None],
		    258 : ["AVC", None, None, None, None],
		    ## TEST
		    #259-32767 : ["Unassigned", None, None, None, None],
		    32768 : ["TA", None, None, None, None],
		    32769 : ["DLV", None, None, None, None],
		    65399 : ["PRIVATE", self.build_record_PRIVATE, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id]
		    ## TEST
			#65280-65534 : ["Private use", None, None, None, None],
			## TEST
		    #65535 : "Reserved"
		}
		return


	def calc_max_throughput_id(self, max_length, hostname, overhead, encoding_class):
		return encoding_class.get_maximum_length(max_length - overhead)

	def pack_record_id(self, data):
		return data

	def unpack_record_id(self, data):
		return data

	def pack_record_hostname(self, data):
		hostname = b""
		for j in range(0,int(math.ceil(float(len(data))/63.0))):
			hostname += data[j*63:(j+1)*63]+b"."

		return hostname

	def unpack_record_hostname(self, data):
		hostname = self.hostnamebin_to_hostname(data)[1].replace(b".", b"")

		return hostname.replace(b".", b"")

	def calc_max_throughput_A(self, max_length, hostname, overhead, encoding_class):
		# max - len("hostname.") - 1 - overhead - plus dots
		max_length -= len(hostname) + 1
		cap = 0
		while max_length > 64:
			cap += 63
			max_length -= 64
		cap += max_length - 1

		return encoding_class.get_maximum_length(cap) - overhead

	def build_record_A(self, record):
		additional_record_num = 0
		additional_records = b""
		answer_num = 1
		answers = struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton(record[2].decode('ascii')) 

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_NS(self, record):
		additional_record_num = 0
		additional_records = b""
		compress_hostname = self.hostname_to_hostnamebin(record[2])

		answer_num = 1
		answers = struct.pack(">HHHIH", 0xc00c, 2, 1, 3600, len(compress_hostname)) + compress_hostname
		
		#additional_record_num = 1
		#additional_records = compress_hostname + struct.pack(">HHIH", 1, 1, 5, 4) + socket.inet_aton("1.1.1.1")

		return (answer_num, answers, additional_record_num, additional_records)

	def calc_max_throughput_CNAME(self, max_length, hostname, overhead, encoding_class):
		# -1 for the zero byte at the end
		max_length -= 1
		cap = 0
		while max_length > 64:
			cap += 63
			max_length -= 64
		cap += max_length - 1

		return encoding_class.get_maximum_length(cap) - overhead

	def build_record_CNAME(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = b""
		answer_num = 1
		answers = struct.pack(">HHHIH", 0xc00c, 5, 1, 5, len(compress_hostname)) + compress_hostname

		return (answer_num, answers, additional_record_num, additional_records)


	def build_record_ANY(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = b""

		answer_num = 2
		answers =  struct.pack(">HHHIH", 0xc00c, 5, 1, 5, len(compress_hostname)) + compress_hostname
		answers += struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton(record[3])
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_SOA(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = b""

		answer_num = 1
		#data = self.hostname_to_hostnamebin(record[2]) + self.hostname_to_hostnamebin(record[3]) + struct.pack(">IIIII", record[4], record[5], record[6], record[7], record[8])
		data = compress_hostname + self.hostname_to_hostnamebin(record[3]) + struct.pack(">IIIII", record[4], record[5], record[6], record[7], record[8])

		answers = struct.pack(">HHHIH", 0xc00c, 6, 1, 5, len(data)) + data
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_NULL(self, record):
		additional_record_num = 0
		additional_records = b""

		answer_num = 1

		answers = struct.pack(">HHHIH", 0xc00c, 10, 1, 0, len(record[2])) + record[2]
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_PRIVATE(self, record):
		additional_record_num = 0
		additional_records = b""

		answer_num = 1

		answers = struct.pack(">HHHIH", 0xc00c, 65399, 1, 0, len(record[2])) + record[2]
		
		return (answer_num, answers, additional_record_num, additional_records)

	def get_RR_type(self, num):
		if num in self.RR_types:
			return self.RR_types[num]
		else:
			common.internal_print("Error: requested RR type was not in the list.", -1)
			return None

	def reverse_RR_type(self, RRtype):
		for i in self.RR_types:
			if self.RR_types[i][0] == RRtype:
				return self.RR_types[i]

		return 0

	def reverse_RR_type_num(self, RRtype):
		for i in self.RR_types:
			if self.RR_types[i][0] == RRtype:
				return i

		return 0


	def get_record(self, short_hostname, qtype, zone):
		if qtype not in self.RR_types:
			return None

		for i in range(len(zone)):
			if (zone[i][0] == self.RR_types[qtype][0]) and (zone[i][1] == short_hostname):
				return zone[i]

		return None

	def hostname_to_hostnamebin(self, hostname):
		if hostname[len(hostname)-1:len(hostname)] != b".":
			hostname += b"."
		i = 0

		hostnamebin = b""
		while not hostname[i:].find(b".") == -1:
			hostnamebin += struct.pack("B", hostname[i:].find(b"."))
			hostnamebin += hostname[i:i+hostname[i:].find(b".")]
			i = i + hostname[i:].find(b".")+1

		hostnamebin += b"\x00"

		return hostnamebin

	def hostnamebin_to_hostname(self, hostnamebin):
		hostname = b""
		i = 0
		length = 0

		while True:
			if len(hostnamebin) > i:
				l = struct.unpack("B",hostnamebin[i:i+1])[0]
				if l > 63:
					length += 2
					break
				if l == 0:
					length += 1
					break
				hostname += hostnamebin[i+1:i+1+l] + b"."
				length += l + 1
				i = i + l + 1
			else:
				break

		return (length, hostname)

	def is_valid_dns(self, msg, hostname):
		# check if the message's len is more than the minimum
		# header + base hostname + type+class
		if len(msg) < (17 + len(hostname)):
			return False

		flags = struct.unpack(">H",msg[2:4])[0]

		# if the message is not query
		#if ((flags >> 15) & 0x1):
		#	return False

		questions = struct.unpack(">H",msg[4:6])[0]

		# if the message does not have any questions
		if questions != 1:
			return False

		(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[12:])

		if hostname != question_hostname[len(question_hostname)-len(hostname):]:
			return False

		return True

	def build_answer(self, transaction_id, record, orig_question):
		if record == None:
			flag = 0x8503 # 1000 0100 0000 0011
			answer_num = 0
			answers = b""
			additional_record_num = 0
			additional_records = b""
		else:
			flag = 0x8500 #	1000 0100 0000 0000
			RRtype = self.reverse_RR_type(record[0])
			if RRtype[1] == None:
				answer_num = 0
				answers = b""
				additional_record_num = 0
				additional_records = b""
			else:
				answer_num = 1
				(answer_num, answers, additional_record_num, additional_records) = RRtype[1](record)

		dns_header = struct.pack(">HHHHHH", transaction_id, flag, 1, answer_num, 0, additional_record_num)

		return dns_header + orig_question + answers + additional_records

	def build_query(self, transaction_id, data, hostname, RRtype):
		flag = 0x0100 #0000 0010 0000 0000
		dns_header = struct.pack(">HHHHHH", transaction_id, flag, 1, 0, 0, 0)
		qhostname = self.hostname_to_hostnamebin(data+hostname)

		return dns_header + qhostname + struct.pack(">HH", RRtype, 1)


	def parse_dns(self, msg, hostname):
		rdata = b""
		transaction_id = struct.unpack(">H",msg[0:2])[0]
		flags = struct.unpack(">H",msg[2:4])[0]
		questions = struct.unpack(">H",msg[4:6])[0]
		answers = struct.unpack(">H",msg[6:8])[0]
		authority = struct.unpack(">H",msg[8:10])[0]
		additional = struct.unpack(">H",msg[10:12])[0]

		i = 12

		if ((flags & 0xF) > 0) and ((flags & 0xF) != 3):
			# Format error/Server failure/Not Implemented/Refused
			return (None, None, None, None, None, None, None, flags & 0xF)
		# parse question
		for q in range(questions):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if hlen == 0:
				return (None, None, None, None, None, None, None, 6)

			if question_hostname == hostname:
				short_hostname = b""
			else:
				short_hostname = question_hostname[0:len(question_hostname)-len(hostname)-1]

			if len(msg) >= i+hlen+4:
				orig_question = msg[i:i+hlen+4]
				i += hlen

				qtype = struct.unpack(">H",msg[i:i+2])[0]
				i += 4
			else:
				return (None, None, None, None, None, None, None, 6)

		for q in range(answers):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if len(msg) >= i+hlen+10:
				i += hlen + 8
				rdlength = struct.unpack(">H",msg[i:i+2])[0]
				if len(msg) >= i + 2 + rdlength:
					rdata = msg[i+2:i+2+rdlength]
					i += 2 + rdlength
				else:
					return (None, None, None, None, None, None, None, 6)
			else:
				return (None, None, None, None, None, None, None, 6)

		for q in range(authority+additional):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if len(msg) >= i+hlen+10:
				i += hlen + 8
				rdlength = struct.unpack(">H",msg[i:i+2])[0]
				if len(msg) >= i + 2 + rdlength:
					i += 2 + rdlength
				else:
					return (None, None, None, None, None, None, None, 6)
			else:
				return (None, None, None, None, None, None, None, 6)

		return (transaction_id, not ((flags >> 15) & 0x01), short_hostname, qtype, orig_question, rdata, i, 0)