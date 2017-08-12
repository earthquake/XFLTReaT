import sys

if "dns_proto.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import struct
import socket
import Queue
import math

# local modules
import client
import common


class DNS_Client(client.Client):
	def __init__(self):
		super(DNS_Client, self).__init__()
		self.userid = None
		self.query_queue = DNS_Queue()
		self.cache_queue = DNS_Queue()
		self.answer_queue = Queue.Queue()
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

	def get_encoding_class(self):
		return self.encoding_class

	def set_encoding_class(self, encoding_class):
		self.encoding_class = encoding_class
		return

	def get_encoding_needed(self):
		return self.encoding_needed

	def set_encoding_needed(self, encoding_needed):
		self.encoding_needed = encoding_needed
		return

class DNS_Queue:

	def __init__(self):
		self.__item_pool = []

	def is_item(self, item):
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
		for _item in self.__item_pool:
			if _item[2] == what:
				_item = to
				return
		return

	def qsize(self):

		return len(self.__item_pool)

	#TOCTOU?
	def how_many_expired(self, expire):
		expired = 0
		for _item in self.__item_pool:
			if _item[0] < expire:
				expired += 1

		return expired

	def get_an_expired(self, expire):
		for _item in self.__item_pool:
			if _item[0] < expire:
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
		self.userid_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	#def create_fragment_header(self, channel_bit, userid, packet_num, fragment_num, last_fragment):
	def create_fragment_header(self, channel_bit, packet_num, fragment_num, last_fragment):
		if last_fragment:
			last_fragment = 0x01
		else:
			last_fragment = 0x00

		return struct.pack(">H", (channel_bit << 8) | ((packet_num & 0x3FF) << 5) | ((fragment_num & 0x0F) << 1) | last_fragment)

	def get_channel_byte_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 8) & 0x80

	def get_userid_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 12) & 0x07

	def get_packet_number_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 5) & 0x7F

	def get_fragment_number_from_header(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num >> 1) & 0x0F

	def is_last_fragment(self, header):
		header_num = struct.unpack(">H", header)[0]

		return (header_num & 0x01) == 0x01

	def get_character_from_userid(self, userid):
		if userid < len(self.userid_alphabet):
			return self.userid_alphabet[userid]

		return self.userid_alphabet[0]

	def get_userid_from_character(self, userid):
		for i in range(0, len(self.userid_alphabet)):
			if self.userid_alphabet[i] == userid:
				return i
		return -1

	def get_userid_length(self):
		return len(self.userid_alphabet)

	# get default nameserver to know where to send packets
	# config file can override this.
	def get_nameserver(self):
		if common.get_os_type() == "Linux":
			f = open("/etc/resolv.conf", "r")
			content = f.read()
			f.close()
			nameserver = content[content.find("nameserver")+len("nameserver "):content[content.find("nameserver"):].find("\n")+content.find("nameserver")]
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
		zone = []
		j = 0

		f = open(filename, "r")
		content = f.read()
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
					zone.append([splitted[2], "", splitted[3], splitted[4]])
				else:
					zone.append([splitted[2], "", splitted[3]])

				i += 1
				continue

			splitted = lines[i].split(" ")
			zone.append([splitted[2], splitted[0], splitted[3]])
			i += 1
			continue

		return (origin, ttl, zone)


class DNS_Proto():
	def __init__(self):
		self.RR_types = {
			0 : ["", None, None, None], # answer with no answers
			1 : ["A", self.build_record_A, self.pack_record_hostname, self.unpack_record_hostname],
			2 : ["NS", self.build_record_NS, self.pack_record_id, self.unpack_record_id],
		    3 : ["MD", None, None, None],
		    4 : ["MF", None, None, None],
		    5 : ["CNAME", self.build_record_CNAME, self.pack_record_hostname, self.unpack_record_hostname],
		    6 : ["SOA", self.build_record_SOA, self.pack_record_id, self.unpack_record_id],
		    7 : ["MB", None, None, None],
		    8 : ["MG", None, None, None],
		    9 : ["MR", None, None, None],
		    10 : ["NULL", self.build_record_NULL, self.pack_record_id, self.unpack_record_id],
		    11 : ["WKS", None, None, None],
		    12 : ["PTR", None, None, None],
		    13 : ["HINFO", None, None, None],
		    14 : ["MINFO", None, None, None],
		    15 : ["MX", None, None, None],
		    16 : ["TXT", None, None, None],
		    17 : ["RP", None, None, None],
		    18 : ["AFSDB", None, None, None],
		    19 : ["X25", None, None, None],
		    20 : ["ISDN", None, None, None],
		    21 : ["RT", None, None, None],
		    22 : ["NSAP", None, None, None],
		    23 : ["NSAP-PTR", None, None, None],
		    24 : ["SIG", None, None, None],
		    25 : ["KEY", None, None, None],
		    26 : ["PX", None, None, None],
		    27 : ["GPOS", None, None, None],
		    28 : ["AAAA", None, None, None],
		    29 : ["LOC", None, None, None],
		    30 : ["NXT", None, None, None],
		    31 : ["EID", None, None, None],
		    32 : ["NIMLOC", None, None, None],
		    33 : ["SRV", None, None, None],
		    34 : ["ATMA", None, None, None],
		    35 : ["NAPTR", None, None, None],
		    36 : ["KX", None, None, None],
		    37 : ["CERT", None, None, None],
		    38 : ["A6", None, None, None],
		    39 : ["DNAME", None, None, None],
		    40 : ["SINK", None, None, None],
		    41 : ["OPT", None, None, None],
		    42 : ["APL", None, None, None],
		    43 : ["DS", None, None, None],
		    44 : ["SSHFP", None, None, None],
		    45 : ["IPSECKEY", None, None, None],
		    46 : ["RRSIG", None, None, None],
		    47 : ["NSEC", None, None, None],
		    48 : ["DNSKEY", None, None, None],
		    49 : ["DHCID", None, None, None],
		    50 : ["NSEC3", None, None, None],
		    51 : ["NSEC3PARAM", None, None, None],
		    52 : ["TLSA", None, None, None],
		    53 : ["SMIMEA", None, None, None],
		    #54 : ["Unassigned", None, None, None],
		    55 : ["HIP", None, None, None],
		    56 : ["NINFO", None, None, None],
		    57 : ["RKEY", None, None, None],
		    58 : ["TALINK", None, None, None],
		    59 : ["CDS", None, None, None],
		    60 : ["CDNSKEY", None, None, None],
		    61 : ["OPENPGPKEY", None, None, None],
		    62 : ["CSYNC", None, None, None],
		    ## TEST
		    #63-98 : ["Unassigned", None, None, None],
		    99 : ["SPF", None, None, None],
		    100 : ["UINFO", None, None, None],
		    101 : ["UID", None, None, None],
		    102 : ["GID", None, None, None],
		    103 : ["UNSPEC", None, None, None],
		    104 : ["NID", None, None, None],
		    105 : ["L32", None, None, None],
		    106 : ["L64", None, None, None],
		    107 : ["LP", None, None, None],
		    108 : ["EUI48", None, None, None],
		    109 : ["EUI64", None, None, None],
		    ## TEST
		    #110-248 : ["Unassigned", None, None, None],
		    249 : ["TKEY", None, None, None],
		    250 : ["TSIG", None, None, None],
		    251 : ["IXFR", None, None, None],
		    252 : ["AXFR", None, None, None],
		    253 : ["MAILB", None, None, None],
		    254 : ["MAILA", None, None, None],
		    255 : ["*", self.build_record_ANY, self.pack_record_id, self.unpack_record_id],
		    256 : ["URI", None, None, None],
		    257 : ["CAA", None, None, None],
		    258 : ["AVC", None, None, None],
		    ## TEST
		    #259-32767 : ["Unassigned", None, None, None],
		    32768 : ["TA", None, None, None],
		    32769 : ["DLV", None, None, None],
		    65399 : ["PRIVATE", self.build_record_PRIVATE, self.pack_record_id, self.unpack_record_id]
		    ## TEST
			#65280-65534 : ["Private use", None, None, None],
			## TEST
		    #65535 : "Reserved"
		}
		return


	def pack_record_id(self, data):
		return data

	def unpack_record_id(self, data):
		return data

	def pack_record_hostname(self, data):
		hostname = ""
		for j in range(0,int(math.ceil(float(len(data))/63))):
			hostname += data[j*63:(j+1)*63]+"."

		return hostname

	def unpack_record_hostname(self, data):
		hostname = self.hostnamebin_to_hostname(data)[1].replace(".", "")
		return hostname.replace(".", "")

	def build_record_A(self, record):
		additional_record_num = 0
		additional_records = ""
		answer_num = 1
		answers = struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton(record[2]) 

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_NS(self, record):
		additional_record_num = 0
		additional_records = ""
		compress_hostname = self.hostname_to_hostnamebin(record[2])

		answer_num = 1
		answers = struct.pack(">HHHIH", 0xc00c, 2, 1, 3600, len(compress_hostname)) + compress_hostname
		
		#additional_record_num = 1
		#additional_records = compress_hostname + struct.pack(">HHIH", 1, 1, 5, 4) + socket.inet_aton("1.1.1.1")

		return (answer_num, answers, additional_record_num, additional_records)


	def build_record_CNAME(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = ""
		answer_num = 1
		answers = struct.pack(">HHHIH", 0xc00c, 5, 1, 5, len(compress_hostname)) + compress_hostname

		return (answer_num, answers, additional_record_num, additional_records)


	def build_record_ANY(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = ""

		answer_num = 2
		answers =  struct.pack(">HHHIH", 0xc00c, 5, 1, 5, len(compress_hostname)) + compress_hostname
		answers += struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton(record[3])
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_SOA(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = ""

		answer_num = 1
		#data = self.hostname_to_hostnamebin(record[2]) + self.hostname_to_hostnamebin(record[3]) + struct.pack(">IIIII", record[4], record[5], record[6], record[7], record[8])
		data = compress_hostname + self.hostname_to_hostnamebin(record[3]) + struct.pack(">IIIII", record[4], record[5], record[6], record[7], record[8])

		answers = struct.pack(">HHHIH", 0xc00c, 6, 1, 5, len(data)) + data
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_NULL(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = 1

		answers = struct.pack(">HHHIH", 0xc00c, 10, 1, 0, len(record[2])) + record[2]
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_PRIVATE(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = 1

		answers = struct.pack(">HHHIH", 0xc00c, 65399, 1, 0, len(record[2])) + record[2]
		
		return (answer_num, answers, additional_record_num, additional_records)


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

		for i in xrange(len(zone)):
			if (zone[i][0] == self.RR_types[qtype][0]) and (zone[i][1] == short_hostname):
				return zone[i]

		return None

	def hostname_to_hostnamebin(self, hostname):
		if hostname[len(hostname)-1:len(hostname)] != ".":
			hostname += "."
		i = 0

		hostnamebin = ""
		while not hostname[i:].find(".") == -1:
			hostnamebin += struct.pack("B", hostname[i:].find(".")) + hostname[i:i+hostname[i:].find(".")]
			i = i + hostname[i:].find(".")+1

		hostnamebin += "\x00"

		return hostnamebin

	def hostnamebin_to_hostname(self, hostnamebin):
		hostname = ""
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
				hostname += hostnamebin[i+1:i+1+l] + "."
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
			flag = 0x8403 # 1000 0100 0000 0011
			answer_num = 0
			answers = ""
			additional_record_num = 0
			additional_records = ""
		else:
			flag = 0x8400 #	1000 0100 0000 0000
			RRtype = self.reverse_RR_type(record[0])
			if RRtype[1] == None:
				answer_num = 0
				answers = ""
				additional_record_num = 0
				additional_records = ""
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
		rdata = ""
		transaction_id = struct.unpack(">H",msg[0:2])[0]
		flags = struct.unpack(">H",msg[2:4])[0]
		questions = struct.unpack(">H",msg[4:6])[0]
		answers = struct.unpack(">H",msg[6:8])[0]
		authority = struct.unpack(">H",msg[8:10])[0]
		additional = struct.unpack(">H",msg[10:12])[0]

		i = 12
		# parse question
		for q in xrange(questions):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])

			if question_hostname == hostname:
				short_hostname = ""
			else:
				short_hostname = question_hostname[0:len(question_hostname)-len(hostname)-1]

			if len(msg) >= i+hlen+4:
				orig_question = msg[i:i+hlen+4]
				i += hlen

				qtype = struct.unpack(">H",msg[i:i+2])[0]
				i += 4
			else:
				return (None, None, None, None, None, None, None)

		for q in xrange(answers):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if len(msg) >= i+hlen+10:
				i += hlen + 8
				rdlength = struct.unpack(">H",msg[i:i+2])[0]
				if len(msg) >= i + 2 + rdlength:
					rdata = msg[i+2:i+2+rdlength]
					i += 2 + rdlength
				else:
					return (None, None, None, None, None, None, None)
			else:
				return (None, None, None, None, None, None, None)

		for q in xrange(authority+additional):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if len(msg) >= i+hlen+10:
				i += hlen + 8
				rdlength = struct.unpack(">H",msg[i:i+2])[0]
				if len(msg) >= i + 2 + rdlength:
					i += 2 + rdlength
				else:
					return (None, None, None, None, None, None, None)
			else:
				return (None, None, None, None, None, None, None)

		return (transaction_id, not ((flags >> 15) & 0x01), short_hostname, qtype, orig_question, rdata, i)