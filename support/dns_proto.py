import sys

if "dns_proto.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import struct
import socket

# local modules
import client
import common

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
	'''
	def replace(self, what, to):
		for _item in self.__item_pool:
			if _item[2] == what:
				_item = to
				return 

		return 
	'''
	def length(self):

		return len(self.__item_pool)

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
				return item_[3]

		return None

	def remove_specific(self, pn, fn):
		for item_ in self.__item_pool:
			if (item_[0] == pn) and (item_[1] == fn):
				self.__item_pool.remove(item_)
				return

		return 

class DNS_common():

	def create_fragment_header(self, channel_bit, userid, packet_num, fragment_num, last_fragment):
		if last_fragment:
			last_fragment = 0x01
		else:
			last_fragment = 0x00

		return struct.pack(">H", (channel_bit << 8) | ((userid & 0x07) << 12) | ((packet_num & 0x7F) << 5) | ((fragment_num & 0x0F) << 1) | last_fragment)

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
			1 : ["A", self.build_record_A],
			2 : ["NS", self.build_record_NS],
		    3 : ["MD", None],
		    4 : ["MF", None],
		    5 : ["CNAME", None],
		    6 : ["SOA", self.build_record_SOA],
		    7 : ["MB", None],
		    8 : ["MG", None],
		    9 : ["MR", None],
		    10 : ["NULL", self.build_record_NULL],
		    11 : ["WKS", None],
		    12 : ["PTR", None],
		    13 : ["HINFO", None],
		    14 : ["MINFO", None],
		    15 : ["MX", None],
		    16 : ["TXT", None],
		    17 : ["RP", None],
		    18 : ["AFSDB", None],
		    19 : ["X25", None],
		    20 : ["ISDN", None],
		    21 : ["RT", None],
		    22 : ["NSAP", None],
		    23 : ["NSAP-PTR", None],
		    24 : ["SIG", None],
		    25 : ["KEY", None],
		    26 : ["PX", None],
		    27 : ["GPOS", None],
		    28 : ["AAAA", None],
		    29 : ["LOC", None],
		    30 : ["NXT", None],
		    31 : ["EID", None],
		    32 : ["NIMLOC", None],
		    33 : ["SRV", None],
		    34 : ["ATMA", None],
		    35 : ["NAPTR", None],
		    36 : ["KX", None],
		    37 : ["CERT", None],
		    38 : ["A6", None],
		    39 : ["DNAME", None],
		    40 : ["SINK", None],
		    41 : ["OPT", None],
		    42 : ["APL", None],
		    43 : ["DS", None],
		    44 : ["SSHFP", None],
		    45 : ["IPSECKEY", None],
		    46 : ["RRSIG", None],
		    47 : ["NSEC", None],
		    48 : ["DNSKEY", None],
		    49 : ["DHCID", None],
		    50 : ["NSEC3", None],
		    51 : ["NSEC3PARAM", None],
		    52 : ["TLSA", None],
		    53 : ["SMIMEA", None],
		    #54 : ["Unassigned", None],
		    55 : ["HIP", None],
		    56 : ["NINFO", None],
		    57 : ["RKEY", None],
		    58 : ["TALINK", None],
		    59 : ["CDS", None],
		    60 : ["CDNSKEY", None],
		    61 : ["OPENPGPKEY", None],
		    62 : ["CSYNC", None],
		    ## TEST
		    #63-98 : ["Unassigned", None],
		    99 : ["SPF", None],
		    100 : ["UINFO", None],
		    101 : ["UID", None],
		    102 : ["GID", None],
		    103 : ["UNSPEC", None],
		    104 : ["NID", None],
		    105 : ["L32", None],
		    106 : ["L64", None],
		    107 : ["LP", None],
		    108 : ["EUI48", None],
		    109 : ["EUI64", None],
		    ## TEST
		    #110-248 : ["Unassigned", None],
		    249 : ["TKEY", None],
		    250 : ["TSIG", None],
		    251 : ["IXFR", None],
		    252 : ["AXFR", None],
		    253 : ["MAILB", None],
		    254 : ["MAILA", None],
		    255 : ["*", self.build_record_ANY],
		    256 : ["URI", None],
		    257 : ["CAA", None],
		    258 : ["AVC", None],
		    ## TEST
		    #259-32767 : ["Unassigned", None],
		    32768 : ["TA", None],
		    32769 : ["DLV", None],
		    ## TEST
			#65280-65534 : ["Private use", None],
			## TEST
		    #65535 : "Reserved"
		}
		return

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
		#?????
		additional_record_num = 0
		additional_records = ""

		answer_num = 1

		answers = struct.pack(">HHHIH", 0xc00c, 10, 1, 0, len(record[1])) + record[1]
		
		return (answer_num, answers, additional_record_num, additional_records)

	'''
	hostname = "xfltreat.info"
	ip = "54.76.113.73"
	zone = {
		0 : ["A", "", ip],
		1 : ["A", "www", ip],
		2 : ["NS", "", "ns1.rycon.hu", ip],
		3 : ["SOA", "", "ns1.rycon.hu", "postmaster."+hostname, 2017070101, 43200, 10800, 604800, 1800],
		4 : ["*", "", hostname, ip]
	}
	'''
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
		#print data
		#print hostname
		qhostname = self.hostname_to_hostnamebin(data+hostname)
		#print "%r" % qhostname

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

			#print "short hostname: {0}".format(short_hostname)

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