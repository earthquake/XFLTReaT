import sys

if "checks.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import struct
import random

class Checks():
	def __init__(self):
		return

	def check_default_generate_challange(self):
		number1 = random.randint(0, 4294967295)
		number2 = random.randint(0, 4294967295)
		number3 = number1 ^ number2

		return (struct.pack(">II", number1, number2), struct.pack(">I", number3))

	def check_default_calculate_challange(self, leftover):
		numbers = struct.unpack(">II", leftover)
		return struct.pack(">I", numbers[0] ^ numbers[1])