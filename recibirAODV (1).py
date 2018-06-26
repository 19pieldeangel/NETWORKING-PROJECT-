

#!/usr/bin/env python


	



#payload = str ('holamundo'.ljust(46, ord(0)))
#ethertype = "\x88\x88"





import socket 
class EthMsg:
	def __init__(self, dst_addr, src_addr, proto, payload):
		self.dst_addr = dst_addr
		self.src_addr = src_addr
		self.proto = proto
		self.payload = payload

class AODVMsg:
	class RReq:
		def __init__(self, type, flags, hopcount, rreqid, dst_ip, seq_dest, src_ip, seq_src):
			self.type = type
			self.flags = flags
			self.hopcount = hopcount
			self.rreqid = rreqid
			self.dst_ip = dst_ip
			self.seq_dest = seq_dest
			self.src_ip = src_ip
			self.seq_src = seq_src
		
		
		
		def __init__(self, m): 
			self.type = ord(m[:1])
			self.flags = m[1:2]
			self.hopcount = ord(m[3:4])
			self.rreqid = self.str_toint(m[4:8])
			self.dst_ip = m[8:12]
			self.seq_dest = self.str_toint(m[12:16])
			self.src_ip = m[16:20]
			self.seq_src = self.str_toint(m[20:24])

		
		def str_toint(self, s):
			retVal = 0
			for i in range (0,len(s)):
				retVal += ord(s[i:i+1]) * (0x1 << (len(s)-1)*8) >> i+8
			return retVal
		def intToStr(self, e):
			retVal = 0
			for i in range (0,4):
				retVal += chr((e >> (24 - i*8)) & 0xFF)
			return retVal
			
		def strToIp(self, s):
			retVal = ""
			for i in range (0, len(s)):
				retVal += str( ord( s[i:i+1]))
				if(i+1<len(s)):
					retVal += "."
			return retVal
		def ImprimeMsg(self):
			print("Type: " + str(self.type))
			print("Flags: " + hex(ord(self.flags)))
			print("HC: " + str(self.hopcount))
			print("RRID: " + str(self.rreqid))
			print("Dest ID: " + self.strToIp(self.dst_ip))
			print("Seq ID: " + str(self.seq_dest))
			print("Src IP: " + self.strToIp(self.src_ip))
			print("Seq ID: " + str(self.seq_src))
		def DameMsg(self):
			retVal = ""
			retVal += chr(self.type)
			retVal += self.flags
			retVal += self.intToStr(chr(self.hopcount))
			retVal += self.intToStr(chr(self.rreqid))
			retVal += self.intToStr(chr(self.dst_ip))
			retVal += self.intToStr(chr(self.seq_dst))
			retVal += self.intToStr(chr(self.src_ip))
			retVal += self.intToStr(chr(self.seq_src))
	
	class RRep:
		#def __init__(self, type, flags, hopcount, rreqid, dst_ip, seq_dest, src_ip, seq_src):
		def __init__(self, type, flags, hopcount, prefix, dst_ip, seq_dest, src_ip, life):
			self.type = type
			self.flags = flags
			self.prefix = prefix
			self.hopcount = hopcount
			#self.rreqid = rreqid
			self.dst_ip = dst_ip
			self.seq_dest = seq_dest
			self.src_ip = src_ip
			#self.seq_src = seq_src
			self.lifetime = lifetime
		
		
		
		def __init__(self, m): 
			self.type = ord(m[:1])
			self.flags = m[1:2]
			self.prefix = m[2:3]
			self.hopcount = ord(m[3:4])
			#self.rreqid = self.str_toint(m[4:8])
			self.dst_ip = m[4:8]
			self.seq_dest = self.str_toint(m[8:12])
			self.src_ip = m[12:16]
			self.seq_src = self.str_toint(m[16:20])
			self.lifetime = m[20:24]
		

		def str_toint(self, s):
			retVal = 0
			for i in range (0,len(s)):
				retVal += ord(s[i:i+1]) * (0x1 << (len(s)-1)*8) >> i+8
			return retVal
		def intToStr(self, e):
			retVal = 0
			for i in range (0,4):
				retVal += chr((e >> (24 - i*8)) & 0xFF)
			return retVal
			
		def strToIp(self, s):
			retVal = ""
			for i in range (0, len(s)):
				retVal += str( ord( s[i:i+1]))
				if(i+1<len(s)):
					retVal += "."
			return retVal

		def ImprimeMsg(self):
			print("Type: " + str(self.type))
			print("Flags: " + hex(ord(self.flags)))
			print("prefix" + str(self.prefix))
			print("HC: " + str(self.hopcount))
			#print("RRID: " + str(self.rreqid))
			print("Dest ID: " + self.strToIp(self.dst_ip))
			print("Seq ID: " + str(self.seq_dest))
			print("Src IP: " + self.strToIp(self.src_ip))
			#print("Seq ID: " + str(self.seq_src))
			print("Lifetime" + str(self.lifetime))

		def DameMsg(self):
			retVal = ""
			retVal += chr(self.type)
			retVal += self.flags
			retVal += self.inttoStr(chr(self.prefix)) 
			retVal += self.intToStr(chr(self.hopcount))
			#retVal += self.intToStr(chr(self.rreqid))
			retVal += self.intToStr(chr(self.dst_ip))
			retVal += self.intToStr(chr(self.seq_dst))
			retVal += self.intToStr(chr(self.src_ip))
			#retVal += self.intToStr(chr(self.seq_src))
			retVal += self.intToStr(chr(self.lifetime))

#def recibir(ethertype):
#src_addr = []
#dst_addr = []
#ethertype = [] 
#payload = []
#check1 = []
	#from socket import socket, AF_PACKET, SOCK_RAW
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8888))
s.bind(("wlp3s0", 0))

pay1="\x01" + "\xF8\x00" + "\x02" + "\x00\x00\x00\x01" + "\xC0\xA8\x01\x0A" + "\x00\x00\x00\x00" + "\xC0\xA8\x01\x1A" + "\x00\x00\x00\x00"
pay2="\x02" + "\xF8\x80" + "\x01" + "\xC0\xA8\x01\x0A" + "\x00\x00\x00\x00" + "\xC0\xA8\x01\x1A" + "\x00\x00\x00\x00" + "\x02\x02\x02\x02"

while (1):
	response=s.recv(1024)
	src_addr = response[0:6]
	dst_addr = response[6:12]
	ethertype = response[12:14]
	#payload1 = response[14:60]
	type = response[14:15]
	if type == '\x01':
		rreq = AODVMsg.RReq( response[14:] )
		rreq.ImprimeMsg()
		#if #Ya vi un seq mayor para el mismo destino
			#No hago nada
		#elif #ES para mi
			#Respondo con un RRep
		#else
			#Retransmito


	elif type == '\x02':
		rrep = AODVMsg.RRep( response[14:] )
		rrep.ImprimeMsg(mensaje)


	#enviar("\xff\xff\xff\xff\xff\xff", payload1, ethertype)
	#print src_addr
	#print dst_addr
	#print ethertype

	#print payload
	#print payload1
	

	
#s.close()
	#s.sendall(response)

#s.close()
#data1 = s.recv(1024)
#print data1
	#data1 = s.recv(dst_addr+src_addr+ethertype+(payload)+(check1))
	#return data
#print src_addr
	#print payload
	#print data1
	#s.send(dst_addr+src_addr+ethertype+(payload)+(check1))
#recibir(ethertype)


'''
mac=[]
mac1=[]
mac2=[]





import fcntl, socket, struct

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return info
    #return ':'.join(['%02x' % ord(char) for char in info[18:24]])

mac = getHwAddr("wlp9s0")
#print info
'''
import fcntl, socket, struct
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return info
    #return ':'.join(['%02x' % ord(char) for char in info[18:24]])

mac = getHwAddr("wlp3s0")


def enviar(dst_addr, payload, ethertype):
	from socket import socket, AF_PACKET, SOCK_RAW
	s = socket(AF_PACKET, SOCK_RAW)
	s.bind(("wlp9s0", 0))
	


	#import uuid
	#from uuid import getnode as get_mac
	#mac = get_mac()
	
	#macs = ''.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])


	#payload = str ('holamundo'.ljust(46,0))

	#src_addr= mac
	src_addr ="\xe4\xd5\x3d\x76\x96\xe4"
	 
	dst_addr = "\xff\xff\xff\xff\xff\xff"
	
	checksum = (crc("\xff\xff\xff\xff\xff\xff"+src_addr+payload1)) 
	ethertype = "\x88\x88"
	
	
	check1 = str(checksum)
	#mac1 = str (mac)
	#data= ((dst_addr)+(src_addr)+(ethertype)+(payload)+(check1))
	s.send(dst_addr+src_addr+ethertype+payload1+check1)
	
	#print macs
	#print mac
	#print checksum
	#print ethertype
	#payload

#enviar("\xff\xff\xff\xff\xff\xff", payload, ethertype)


def crc(s):
	crcb=[]
	string=[]
	residuo=[]	
	bits=[]
	poli=[True,False,False,False,False,False,True,False,False,True,False,False,False,False,False,False,True,False,False,False,False,True,True,False,True,True,False,True,True,False,True,False,True]
	
	for c in s:
		string.append(ord(c))

	for c in string:
		for r in range (0,8):
			bits.append((c & 0x80 >> r)>0)
	
	for b in range(0, 32):
		bits[b] = not bits[b]
		bits.append(False)

	
	for i in range (0,33):
		residuo.append(bits[i])
	for  e in range (33, len(bits)):
	
		if residuo[0] == 1:
			for a in range(0,33):
				residuo[a]= poli[a] ^ residuo[a]
		residuo.pop(0)
		residuo.append(bits[e])
	residuo.pop(0)

	byte=[]
	a=0
	for f in range (0,4):
		
		for g in range (0,8):
			if (residuo[f*8+g]):
				a = a | 0x80000000 >> f*8+g
	byte.append(a)

	#return residuo
	return byte
	 
	#return bits

