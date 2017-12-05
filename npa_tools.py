# -*- coding:utf-8 -*-
import socket,sys,struct

SOCKET = None

def initializeNPA(host):

    global SOCKET
    #crea un raw socket e lo binda all' interfaccia pubblica
    # (family (IPv4), tipo_socket (RAW), protocollo (IP))
    SOCKET = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    SOCKET.bind((host, 0))

    #dobbiamo aggiungere un header IP così possiamo sapere che protocollo stiamo sniffando
    # (level (IP), optname(HDRINCL - includi header), value (1))
    SOCKET.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # attiaviamo la modalita promisqua
    # permette al socket di ricevere tutti i pacchetti passanti per l'interfaccia network
    #(control (ricevi tutto), option (riveci tutto ON))
    SOCKET.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

def receiveData():
    data = ""
    try:
        data = SOCKET.recvfrom(65565)
    except socket.timeout:
        data = ""
        return data
    except:
        print "Oooops, errore :("
        sys.exc_info()
    return data[0] #data è una tupla (data,address)

def createIP(data):
    unpackedData = struct.unpack("!BBHHHBBH4s4s",data)

    src = socket.inet_ntoa(unpackedData[8])
    dst = socket.inet_ntoa(unpackedData[9])
    length = int(unpackedData[2])
    ihl = unpackedData[0] & 0xF
    protocolNr = unpackedData[6]

    ip = IPPacket(protocolNr,src,dst,ihl,length)

    return ip

def createUDP(data,ip):
    d = {
    "sourceP" : 0,
    "destinationP" : 0,
    "length" : 0
    }
    unpackedData = struct.unpack("!HHHH",data)
    d["sourceP"] = unpackedData[0]
    d["destinationP"] = unpackedData[1]
    d["length"] = unpackedData[2]
    srcP = d["sourceP"]
    dstP = d["destinationP"]
    length = d["length"]
    udp = UDPPacket(ip,srcP,dstP,length)
    return udp

def createTCP(data,ip):
    unpackedData = struct.unpack("!HHLLHHHH",data)
    d = {
    "sourceP" : 0,
    "destinationP" : 0,
    "sequenceNr" : 0,
    "ackNr" : 0,
    "offset" : 0,
    "ECN" : 0,
    "control" : 0,
    "window" : 0,
    "checksum" : 0,
    "urgent" : 0
    }

    d["sourceP"] = unpackedData[0]
    d["destinationP"] = unpackedData[1]
    d["sequenceNr"] = unpackedData[2]
    d["ackNr"] = unpackedData[3]
    d["offset"] = (unpackedData[4] & 0xF000) >> 12
    d["ECN"] = (unpackedData[4] & 0x1C0) >> 6
    control = unpackedData[4] & 0x3F
    bits = "{0:06b}".format(control)
    bits = bits[::-1]
    cbits = []
    for i in [0,1,2,3,4,5]:
        check = int(bits[i])
        if(i == 0 and check == 1):
            cbits.append("FIN")
        elif(i == 1 and check == 1):
            cbits.append("SYN")
        elif(i == 2 and check == 1):
            cbits.append("RST")
        elif(i == 3 and check == 1):
            cbits.append("PSH")
        elif(i == 4 and check == 1):
            cbits.append("ACK")
        elif(i == 5 and check == 1):
            cbits.append("URG")
    d["control"] = cbits
    d["window"] = unpackedData[5]
    d["checksum"] = unpackedData[6]
    d["urgent"] = unpackedData[7]

    srcP = d["sourceP"]
    dstP = d["destinationP"]
    offset = d["offset"]
    seq = d["sequenceNr"]
    ack = d["ackNr"]
    flags = d["control"]
    window = d["window"]

    tcp = TCPPacket(ip,srcP,dstP,offset,seq,ack,flags,window)

    return tcp

class IPPacket(object):
    def __init__(self,protocol,src,dst,ihl,l):
        self.protocol = protocol
        self.srcAddr = src
        self.dstAddr = dst
        self.ihl = ihl
        self.length = l

    def __len__(self):
        return self.length

    def __eq__(self,ip):
        if(type(ip) is IPPacket):
            return (self.protocol == ip.protocol and self.srcAddr == ip.srcAddr
                    and self.dstAddr == ip.dstAddr and self.ihl == ip.ihl and self.length == ip.length)
        else:
            return False

    def __ne__ (self,ip):
        return not self.__eq__(ip)

class TCPPacket(object):
    def __init__(self,iphdr,srcP,dstP,offset,seq,ack,flags,window):
        self.header = iphdr
        self.srcPort = srcP
        self.dstPort = dstP
        self.dataOffset = offset
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window
        self.retransmitted = False

    def __len__(self):
        return len(self.header) - (self.header.ihl + self.dataOffset)*4

    def __str__(self):
        s = """<TCP>
        <srcAddr  v='%s' />
        <dstAddr  v='%s' />
        <srcPort v='%d' />
        <dstPort v='%d' />
        <seq v='%d' />
        <ack v='%d' />
        <flags v='%s' />
        <off v='%d' />
        <length v='%d' />
        </TCP>""" % (self.header.srcAddr,self.header.dstAddr,self.srcPort,self.dstPort,self.seq,self.ack,self.flags,self.dataOffset,self.__len__())
        return s

    def getStreamValue(self):
        a = 0
        if (self.header.srcAddr > self.header.dstAddr):
            a = (self.header.srcAddr, self.header.dstAddr)
        else:
            a = (self.header.dstAddr, self.header.srcAddr)

        b = 0
        if (self.srcPort > self.dstPort):
            b = (self.srcPort, self.dstPort)
        else:
            b = (self.dstPort, self.srcPort)

        return (a,b)

    def getOptionLength(self):
        return self.dataOffset*4 - 20

    def __eq__(self,tcp):
        if (type(tcp) is TCPPacket):
            return (self.header == tcp.header and self.srcPort == tcp.srcPort and
                    self.dstPort == tcp.dstPort and self.dataOffset == tcp.dataOffset and
                        self.seq == tcp.seq and self.ack == tcp.ack and self.flags == tcp.flags and
                            self.window == tcp.window and self.retransmitted == tcp.retransmitted)
        else:
            return False

class UDPPacket(object):
    def __init__(self,iphdr,srcP,dstP,l):
        self.header = iphdr
        self.srcPort = srcP
        self.dstPort = dstP
        self.length = l

    def __len__(self):
        return self.length

    def __str__(self):
        s = """<UDP>
        <srcPort v='%d' />
        <dstPort v='%d' />
        </UDP>
        """% (self.srcPort, self.dstPort)
        return s
