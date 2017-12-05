# -*- coding:utf-8 -*-
import socket,argparse
import npa_tools as NT
import graphics_tools as GT
import threading

parser = argparse.ArgumentParser(description = "Network Port Art. Displays some colored packed circles based on the packet that sniffs.")
parser.add_argument("--port",help="N -> Sniff that port, N1-N2...Nk -> Sniff those ports")
parser.add_argument("--host",help="An IPv4 address")
parser.add_argument("--direction",help="IN -> Sniff incoming packets, OUT -> Sniffs outgoing packets")
parser.add_argument("--noPack",help="Does not pack circles",action="store_true")

args = parser.parse_args()

if(args.host != None):
    host = args.host
else:
    # l'interfaccia network pubblica
    nomePc = socket.gethostname()
    host = socket.gethostbyname_ex(nomePc)[2][-1] #indirizzo IPv4

#Parse the ports
ports = args.port
if ports != None:
    ports = args.port.split("-")
    ports = filter(bool,ports) #delete all empty strings
    ports = map(int, ports)

direction = args.direction
if direction != None:
    direction = direction.upper()
if direction not in [None, "IN", "OUT"]:
    parser.error("Direction command not recognized.")


width, height = GT.initializeTK()
maxPackets = 2000
#[{"c" : cerchio1, "s" : cerchio1.show()},...]
circles = []
#{"streamvalue" : [pkt1,pkt2,...,pktn]}
streams = {}

def addTcp(circle):

    streamValue = circle.pkt.getStreamValue()

    if (streamValue in streams):
        #presente = False
        p = next((x for x in streams[streamValue] if x.pkt == circle.pkt),None)
        # for x in streams[streamValue]:
        #     presente = x == tcp
        #     if presente:
        #         break
        if p == None:
            #è la prima volta che vedo questo pacchetto
            streams[streamValue].append(circle)
            #color = "green"
        else:
            #il pacchetto è stato ritrasmesso
            circle.pkt.retransmitted = True
    else:
        #connessione mai vista
        streams[streamValue] = [circle]

def checkPacket(circle):
    global ports, direction, host
    IN = direction == "IN"
    OUT = direction == "OUT"
    BOTH = direction == None
    srcAddr = circle.pkt.header.srcAddr
    dstAddr = circle.pkt.header.dstAddr
    srcPort = circle.pkt.srcPort
    dstPort = circle.pkt.dstPort

    if ports == None:
        if BOTH:
            #possiamo sniffare tutto
            return True
        elif IN:
            #solo i pacchetti in entrata
            return dstAddr == host
        elif OUT:
            #solo i pacchetti in uscita
            return srcAddr == host
    else:
        #abbiamo una lista di porte su cui sniffare
        if BOTH:
            return srcPort in ports or dstPort in ports
        elif IN:
            return dstAddr == host and dstPort in ports
        elif OUT:
            return srcAddr == host and srcPort in ports

def findXY():
    k = 0
    x, y = 0, 0
    tentativi = 500
    valido = False
    while k < tentativi and not valido:
        x = GT.rndInt(0,width)
        y = GT.rndInt(0,height)
        if len(circles) > 0:
            for ck in circles:
                valido &= GT.dst(x,y,ck["c"].x,ck["c"].y) > ck["c"].r
                if not valido:
                    break

        else:
            break
        k += 1

    return x, y

def start():

    global width, height, host

    NT.initializeNPA(host)

    while len(circles) < maxPackets or args.noPack:

        pkt = None
        if not args.noPack:
            x, y = findXY()
        else:
            x, y = GT.rndInt(0,width), GT.rndInt(0,height)
        data = NT.receiveData()
        ip = NT.createIP(data[:20]) #solo i primi 20 byte perchè dopo c'è il payload
        if ip.protocol == 6:
            pkt = NT.createTCP(data[20:40],ip)
            if not args.noPack:
                circle = GT.Circle(x,y,pkt)
            else:
                circle = GT.Circle(x,y,pkt,GT.rndInt(15,30))
            if checkPacket(circle):
                addTcp(circle)
                circles.append({"c" : circle, "s" : circle.show()})
        elif ip.protocol == 17:
            pkt = NT.createUDP(data[20:28],ip)
            if not args.noPack:
                circle = GT.Circle(x,y,pkt)
            else:
                circle = GT.Circle(x,y,pkt,GT.rndInt(5,10))
            if checkPacket(circle):
                circles.append({"c" : circle, "s" : circle.show()})

        while GT.CRITICAL_ZONE:
            pass
        if not args.noPack:
            GT.CRITICAL_ZONE = True
            for ci in circles:
                if ci["c"].growing:
                    if not ci["c"].edges() and not ci["c"].others(circles):
                        ci["c"].grow()
                        GT.canvas.coords(ci["s"],ci["c"].x-ci["c"].r,ci["c"].y-ci["c"].r,ci["c"].x+ci["c"].r,ci["c"].y+ci["c"].r)
                    else:
                        ci["c"].growing = False
            GT.canvas.update()
            GT.CRITICAL_ZONE = False

def main():
    t1 = threading.Thread(target=start)
    t1.daemon = True
    t1.start()

GT.root.after(0,main)
GT.root.mainloop()
