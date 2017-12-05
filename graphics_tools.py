# -*- coding:utf-8 -*-
from Tkinter import *
import npa_tools as NT
import socket
import random
import math

#elimina il conflitto tra toggleFullscreen e l'aggiornamento del canvas
CRITICAL_ZONE = False
FULLSCREEN = True
root = None
canvas = None
maxS = 100
width = 0
height = 0

def initializeTK():
    global root, canvas, FULLSCREEN, width, height
    root = Tk()
    root.bind("<F11>",toggleFullscreen)
    root.protocol("WM_DELETE_WINDOW", onclose)
    root.attributes("-fullscreen",FULLSCREEN)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    canvas = Canvas(root, width = screen_width, height = screen_height)
    canvas.pack()
    # canvas["bg"] = "black"
    width, height = (screen_width, screen_height)
    return (screen_width, screen_height)

def toggleFullscreen(event):
    global FULLSCREEN, CRITICAL_ZONE, root
    while(CRITICAL_ZONE):
        pass
    CRITICAL_ZONE = True
    FULLSCREEN = not FULLSCREEN
    root.attributes("-fullscreen",FULLSCREEN)
    CRITICAL_ZONE = False

def rndCol(target = None):
    r = lambda : random.randint(0,255)
    if (target != None):
        if (target == "red"):
            return "#%02X%02X%02X" % (255,r()%200,r()%128)
        elif (target == "blue"):
            return "#%02X%02X%02X" % (r()%128,r(),255)

    return "#%02X%02X%02X" % (r(),r(),r())

def rndInt(minR,maxR):
    return random.randint(minR,maxR)

def dst(x1,y1,x2,y2):
    a = math.fabs(x1-x2)
    b = math.fabs(y1-y2)
    return math.sqrt(a*a+b*b)

def onclose():
    # disattiva la modalita promisqua
    NT.SOCKET.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    #chiude il socket
    NT.SOCKET.close()
    #chiude l'applicazione
    root.destroy()

class Circle(object):

    def __init__(self,x,y,pkt,radius = 2):
        self.x = x
        self.y = y
        self.r = radius
        self.s = len(pkt)*maxS/1500
        self.pkt = pkt
        self.growing = True

    def show(self):
        r = 0
        color = ""
        width = 3
        outline = ""
        if (type(self.pkt) is NT.TCPPacket):
            color = rndCol("red")
            if (self.pkt.retransmitted):
                color = "#03C03C"
            if self.pkt.flags == ["ACK"]:
                outline = "#00FFFF" #ciano
            elif self.pkt.flags == ["SYN", "ACK"]:
                outline = "#05ae5a" #verde scuro
            elif self.pkt.flags == ["SYN"]:
                outline = "blue"
            elif self.pkt.flags == ["PSH", "ACK"]:
                outline = "#bd00ff" #viola scuro
            elif self.pkt.flags == ["FIN","ACK"]:
                outline = "#FF9A00" #arancione
            elif "URG" in self.pkt.flags:
                outline = "red"
            elif "RST" in self.pkt.flags:
                outline = "black"
        else:
            width = 1
            color = rndCol("blue")
            outline = "black"

        return canvas.create_oval(
            self.x-self.r,
            self.y-self.r,
            self.x+self.r,
            self.y+self.r,
            fill = color,
            outline = outline,
            width = width
        )

    def grow(self):
        if self.growing and self.r <= self.s:
            self.r += 1

    def edges(self):
        return (self.x + self.r) > width or (self.y + self.r) > height or (self.x - self.r) < 0 or (self.y - self.r) < 0

    def others(self,c):
        touch = False
        for x in c:
            if x["c"] != self:
                d = dst(x["c"].x,x["c"].y,self.x,self.y)
                touch = d <= (x["c"].r + self.r)
                if touch:
                    return True

        return False
