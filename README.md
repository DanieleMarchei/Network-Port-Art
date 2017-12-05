# Network Port Art
A project I made for an exam.

This programs sniff incoming and outcoming TCP/UDP packets on a port or a set of ports.
Once a packet is sniffed, draws a circle on the screen.

TCP packets are displayed as red-ish color (green if retrasmitted), with an outline:
- cyan        if ACK
- dark green  if SYN ACK
- blu         if SYN
- dark violet if PSH ACK
- orange      if FIN ACK
- red         if URG
- black       if RST

UDP datagrams are displayed as blu-ish.
The program tries his best to pack the circles (without intersections).

# How to use it
Using console and the command
```cmd
-h --help
```
you can see the help.
```cmd
--port n1-n2...nk to sniff the k port you selected
--host define the IPv4 host to sniff
--direction in/out to sniff incoming/outocming packets (both if not specified)
--noPack draws random circles without packing
```
