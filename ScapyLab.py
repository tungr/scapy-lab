from scapy.all import *

print("---------------- Creating a Packet ----------------\n")

packetA = IP(ttl=10)
packetA.src="127.0.0.1"
packetA.dst="1.2.3.4"

packetA.show()

print("---------------- Sending a Packet ----------------\n")

send(IP(dst="www.google.com")/ICMP())

print("---------------- Sending and Receiving a Packet ----------------\n")

p = sr1(IP(dst="www.slashdot.org")/ICMP()/"Raw text being sent for testing")

if p:
	p.show()

print("---------------- Establshing a HTTP connection ----------------\n")

load_layer("http")
http_request("www.google.com", "/", display=True)

req = HTTP()/HTTPRequest(
    Accept_Encoding=b'gzip',
    Connection=b"keep-alive",
    Host=b'www.google.com'
    )

pkt = TCP_client.tcplink(HTTP, "www.google.com", 80)
ans = pkt.sr1(req)
ans.show()
pkt.close()

print("---------------- Sniffing ----------------\n")

sniff(iface="enp0s3", prn=lambda x: x.show())
sniff(iface="enp0s3", prn=lambda x: x.summary())

pkts = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))

wrpcap("Session1.cap",pkts)
pkts = rdpcap("Session1.cap")
