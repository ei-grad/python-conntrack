from Conntrack import *



x = ConnectionManager()

for i in range(30000, 40000):
	x.delete(ipversion=4, proto=6, sport=i, dport=5672)
