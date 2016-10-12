from Conntrack import *
import time


x = ConnectionManager()

begin = time.time()
for i in range(30000, 40000):
	x.delete(ipversion=4, proto=6, sport=i, dport=11211)

end = time.time()

print "Executed time: " + str(end-begin)