import time

from Conntrack import ConnectionManager


def test_connection_manager_delete_perfomance():
    x = ConnectionManager()
    begin = time.time()
    for i in range(30000, 40000):
        x.delete(ipversion=4, proto=6, sport=i, dport=11211)
    print("Executed time: " + str(time.time()-begin))


if __name__ == "__main__":
    test_connection_manager_delete_perfomance()
