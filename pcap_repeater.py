from contextlib import contextmanager, closing

import dpkt
import sys
import socket


@contextmanager
def ignored(excpts):
    try:
        yield
    except excpts:
        pass


def pcap_handler(path, timeout=1):
    for ts, pkt in dpkt.pcap.Reader(open(path, 'r')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            dst_ip = socket.inet_ntoa(eth.ip.dst)
            # src_ip = socket.inet_ntoa(eth.ip.src)
            dst_port = eth.ip.data.dport
            # src_port = eth.ip.data.sport
            data = eth.ip.data.data

            if data is '':  # python caches and reuses short strings
                continue

            if type(eth.ip.data) == dpkt.udp.UDP:
                protocol = socket.SOCK_DGRAM
            elif type(eth.ip.data) == dpkt.tcp.TCP:
                protocol = socket.SOCK_STREAM
            else:
                raise TypeError

            with ignored(socket.timeout), closing(socket.socket(socket.AF_INET, protocol)) as sock_client:
                sock_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock_client.settimeout(timeout)
                sock_client.connect((dst_ip, dst_port))
                sock_client.send(data)
                sock_client.shutdown(socket.SHUT_WR)
                sock_client.recv(0)

if __name__ == '__main__':
    args = sys.argv
    pcap_handler(args[1], args[2])

