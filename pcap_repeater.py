import dpkt
import sys
import socket


if __name__ == '__main__':
    path = sys.argv
    for ts, pkt in dpkt.pcap.Reader(open(path, 'r')):
        eth = dpkt.ethernet.Ethernet(pkt)
        dst_ip = socket.inet_ntoa(eth.ip.dst)
        src_ip = socket.inet_ntoa(eth.ip.src)
        dst_port = eth.ip.data.dport
        src_port = eth.ip.data.sport
        data = eth.ip.data.data
        print eth, dst_ip, src_ip, dst_port, src_port, data
