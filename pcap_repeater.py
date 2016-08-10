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

        if type(eth.ip.data) == dpkt.udp.UDP:
            protocol = socket.SOCK_DGRAM
        elif type(eth.ip.data) == dpkt.tcp.TCP:
            protocol = socket.SOCK_STREAM
        else:
            raise TypeError

        sock_client = socket.socket(socket.AF_INET, protocol)
        sock_client.connect((dst_ip, dst_port))
        sock_client.send(data)
        sock_client.recv(0)
