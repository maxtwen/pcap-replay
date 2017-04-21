import dpkt
import socket
from contextlib import closing, contextmanager
from optparse import OptionParser


@contextmanager
def ignored(excpts, errno_list):
    try:
        yield
    except excpts:
        pass
    except socket.error as serr:
        if serr.errno in errno_list:
            return
        raise serr


def pcap_handler(path, ignore_errno_list, timeout=1):
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

            with ignored(socket.timeout, errno_list=ignore_errno_list), closing(socket.socket(socket.AF_INET, protocol)) as sock_client:
                sock_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock_client.settimeout(timeout)
                sock_client.connect((dst_ip, dst_port))
                sock_client.send(data)
                sock_client.shutdown(socket.SHUT_WR)
                sock_client.recv(0)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="path",
                      help="path to pcap file", )
    parser.add_option("-t", "--timeout", dest="timeout",
                      help="recv timeout in seconds (default=1)",
                      default=1)
    parser.add_option("-i", "--ignore", dest="ignore",
                      help="""ignore specified socket errors. \n
                           54 - Connection reset by peer \n
                           61 - Connection refused \n
                           110 - Connection timed out \n""",
                      choices=('54', '61', '110'), type='choice',
                      default=[], action='append')
    (options, args) = parser.parse_args()
    pcap_handler(path=options.path, timeout=options.timeout, ignore_errno_list=map(int, options.ignore))
