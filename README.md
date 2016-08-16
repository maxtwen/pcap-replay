**Usage:**

sudo tcpdump -i lo dst host localhost and port 5000 -A -w  /path/to/mycap.pcap

python pcap_repeater.py -f /path/to/mycap.pcap

python pcap_repeater.py -f /path/to/mycap.pcap -i 54 -i 61

**Options:**

    -h, --help            show this help message and exit
    -f PATH, --file=PATH  path to pcap file
    -t TIMEOUT, --timeout=TIMEOUT
                        recv timeout in seconds (default=1)
    -i IGNORE, --ignore=IGNORE
                        ignore specified socket errors
                        54 - Connection reset by peer
                        61 - Connection refused
                        110 - Connection timed out
