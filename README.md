saz2pcap
============

Forked from <a href="https://github.com/EmergingThreats/fiddler2pcap">fiddler2pcap</a>, original author is <strong>Will Metcalf</strong> (Emergingthreats). This version contains many improvements, please see the source code for more information.

fiddler output (.saz) to pcap (.pcap)

Example saz file as input
./fiddler2pcap.py -i /home/blah/Downloads/Infinity_2014-03-17.saz -o infinity.pcap --saz

Example raw directory as input
./saz2pcap.py -i /tmp/tmpaPRU3T/raw/ -o infinity.pcap

Help
Usage: saz2pcap.py [options]

Options:
  -h, --help       show this help message and exit
  -i INPUT_TARGET  path to fiddler raw directory we will read from glob format
                   or path to saz file with --saz option
  -o OUTPUT_PCAP   path to output PCAP file
  --src=SRCIP      src ip address to use if not specified we read it from the
                   XML
  --dst=DSTIP      dst ip address to use if not specified we read it from the
                   XML
  --dproxy         attempt to unproxify the pcap
  --saz            input is saz instead of raw directory
None
