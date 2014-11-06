# ** Original author: Will Metcalf (Emergingthreats). The original comments for this file are below **
# https://github.com/EmergingThreats/fiddler2pcap

#!/usr/bin/python
# This is probably useful to like 4 people. Some of the packet inection stuff is taken from rule2alert https://code.google.com/p/rule2alert/ which is GPLv2 so I guess this is well.
# This ultra alpha if everything isn't right it will fall on its face and probably cause you to run away from it screaming into the night

#TODO:
# 1. Optionally trim request line to start with uripath 
# 2. Better error checking... Well any error checking really.

################################

# Author (saz2pcap): Nick Griffin (Websense)
#
# Updates include:
# 1. Added linktype, ethernet headers & IP version 4 to packets for better compatibility (ie. you can now import back into Fiddler)
# 2. Some error checking, still needs more though.
# 3. Windows compatibility (reading files in binary mode)

import random
import os
import sys
import re
import zipfile
import tempfile
import shutil
from xml.dom.minidom import parse, parseString
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.utils import PcapWriter
from scapy.all import *
import glob
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-i", dest="input_target", type="string", help="path to fiddler raw directory we will read from glob format or path to saz file with --saz option")
parser.add_option("-o", dest="output_pcap", type="string", help="path to output PCAP file")
parser.add_option("--src", dest="srcip", type="string", help="src ip address to use if not specified we read it from the XML")
parser.add_option("--dst", dest="dstip", type="string", help="dst ip address to use if not specified we read it from the XML")
parser.add_option("--dproxy", dest="dproxy", action="store_true", default=False, help="attempt to unproxify the pcap")
parser.add_option("--saz", dest="input_is_saz", action="store_true", default=False, help="input is saz instead of raw directory")

src = None
dst = None

def validate_ip(ip):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",ip) != None:
        return True
    else:
        print "The ip address you provides is invalid %s exiting" % (ip)
        sys.exit(-1)


(options, args) = parser.parse_args()

print "\n* Input: "  + str(options.input_target)

if options == []:
   print parser.print_help()
   sys.exit(-1)
if not options.input_target or options.input_target == "":
   print parser.print_help()
   sys.exit(-1)
if not options.output_pcap or options.output_pcap == "":
   print parser.print_help()
   sys.exit(-1)
if options.srcip and validate_ip(options.srcip):
   src = options.srcip 
if options.dstip and validate_ip(options.dstip):
   dst = options.dstip

#Open our packet dumper
pktdump = PcapWriter(options.output_pcap, sync=True)
pktdump.linktype = 1 # Ethernet

def build_handshake(src,dst,sport,dport):
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport

#    We don't deal with session wrap around so lets make the range smaller for now
#    client_isn = random.randint(1024, (2**32)-1)
#    server_isn = random.randint(1024, (2**32)-1)
    client_isn = random.randint(1024, 10000)
    server_isn = random.randint(1024, 10000)
    syn = Ether(src="00:01:02:03:04:05",dst="06:07:08:09:0a:0b",type=0x800)/IP(version=4L,src=ipsrc, dst=ipdst)/TCP(flags="S", sport=portsrc, dport=portdst, seq=client_isn)
    synack = Ether(dst="00:01:02:03:04:05",src="06:07:08:09:0a:0b",type=0x800)/IP(version=4L,src=ipdst, dst=ipsrc)/TCP(flags="SA", sport=portdst, dport=portsrc, seq=server_isn, ack=syn.seq+1)
    ack = Ether(src="00:01:02:03:04:05",dst="06:07:08:09:0a:0b",type=0x800)/IP(version=4L,src=ipsrc, dst=ipdst)/TCP(flags="A", sport=portsrc, dport=portdst, seq=syn.seq+1, ack=synack.seq+1)
    pktdump.write(syn)
    pktdump.write(synack)
    pktdump.write(ack)
    return(ack.seq,ack.ack)

def build_finshake(src,dst,sport,dport,seq,ack):
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport
    finAck = Ether(src="00:01:02:03:04:05",dst="06:07:08:09:0a:0b",type=0x800)/IP(version=4L,src=ipsrc, dst=ipdst)/TCP(flags="FA", sport=sport, dport=dport, seq=seq, ack=ack)
    finalAck = Ether(dst="00:01:02:03:04:05",src="06:07:08:09:0a:0b",type=0x800)/IP(version=4L,src=ipdst, dst=ipsrc)/TCP(flags="A", sport=dport, dport=sport, seq=finAck.ack, ack=finAck.seq+1)
    pktdump.write(finAck)
    pktdump.write(finalAck)

#http://stackoverflow.com/questions/18854620/whats-the-best-way-to-split-a-string-into-fixed-length-chunks-and-work-with-the
def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def make_poop(src,dst,sport,dport,seq,ack,payload):
    segments = [] 
    if len(payload) > 1460:
        segments=chunkstring(payload,1460)
    else:
        segments.append(payload)    
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport
    for segment in segments:
        p = Ether(src="00:01:02:03:04:05",dst="06:07:08:09:0a:0b",type=0x800)/IP(version=4L,src=ipsrc, dst=ipdst)/TCP(flags="PA", sport=sport, dport=dport, seq=seq, ack=ack)/segment
        returnAck = Ether(dst="00:01:02:03:04:05",src="06:07:08:09:0a:0b",type=0x800)/IP(version=4L,src=ipdst, dst=ipsrc)/TCP(flags="A", sport=dport, dport=sport, seq=p.ack, ack=(p.seq + len(p[Raw])))
        seq = returnAck.ack
        ack = returnAck.seq
        pktdump.write(p)
        pktdump.write(returnAck)
    return(returnAck.seq,returnAck.ack)

print "* Parsing and outputting...\n"

if options.input_is_saz and os.path.isfile(options.input_target):
    try:
        options.tmpdir = tempfile.mkdtemp()
    except:
        print "failed to create temp directory for saz extraction"
        sys.exit(-1)
    try:
        z = zipfile.ZipFile(options.input_target,"r")
    except:
        print "failed to open saz file %s" % (options.input_target)
        sys.exit(-1)
    try:
       z.extractall(options.tmpdir)
       z.close()
    except:
       print "failed to extract saz file %s to %s" % (options.input_target, options.tmpdir)
       sys.exit(-1)
    if os.path.isdir("%s/raw/" % (options.tmpdir)):
       options.fiddler_raw_dir = "%s/raw/" % (options.tmpdir)
    else:
       print "failed to find raw directory in extracted files %s/raw (must remove tmp file yourself)" % (options.tmpdir)
       sys.exit(-1)
    
elif os.path.isdir(options.input_target):
    options.fiddler_raw_dir = options.input_target
    options.tmpdir = None

if os.path.isdir(options.fiddler_raw_dir):
    m_file_list=glob.glob("%s/%s" % (options.fiddler_raw_dir,"*_m.xml")) 
    m_file_list.sort()
    for xml_file in m_file_list:
        dst=None
        sport=""
        dport=80
        dom = parse(xml_file)
        m = re.match(r"^(?P<fid>\d+)_m\.xml",os.path.basename(xml_file))
        if m:
            fid = m.group("fid")
        else:
            print("failed to get fiddler id tag")
            sys.exit(-1)
        
        xmlTags = dom.getElementsByTagName('SessionFlag')
        for xmlTag in xmlTags:
            xmlTag = xmlTag.toxml()
            m = re.match(r"\<SessionFlag N=\x22x-(?:client(?:ip\x22 V=\x22[^\x22]*?(?P<clientip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|port\x22 V=\x22(?P<sport>\d+))|hostip\x22 V=\x22[^\x22]*?(?P<hostip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\x22",xmlTag)
            if m and m.group("sport"):
                sport = int(m.group("sport"))
                #sport = random.randint(1024, 65535)
            elif m and m.group("clientip") and src == None:
                src = m.group("clientip")
            elif m and m.group("hostip") and dst == None:
                dst = m.group("hostip")
        
        req = open(options.fiddler_raw_dir + fid + "_c.txt", "rb").read()
        m=re.match(r"^[^\r\n\s]+\s+(?P<host_and_port>https?:\/\/(?P<hostname>[^\/\r\n:]+)(\:(?P<dport>\d{1,5}))?)\/",req)
        
        # Not an HTTP stream
        if m == None:
            continue
        
        hostname = m.group("hostname")
        if m and options.dproxy and m.group("host_and_port"):
            req = req.replace(m.group("host_and_port"),"",1)
            if m.group("dport") and int(m.group("dport")) <= 65535:
                dport = int(m.group("dport"))
        
        # ** Initiate superl33b checks **
        # Give it an IP if we've got one from the URL, duh.
        # No src IP? Well that sucks, let's give it localhost
        # Dat ugly src port 0? Gah, let's generate a new one for this stream
        # [TODO: Ask Telerik to make Fiddler SAZ XML files have more metadata so I don't have to hack up shit like this =D]
        if dst == None:
            m = re.match(r"^(\d{1,3}\.){3}\d{1,3}$",hostname)
            if m:
                dst = hostname
            else:
                dst = "0.0.0.0"
        if src == None:
            src = "127.0.0.1"
        if sport == 0:
            sport = random.randrange(1000,9999)
        
        resp = open(options.fiddler_raw_dir + fid + "_s.txt", "rb").read()
        print "src: %s dst: %s sport: %s dport: %s host: %s" % (src, dst, sport, dport, hostname)
        (seq,ack)=build_handshake(src,dst,sport,dport)
        (seq,ack)=make_poop(src,dst,sport,dport,seq,ack,req)
        (seq,ack)=make_poop(dst,src,dport,sport,seq,ack,resp)
        build_finshake(src,dst,sport,dport,seq,ack)
   
    if options.tmpdir: 
        try:
            shutil.rmtree(options.tmpdir)
        except:
            print "failed to clean up tmpdir %s you will have to do it" % (options.tmpdir)
else:
    print "fiddler raw dir specified:%s dos not exist" % (options.fiddler_raw_dir)
    sys.exit(-1)

pktdump.close()
