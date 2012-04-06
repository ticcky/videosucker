#!/usr/bin/env python
"""
Video Sucker - pcap file video extractor

This is a tool that sucks the videos out of your .pcap files.
It reconstructs the original TCP streams, processes HTTP messages,
and looks for video transfers in them. The videos are dumped into
a chosen folder

For research and educational purposes ONLY."""

__author__ = "Lukas Zilka"
__license__ = "GPL"
__version__ = 0.9
__email__ = "lukas@zilka.me"
__status__ = "Development"

import os
import re
import dpkt
import sys
import socket
import StringIO
from collections import defaultdict
from httplib import HTTPResponse

class TCPStream:
    open_time = None
    synced = False
    sync_seq = None
    fined = False
    length = 0
    seqs = None

    def __init__(self, conn):
        self.conn = conn
        self.data = StringIO.StringIO()
        self.data_buff = []
        self.seqs = []

    def process_new_data(self, tcp):
        if self.sync_seq == None:
            self.data_buff += [tcp]
        else:
            self.write_new_data(tcp)

    def write_new_data(self, tcp):
        self.fill_interval(tcp.seq - 1 - self.sync_seq, tcp.seq - 1 - self.sync_seq + len(tcp.data))
        self.data.seek(tcp.seq - 1 - self.sync_seq)
        self.data.write(tcp.data)
        self.length += len(tcp.data)

    def fill_interval(self, istart, iend):
        for seq in self.seqs:
            if istart >= seq[0] and istart <= seq[1]:
                self.seqs.remove(seq)
                self.fill_interval(seq[0], max(seq[1], iend))
                break
            elif iend >= seq[0] and iend <= seq[1]:
                self.seqs.remove(seq)
                self.fill_interval(min(istart, seq[0]), seq[1])
                break
        else:            
            self.seqs += [(istart, iend)]
                

    def check_seq(self):
        f = StringIO.StringIO()
        for seq in self.seqs:
            f.seek(seq[0])
            f.write('x' * (seq[1] - seq[0]))

        f.seek(0)
        cont = f.read()
        
        res = cont.find('\x00')
        if res != -1:
            return False
        else:
            return True
        #import pdb; pdb.set_trace()

    def get_data(self):
        self.data.seek(0)
        return self.data

def conn_invar(conn):
    res = list(conn)
    res.sort()
    return tuple(res)
    
class TCPStreamReassembler:
    def __init__(self, packet_reader, callback):
        self.packet_reader = packet_reader
        self.callback = callback

    def process_packet(self, t, pkt):
        ether = dpkt.ethernet.Ethernet(pkt)
        if ether.type != dpkt.ethernet.ETH_TYPE_IP: 
            return
        ip = ether.data
        if ip.p != dpkt.ip.IP_PROTO_TCP: 
            return

        tcp = ip.data

        conn = (ip.src, tcp.sport, ip.dst, tcp.dport)
        ts = self.streams.get(conn, TCPStream(conn))
        self.streams[conn] = ts
        
        if (tcp.flags & dpkt.tcp.TH_SYN) != 0:
            ts.open_time = t
            ts.synced = True
            ts.sync_seq = tcp.seq
            
        if (tcp.flags & dpkt.tcp.TH_FIN) != 0:
            ts.fined = True
            #del self.streams[conn]

            #print ts, conn, ts.fined, ts.seqs

        ts.process_new_data(tcp)

        self.callback(ts, t)


    def process(self):
        self.streams = {}

        packet_cntr = 0
        for ts, data in self.packet_reader:
            packet_cntr += 1
            try:
                self.process_packet(ts, data)
            except Exception, e:
                print >>sys.stderr, 'Error processing packet #%d:' % packet_cntr, str(e)

class HttpMessage:
    timestamp = None
    cmd = None
    header = None
    data = None
    tcp_stream = None
    timestamp = None
            
class HttpExtractor:
    __proto = "HTTP/"
    __methods = ["GET", "POST"]
    
    def __init__(self, packet_reader, callback):
        self.tcp_reasm = TCPStreamReassembler(packet_reader, self.process_new_data)
        self.callback = callback
        self.cntr = 0

    def process_new_data(self, ts, t):
        if ts.fined:
            if not ts.check_seq():
                return
            data = ts.get_data()
            #f = open("out/stream-%d-%s-%d-%s-%d" % (self.cntr, socket.inet_ntoa(ts.conn[0]), ts.conn[1], socket.inet_ntoa(ts.conn[2]), ts.conn[3]), "w")
            #f.write(data.read())
            #f.close()
            data.seek(0)
            while True:
                ln = data.readline()
                if len(ln) == 0:
                    break
                headers = None
                if ln.startswith(self.__proto) or any([True for m in self.__methods if ln.startswith(m)]):
                    headers = dpkt.http.parse_headers(data)
                
                if headers is None:
                    continue
                
                content_length = int(headers.get('content-length', 0))
                content = data.read(content_length)
            
                self.cntr += 1
                msg = HttpMessage()
                msg.cmd = ln
                msg.header = headers
                msg.data = StringIO.StringIO(content)
                msg.tcp_stream = ts
                msg.timestamp = t
                
                self.callback(msg)                

    def process(self):
        self.tcp_reasm.process()

class Video:
    container = "flv"

    def __init__(self):
        self.data = StringIO.StringIO()

    def process_new_data(self, msg):
        if type(msg) == str:
            self.data.write(msg)
        else:
            self.data.write(msg.data.read())

    def get_content(self):
        self.data.seek(0)
        return self.data.read()

def conn_rev(conn):
    return (conn[2], conn[3], conn[0], conn[1])
    
class VideoSucker:
    def suck(self, packet_reader):
        self.videos = []
        self.conn_tracker = {} # serves to track video id's over a particular connection
        self.conn_name_tracker = []
        
        http_e = HttpExtractor(packet_reader, self.process_new_msg)
        http_e.process()

        #self.merge_youtube_videos()


        return self.videos

    def process_new_msg(self, msg):
        patt = re.compile("upn=(?P<id>[^&]*)&")
        video_id_match = patt.search(msg.cmd)
        
        if video_id_match != None:
            video_id = video_id_match.group(1)
            self.conn_name_tracker += [(msg.timestamp, video_id)]
            orig_video = self.conn_tracker.get(conn_rev(msg.tcp_stream.conn), None)
            
            if orig_video is not None:
                orig_video.id = video_id
            
            self.conn_tracker[msg.tcp_stream.conn] = video_id
            #print 'setting', msg.tcp_stream.conn, video_id

        if 'video' in msg.header.get('content-type', ''):
            conn = msg.tcp_stream.conn
            video = self.conn_tracker.get(conn, None)
            if video is None:
                video = Video()
                video.id = None
                self.videos += [video]
                self.conn_tracker[conn] = video

            video.process_new_data(msg)

    def merge_youtube_videos(self):
        groups = defaultdict(list)
        for video in self.videos:
            groups[video.id] += [video]

        videos = []
        for group in groups.values():
            first_video = group[0]
            for video in group[1:]:
                content = video.get_content()
                data_start = 0
                for i in content:
                    if i == '\x08' or i == '\x08':
                        break
                    data_start += 1
                print data_start, ord(content[data_start])
                first_video.process_new_data(content[data_start:])
            videos += [first_video]

        self.videos = videos
        

def fix_flv(content):
    """This is aimed to make the extracted video files playable. For some reason
    youtube sends the files without the initial 13 bytes of FLV header. This should
    remediate this and allow for replaying saved videos by normal media players."""

    # to prevent adding the header to file that does not make senese, just check the first
    # two bytes
    if content[0:2] == "\x12\x00":
        return "FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00" + content
    else:
        return content


if __name__ == "__main__":
    pcap_file = sys.argv[1]
    outdir = sys.argv[2]
    
    packet_reader = dpkt.pcap.Reader(open(pcap_file, "rb"))

    vs = VideoSucker()
    videos = vs.suck(packet_reader)

    for i, video in enumerate(videos):
        print >>sys.stderr, "Saving video", video.id
        f = open(os.path.join(outdir, "%d-%s.%s" % (i, video.id, video.container)), "w")
        content = video.get_content()
        content = fix_flv(content)
        f.write(content)
        f.close()
        

