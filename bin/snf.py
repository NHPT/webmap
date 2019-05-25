#!/usr/bin/python3
from scapy.all import *
import os
def get_postdata(packet):
    '''
    处理HTTP数据包，返回HTTPRequest
    :param packet: sniff嗅探到的POST请求包
    :return: HTTP Request
    '''
    for p in packet:
        #print(p.payload.payload.dport)
        hex_raw = p.payload.payload.payload
        #print(type(hex_raw))
    try:
        hex_raw =eval(str(hex_raw)).decode()
        f = open('/tmp/snf.txt', 'w')
        f.write(hex_raw)
        f.close()
        #print(hex_raw)
        os._exit(0)
    except:
        pass

    #print(hex_raw.decode())
'''
    f = open('snf.txt', 'w')
    f.write(hex_raw.decode())
    f.close()
    #return hex_raw
'''

# and dst host 61.135.169.121

pkt = sniff(lfilter=lambda x:'POST' in str(x),filter="proto TCP and(dst port 80 or dst port 443)",prn=get_postdata)


#print(pkt,type(pkt))


import scapy_http.http
#p=sniff(count=1,lfilter= lambda x:x.haslayer(scapy_http.http.HTTPRequest),filter="dst host www.baidu.com")
