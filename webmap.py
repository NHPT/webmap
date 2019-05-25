#!/usr/bin/python3
from conf import banner
from conf import webmapargs
from Core import MsgLkg
from Core.scanandverif import *
from Core import report
import datetime
#url="http://www.btoa.cn/m/login.php"

st=datetime.datetime.now()
print("Starting webmap at "+str(st)+' CST')
report.init()
MsgLkg.info()
MsgLkg.httpHead(webmapargs.url)
MsgLkg.ipLkg(webmapargs.url)
MsgLkg.options(webmapargs.url)
MsgLkg.robots(webmapargs.url)
MsgLkg.mwcs(webmapargs.url)
MsgLkg.httpauth(webmapargs.url)
nikto(webmapargs.url)
py_nmap(webmapargs.url,webmapargs.args.F,webmapargs.args.user,webmapargs.args.passwd,webmapargs.args.userfile,webmapargs.args.passwdfile)

wapiti(webmapargs.url)
#t="http://math.tust.edu.cn/phpmyadmin/export.php"

et=datetime.datetime.now()
print("测试用时：",et-st)
vulnsum.vulnprint()
report.ptrst()
report.htmlend()
report.browser()