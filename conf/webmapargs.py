import argparse
import os
parser=argparse.ArgumentParser(epilog="Example: webmap -u http://www.example.com")
parser.add_argument("-u","--url",type=str,help="目标url，如：http://example.com")
parser.add_argument("-l","--user",type=str,default=None,help="指定枚举的用户名")
parser.add_argument("-p","--passwd",type=str,default=None,help="指定枚举的密码")
parser.add_argument("-L","--userfile",type=str,default='./wordlists/user.txt',help="用户名字典文件")
parser.add_argument("-P","--passwdfile",type=str,default='./wordlists/passwd.txt',help="密码字典文件")
parser.add_argument("-F",action='store_true',default=False,help="启用全端口扫描")
args=parser.parse_args()

if not args.url:
    parser.print_help()
    os._exit(0)
if args.url:
    url=args.url
