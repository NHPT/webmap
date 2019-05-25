import webbrowser
from Core import vulnsum
from conf.webmapargs import url
import datetime
f=open('./report/index.html','w')
f.write('<!DOCTYPE html>\n')
#f.write('<header style="text-align: center">\n')
#标题及样式
f.write('<html>\n<head>\n<meta charset="utf-8">\n<title>Webmap Penetration Testing Report</title>\n')
f.write('<meta name="viewport" content="width=device-width, initial-scale=1">\n<link rel="stylesheet" type="text/css" href="css/kube.min.css" />\n<link rel="stylesheet" type="text/css" href="css/master.css" />\n</head>\n<body>\n')
f.write('<div id="page">\n<h2 class="title" style="text-align: center">Webmap Penetration Testing Report</h2>\n')
f.write('<h3>Target: '+url+'</h3>\n')
f.write('<h3>Report at '+str(datetime.datetime.now())+'CST</h3>\n')
f.write('<hr/>')
#第一部分渗透测试使用的工具
def init():
    f.write('<h4>Tools used in this penetration testing</h4>\n')
    f.write('<table class="width-100 hovered" no-repeat center;">\n')
    f.write('<thead>\n<tr>\n<th>Tools</th>\n<th>Version</th>\n</tr>\n</thead>\n')
    f.write('<tr>\n<td>Nmap</td>\n<td>7.7</td>\n</tr>\n')
    f.write('<tr>\n<td>dirb</td>\n<td>2.22</td>\n</tr>\n')
    f.write('<tr>\n<td>hydra</td>\n<td>8.9</td>\n</tr>\n')
    f.write('<tr>\n<td>Nikto</td>\n<td>2.1.6</td>\n</tr>\n')
    f.write('<tr>\n<td>wapiti</td>\n<td>3.0.1</td>\n</tr>\n')
    f.write('<tr>\n<td>Metasploit</td>\n<td>5.0.16</td>\n</tr>\n')
    f.write('</table>\n<hr/>\n')

#第二部分渗透测试操作系统信息
def ip(exIP,inIP,osystem):
    f.write('<h4>Personnel information for penetration testing</h4>\n')
    f.write('<table class="width-100 hovered" no-repeat center;">\n')
    f.write('<tr>\n<td class="small">Extranet IP：</td><td class="small .text-centered">'+str(exIP)+'</td></tr>\n')
    f.write('<tr>\n<td class="small">Intranet IP：</td><td class="small .text-centered">'+str(inIP)+'</td></tr>\n')
    f.write('<tr>\n<td class="small">Operating System：</td><td class="small .text-centered">'+str(osystem)+'</td></tr>\n')
    f.write('</table>\n<hr/>\n')
#第三部分Wapiti测试的漏洞信息
def tbody(html):
    f.write('<h4>Wapiti Found vulnerablities</h4>\n')
    f.write('<table class="width-100 hovered" no-repeat center;">\n')
    f.write('<thead>\n<tr>\n<th>Category</th>\n<th>Number of vulnerabilities found</th>\n</tr>\n</thead>\n')
    f.write(str(html)+'\n')
    f.write('</table>\n<hr/>\n')

def wdiv(html):
    f.write(str(html)+'\n')

#第四部分写入Nmap扫描结果
def wnmap(part,c1,c2,c3,data):
    f.write('<h4>' + str(part) + '</h4>\n')
    f.write('<table class="width-100 hovered" no-repeat center;">\n')
    f.write('<thead>\n<tr>\n<th>'+str(c1)+'</th>\n<th>'+str(c2)+'</th>\n<th>'+str(c3)+'</th>\n</tr>\n</thead>\n')

    for i in data:
        i = i.split(' ')
        while '' in i:
            i.remove('')
        f.write('<tr><td>'+i[0]+'</td>\n<td>'+i[1]+'</td>\n<td>'+i[2]+'</td>\n</tr>\n')
    f.write('</table>\n<hr/>\n')

#第五部分漏洞分类及数量写入
def wvuln():
    f.write('<h4>Vulnerablities Sum</h4>\n')
    f.write('<table class="width-100 hovered" no-repeat center;">\n')
    f.write('<tr style="color: red">\n<td class="small" style="color: red">High Vulnerabilites Sum：</td><td class="small .text-centered">' + str(vulnsum.HIGH) + '</td></tr>\n')
    f.write('<tr style="color: orange">\n<td class="small" style="color: orange">Medium Vulnerabilites Sum：</td><td class="small .text-centered">' + str(vulnsum.MEDIUM) + '</td></tr>\n')
    f.write('<tr style="color: seagreen">\n<td class="small" style="color: seagreen">Low Vulnerabilites Sum：</td><td class="small .text-centered">' + str(vulnsum.LOW) + '</td></tr>\n')
    f.write('</table>\n<hr/>\n')

#第六部分通用漏洞写入
def whtml(part,html):
    f.write('<h4>'+str(part)+'</h4>\n')
    if type(html)==str:
        f.write('<p>'+str(html)+'</p>\n')
    if type(html)==list:
        for i in html:
            f.write('<p>'+str(i)+'</p>\n')

#第七部分测试评级写入
def ptrst():
    f.write('<h4>Penetration Testing Result</h4>\n')
    if vulnsum.HIGH>0:
        f.write('<h5 style="color: red">Comprehensive evaluation of the system as a remote unsafe system</h5>\n')
    elif vulnsum.MEDIUM>2:
        f.write('<h5 style="color: orange">Comprehensive evaluation of the system as a remote general security system</h5>\n')
    else:
        f.write('<h5 style="color: seagreen">Comprehensive evaluation of the system as a remote security system</h5>\n')

def htmlend():
    f.write('</body>\n</html>')
    f.close()
def browser():
    webbrowser.open("./report/index.html")
