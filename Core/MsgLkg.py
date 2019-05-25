import requests
import re
import platform
from bs4 import BeautifulSoup
from selenium import webdriver
import os
from Core import vulnsum
#用来进行HTTP auth认证
from requests.auth import HTTPBasicAuth
from selenium.webdriver.common.keys import Keys
from Core import report
head = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0"}
def info():
    """
    前期交互
    :return:
    """
    try:
        r = requests.get('https://ip.cn')
        r.encoding = r.apparent_encoding
        rst = re.findall(r'Your IP</span>:\s*\d+\.\d+\.\d+\.\d+</span>', r.text)
        # print(r.text)
        if rst != []:
            rst = re.findall(r'\d+\.\d+\.\d+\.\d+', rst[0])
            print("\033[1;32;1m外网IP：" + rst[0] + "\033[0m")
    except:
        print("\033[1,31;1m[!]获取外网IP失败，请检查网络连接")
    print("\033[1;32;1m操作系统：" + platform.platform() + "\033[0m")
    inip=os.popen(
        'ip addr | grep -v inet6 | grep -v vmnet1$ | grep -v vmnet8$ | grep -v lo$ | grep inet | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"').read()
    print("\033[1;32;1m内网IP：" + inip.strip() + "\033[0m")
    try:
        report.ip(rst[0],inip,platform.platform())
    except:
        pass

def httpHead(target):
    '''
    HTTP 头信息泄漏
    :param target:目标url
    :return: 服务器banner信息
    '''
    try:
        r = requests.get(target, headers=head)
        print("\033[1;32;1m[+]发现HTTP头泄露了服务器信息：", r.headers['Server']+'\033[0m')
        vulnsum.addLow()
        report.whtml('HTTP Header Information Leakage',r.headers['Server'])
    except:
        pass

def ipLkg(target):
    '''
    IP地址泄漏
    :param target:target url
    :return: IP information
    '''
    ip=[]
    try:
        r = requests.get(target, headers=head)
        #url = re.findall(r'http://[a-zA-Z0-9./]*|https://[a-zA-Z0-9./]*', r.text)
        fip = re.findall(
            r'(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)',
            r.text)
        if fip !=[]:
            vulnsum.addLow()
            for i in range(len(fip)):
                print("\033[1;32;1m[+]发现源码中泄露了IP地址：", ".".join(fip[i])+'\033[0m')
                ip.append(".".join(fip[i]))
            report.whtml('Source Leakage IP Address',ip)
    except:
        pass

def robots(target):
    '''
    robots文件泄漏敏感信息
    :param target: target url
    :return: 0
    '''
    try:
        r = requests.get(target + "/robots.txt", headers=head)
        if 'admin'in r.text:
            print("\033[1;32;1m[+]发现目标robots.txt泄露了admin目录！\033[0m")
            vulnsum.addLow()
            report.whtml('Robots.txt File Information Leakage',re.findall(r'admin',r.text))
        if 'management' in r.text:
            print("\033[1;32;1m[+]发现目标robots.txt泄露了manage目录！\033[0m")
            vulnsum.addLow()
            report.whtml('Robots.txt File Information Leakage', re.findall(r'management', r.text))
            if 'manage' in r.text:
                print("\033[1;32;1m[+]发现目标robots.txt泄露了manage目录！\033[0m")
                vulnsum.addLow()
                report.whtml('Robots.txt File Information Leakage', re.findall(r'manage', r.text))
    except:
        pass
    # url=re.findall(r'http://[a-zA-Z0-9./]*|https://[a-zA-Z0-9./]*',r.text)
    # print(url)
def options(target):
    '''
    HTTP OPTIONS Method Detect
    :param target: target url
    :return:0
    '''
    try:
        r = requests.options(target, headers=head)
        print("\033[1;32;1m[+]发现服务器启用了OPTIONS方法：", r.headers['Allow']+'\033[0m')
        vulnsum.addLow()
        report.whtml('HTTP OPTIONS method is active',r.headers['Allow'])
    except:
        pass
def mwcs(target):
    '''
    明文传输检测
    :param target:
    :return:
    '''
    profile = webdriver.FirefoxProfile()
    profile.accept_untrusted_certs = True
    opt = webdriver.FirefoxOptions()
    opt.add_argument('--headless')
    browser = webdriver.Firefox(firefox_profile=profile, options=opt)

    try:


        browser.get(target)
        sour = browser.page_source
        # print(sour)
        soup = BeautifulSoup(sour, "html.parser")
        pwd = soup('input', type="password")
        if pwd==[]:
            return 0
        da = os.popen("./bin/snf.py")
        ipt = soup('input')
        for i in range(len(ipt)):
            if "用户名" in str(ipt[i]) or "User" in str(ipt[i]) or "user" in str(ipt[i]) or "loginID" in str(ipt[i]):
                if pwd[0] != ipt[i]:
                    pwd.append(ipt[i])
        for i in range(len(pwd)):
            #print(pwd[i])
            pwd[i] = re.findall(r'name="[a-zA-Z0-9_=+\-/]+"', str(pwd[i]))[0][6:-1]
    except:
        print("\033[1;31;1m[!]无法获取登录变量！！！\033[0m")
        return 0


    browser.refresh()

    for i in pwd:
        browser.find_element_by_name(i).send_keys("Admin123")
    try:
        browser.find_element_by_name(pwd[0]).send_keys(Keys.ENTER)
    except IndexError:
        pass
    browser.close()
    da.read()
    da = open('/tmp/snf.txt','r').read()
    try:
        if pwd[0]+"="+"Admin123" in da:
            print("\033[1;32;1m[+]存在密码明文传输漏洞！\033[0m")
            vulnsum.addMedium()
            report.whtml('User name and password plaintext transmission',da)
        os.system('rm /tmp/snf.txt')
    except:
        pass
    #print(da)

def httpauth(target,userfile='./wordlists/user.txt',passwdfile='./wordlists/passwd.txt'):
    '''
    HTTP 认证缺陷检测
    :param target:
    :param user: 用户名
    :param passwd: 密码
    :return: 0
    '''
    up=[]
    userfile=open(userfile,'r').read().split('\n')
    passwdfile=open(passwdfile,'r').read().split('\n')
    for i in userfile:
        for j in passwdfile:
            try:
                r = requests.get(target)
                if r.status_code == 200:
                    return 0
                r = requests.get(target, auth=HTTPBasicAuth(i, j))
                if r.status_code == 200:
                    print("\033[1;32;1m[+]目标存在HTTP认证弱密钥漏洞！user:{},password:{}\033[0m".format(i, j))
                    vulnsum.addMedium()
                    up.append('user:'+i+'password:'+j)
            except:
                pass
    if up !=[]:
        report.whtml('HTTP Authentication Defects',up)
