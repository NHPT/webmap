#####################################################################

工具名称：
	webmap

#####################################################################

工具简介：
	本工具是基于Python3.7而开发的自动化渗透测试工具，可以对单个网站和服务器主机进行一次简单的渗透测试，并输出测试报告。

#####################################################################

环境依赖：
	本工具适用于Kali Linux 2019.1操作系统，其他Linux操作系统需要安装有Nmap、Nikto、Dirb、Wapiti、Metasploit工具，同时需要Python3.7运行环境、selenium模块、requests模块、BeautifulSoup模块和scapy模块，以及Firefox驱动程序的支持。

#####################################################################

部署步骤：
	1、安装Python3.7 第三方模块selenium：pip3 install selenium
	2、下载Firefox浏览器对应的驱动程序，如：https://github.com/mozilla/geckodriver/releases/download/v0.23.0/geckodriver-v0.23.0-linux64.tar.gz，然后解压：tar -zxvf geckodriver-v0.23.0-linux64.tar.gz，接着将解压后的程序移动到“/usr/local/bin/”目录下：mv geckodriver /usr/local/bin/

#####################################################################

Tool name: 
webmap

#####################################################################

Tool Description: 
	This tool is an automated penetration testing tool based on Python 3.7. It can conduct a simple penetration test for a single website and server host, and output test reports.

#####################################################################

Environmental dependence:

This tool is suitable for Kali Linux 2019.1 operating system. Other Linux operating systems need Nmap, Nikto, Dirb, Wapiti, Metasploit tools, Python 3.7 operating environment, selenium module and Firefox driver support.

#####################################################################

Deployment steps:

1. Install Python 3.7 third-party module selenium：pip3 install selenium
2. Download the driver for Firefox browser, such as: https://github.com/mozilla/geckodriver/releases/download/v0.23.0/geckodriver-v0.23.0-linux64.tar.gz, then decompress: tar-zxvf geckodriver-v0.23.0-linux64.tar.gz, and move the decompressed program to “/usr/local/bin/”directory:mv geckodriver /usr/local/bin/

