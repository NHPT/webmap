#!/usr/bin/python3
import platform
from colorama import Fore, Style,init
if 'Windows' in platform.system():
    init(wrap=True)
else:
    init(autoreset=False)
banner=[]
banner.append('__      _____| |__ ')
banner.append(' _ __ ___   __ _ _ __  ')
banner.append("\ \ /\ / / _ \ '_ \\")
banner.append("| '_ ` _ \ / _` | '_ \ ")
banner.append(" \ V  V /  __/ |_) ")
banner.append("| | | | | | (_| | |_) |")
banner.append("  \_/\_/ \___|_.__/")
banner.append('''|_| |_| |_|\__,_| .__/ 
                                   | |    
                                   |_|    ''')

for i in range(0,7,2):
    print(Fore.RED + banner[i]+Fore.GREEN + banner[i+1])
print(Style.RESET_ALL)
print('Webmap.py 基于Python3的自动化渗透测试工具')
