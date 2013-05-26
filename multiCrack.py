#!/usr/bin/env python

"""Cracks hashes with the algorthim of your choice"""

import hashlib

"""specifies what hashing algorthim to try"""
def options():
	print "(1) MD5\n(2) SHA1\n(3) SHA224\n(4) SHA256\n(5) SHA384\n(6) SHA512"
	option = raw_input("Please enter the number of the hashing algorthim you would like to crack: ")
	if ((option != "1") and (option != "2") and (option != "3") and (option != "4") and (option != "5") and (option != "6")):
		print
		options()
	else:
		return option

"""hashes a string based on what hashing algorthim the user chose"""
def hash(string, algorthim):
	"""MD5"""
	if (algorthim == "1"):
		return hashlib.md5(string).hexdigest()

	"""SHA-1"""
	if (algorthim == "2"): 
		return hashlib.sha1(string).hexdigest()

	"""SHA-224"""
	if (algorthim == "3"): 
		return hashlib.sha224(string).hexdigest()

	"""SHA-256"""
	if (algorthim == "4"): 
		return hashlib.sha256(string).hexdigest()

	"""SHA-384"""
	if (algorthim == "5"):
		return hashlib.sha384(string).hexdigest()

	"""SHA-512"""
	if (algorthim == "6"):
		return hashlib.sha512(string).hexdigest()

"""Tries to find a match for the password based on a dictionary"""
def matchPass(hashedPass, option):
	dictionary = open('dictionary.txt','r')
	for word in dictionary.readlines():
			word = word.strip('\n')
			hashedWord = hash(word, option)
			if(hashedWord == hashedPass):
				print "[+] Found Password: " + word + "\n"
				return
	print "[-] Password Not Found.\n"
	return


def main():
	option = options()

	passwords = open('passwords.txt')
	for line in passwords.readlines():
		if ":" in line:
			user = line.split(":")[0]
			hashedPass = line.split(":")[1].strip(' ').strip('\n')
			print "[*] Cracking Password For: " + user
			matchPass(hashedPass, option)

if __name__ == "__main__":
	main()