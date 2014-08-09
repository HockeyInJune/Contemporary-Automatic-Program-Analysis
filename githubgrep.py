#!/usr/bin/python

import sys
import time
import urllib
import httplib
from lxml import etree

COOKIE = "user_session=h2BY_ezJVzSNTCIjW0c0WA8bQxtKuoVm8_2quytmt4VaRH0eU9ZdQ4GSXVA-l5CNVe2zpc_BpheFNfZo"
	
def main():
	totalvulns = 0
	language, functions, sources, sanitizers = None, None, None, None
	
	i = 1
	while i < len(sys.argv):
		if sys.argv[i] == "-language":
			language = sys.argv[i+1]
		if sys.argv[i] == "-functions":
			functions = sys.argv[i+1].split(',')
		if sys.argv[i] == "-sources":
			sources = sys.argv[i+1].split(',')
		if sys.argv[i] == "-sanitizers":
			sanitizers = sys.argv[i+1].split(',')
		i = i+1

	if (language == None or functions == None or sources == None or sanitizers == None):
		print("\nUsage: " + sys.argv[0] + " -language lang -functions func1[,func2,func3] -sources src1[,src2,src3] -sanitizers func1[,func2,func3]")
		print("\t-language:\t\tFile extention of language being searched.")
		print("\t-function:\t\tPotentially vulnerable function calls.")
		print("\t-sources:\t\tInput sources you expect tainted data to come from.")
		print("\t-sanitizers:\t\tSantization or validation functions calls.")
		exit(1)

	#print(language)
	#print(functions)
	#print(sources)
	#print(sanitizers)
	
	sanitizerquery = ""
	for s in sanitizers:
		sanitizerquery += " NOT " + s

	for f in functions:
		for s in sources:
			q = f + " " + s + sanitizerquery + " " + "extension:." + language
			output = search(q)
			parser = etree.XMLParser(recover=True)
			root = etree.fromstring(output, parser=parser)
			for lol in root.iter("h1"):
				if (lol.text == "Whoa there!"):
					print "Rate limited!  You should put in a valid cookie."
			for lol in root.iter("h3"):
				if (lol.text.find("Showing") != -1):
					start = lol.text.replace(',', '')[8:]
					end = start.find(" ")
					print start
					num = int(start[0:end])
				elif (lol.text.find("results") != -1):
					start = lol.text.replace(',', '')[12:]
					end = start.find(" ")
					print start
					num = int(start[0:end])
			print("\nQuery: \"" + q + "\"")
			if (num > 0):
				print(str(num) + " vulnerabilities found!")
				print("URL: \"https://github.com/search?" + urllib.urlencode({'q': q}) + "\"")
				totalvulns += num
			time.sleep(1)
	print("\nTOTAL NUMBER OF VULNERABILITIES FOUND: " + str(totalvulns))

def search(query):
	params = urllib.urlencode({"q": query, "type": "Code"})
	headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		   "Cache-Control": "max-age=0",
		   "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36",
		   "Cookie": "logged_in=no;" + COOKIE
		   }
	conn = httplib.HTTPSConnection("github.com")
	conn.request("GET", "/search" + "?" + params, None, headers)
	response = conn.getresponse()
	data = response.read()
	conn.close()
	return data;

if __name__ == '__main__':
	main()
