import sys
import requests
import bs4
import Database
import threading

from urlparse import urlparse, urljoin

from clase_database.database import Database

def checkearMetodo(url, names, metodo):
    form_data= {}
    # aca cargar previamente los payloads maliciosos
    for name in names:
        form_data[name] = '<script>alert("XssPrueba")</script>'
    
    if metodo == "GET":
        res = requests.get(url, params=form_data)
    elif metodo == "POST":
        res = requests.get(url, data=form_data)
   
    res.raise_for_status()
    print "Ya envie la request"

    # Buscamos si es vulnerable.
    es_vulnerable = False
    soup = bs4.BeautifulSoup(res.text,"html.parser")
    try: 
        scripts = soup.select('script')
        for script in scripts:
            if 'alert("XssPrueba")' in script:
                es_vulnerable = True
        return es_vulnerable
                    
    except:

        return es_vulnerable


def checkearXSS(url, database, *args):
    xss_encontrado = False
    hayLock = False

    if len(args) > 0:
        hayLock = True
        lock = args[0]

    res = requests.get(url)
    res.raise_for_status()
    soup = bs4.BeautifulSoup(res.text,"html.parser")
    forms = soup.select('form')

    for form in forms:
        inputs = form.select('input')
        names = []
        for inpt in inputs:
            name = inpt.get('name')
            if name != None:
                names.append(name)    
        metodo = form.get('method')
        if checkearMetodo(url,names,metodo):
            xss_encontrado = True
            if hayLock:
                lock.acquire()
                database.escribir(url,names,metodo)
                lock.release()
            else:
                database.escribir(url,names,metodo)

    # if checkearMetodo(url,,"GET"):
    #     lock.acquire()
    #     database.escribir(url,names,"GET")
    #     lock.release()
    return xss_encontrado


lock = threading.Lock()
database = Database('xss-game')
url = "http://google-gruyere.appspot.com/339000360975/"
