# Python 2.7.11
import sys
import requests
import bs4
import threading

from urlparse import urlparse, urljoin
from clase_database.database import Database

def requestAceptada(url, metodo, *args):
    hayParams = False
    if len(args) > 0:
        hayParams = True
        form_data = args[0]
    
    try:
        if metodo == "get":
            if hayParams:
                res = requests.get(url, params=form_data)
            else:
                res = requests.get(url)
            return res
        elif metodo == "post":
            if hayParams:
                res = requests.post(url, data=form_data)
            else:
                res = requests.post(url)  
            return res
        else:
            return None
    except:
        return None  


def checkearMetodo(url, names, metodo):
    es_vulnerable = False
    form_data= {}
    codigo_a_inyectar = '<script>alert("XssPrueba")</script>'
    for name in names:
        form_data[name] = codigo_a_inyectar

    if len(names) == 0:
        url = url+codigo_a_inyectar

    res = requestAceptada(url, metodo, form_data)
    if res == None:
        return False 
    html_text = bs4.BeautifulSoup(res.text,"html.parser")
    try: 
        scripts = html_text.select('script')
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

    res = requestAceptada(url, "get")
    if res == None:
        return False 

    html_text = bs4.BeautifulSoup(res.text,"html.parser")
    forms = html_text.select('form')

    for form in forms:
        inputs = form.select('input')
        names = []
        for inpt in inputs:
            name = inpt.get('name')
            if name != None:
                names.append(name)    
        metodo = form.get('method').lower()
        if checkearMetodo(url,names,metodo):
            print "Vulnerabilidad encontrada en "+url+" guardando en db"
            xss_encontrado = True
            if hayLock:
                lock.acquire()
                database.escribir(url,names,metodo)
                lock.release()
            else:
                database.escribir(url,names,metodo)

    if checkearMetodo(url,[],"get"):
        print "Vulnerabilidad encontrada en "+url+" guardando en db"
        xss_encontrado = True
        if hayLock:
            lock.acquire()
            database.escribir(url,['requestSinParametros'],"get")
            lock.release()
        else:
            database.escribir(url,['requestSinParametros'],"get")

    return xss_encontrado
