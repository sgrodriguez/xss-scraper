# Python 2.7.11
import sys
import requests
import bs4
import Database
import threading

from urlparse import urlparse, urljoin
from clase_database.database import Database


def checkearMetodo(url, names, metodo):
    es_vulnerable = False
    form_data= {}
    codigo_a_inyectar = '<script>alert("XssPrueba")</script>'
    for name in names:
        form_data[name] = codigo_a_inyectar

    if len(names) == 0:
        url = url+codigo_a_inyectar

    if metodo == "get":
        res = requests.get(url, params=form_data)
    elif metodo == "post":
        res = requests.get(url, data=form_data)
    else:
        print "Metodo no soportado "+metodo
        return es_vulnerable

    res.raise_for_status()
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

    res = requests.get(url)
    res.raise_for_status()
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
