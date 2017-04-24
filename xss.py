# Python 2.7.11

import sys
import requests
import bs4
import threading
import time
import Queue

from urlparse import urlparse

# Variable globlal
dbName = "xssTest"

def guardarUrl(url,parametrosDelXss):
    # TODO
    print "Guardo "+url
    pass

def agregarUrlsVecinas(url, dominio_original, noVisitadas, visitadas):

    res = requests.get(url)
    res.raise_for_status()

    soup = bs4.BeautifulSoup(res.text,"html.parser")
    links = soup.select('a')

    for link in links:
        link_parseado = link.get('href')
        try:
            dominio_del_link_parseado = urlparse(link_parseado).netloc
            if dominio_del_link_parseado == dominio_original:
                if link_parseado not in visitadas:
                    noVisitadas.add(link_parseado)
        except AttributeError:
            pass


def checkearXSS(url):
    "TODO"
    time.sleep(2)
    print('Ya checkie '+url)
    return True


def checkiadorDeUrls(colaDeUrls,cjtoDeUrls,cantidadDeThreads,semaforo):
    """ Docsting for checkiadorDeUrls """
    # aca poner otro semaforo para que pueda empezar
    while len(cjtoDeUrls) != 0 or not colaDeUrls.empty():
        print "LLEGUE ACA CON "+str(colaDeUrls.qsize())+" urls"
        semaforo.acquire()
        # ACA ponemos un semaforo para eliminar el busy waiting y no terminar cuando faltan urls por checkiar 
        if colaDeUrls.qsize() < cantidadDeThreads:
            # creamos los threads que van a checkiar las urls
            # los starteamos
            # y hacemos join a que terminen
            threadsParaCheckear = []
            for i in range(colaDeUrls.qsize()):
                thread = threading.Thread(target= checkearXSS, args=[colaDeUrls.get()])
                threadsParaCheckear.append(thread)
            for t in threadsParaCheckear:
                t.start()
            semaforo.release()
            for t in threadsParaCheckear:
                t.join()
        else:
            # checkiar las urls
            # los starteamos y hacemos join
            # y hacemos join a que terminen
            threadsParaCheckear = []
            for i in range(cantidadDeThreads):
                thread = threading.Thread(target= checkearXSS, args=[colaDeUrls.get()])
                threadsParaCheckear.append(thread)
            for t in threadsParaCheckear:
                t.start()
            semaforo.release()
            for t in threadsParaCheckear:
                t.join()



def xss_scraper(url, cantidadDeThreads, cota_maxima_de_urls):
    #Guarda el dominio para filtrar los hipervinculos futuros
    dominio_original = urlparse(url).netloc
    if checkearXSS(url):
        #Si es vulnerable guardamos la url a la db y procedemos a checkiar el resto del sitio
        parametrosDelXss = 1
        guardarUrl(url,parametrosDelXss)
        urlNoVisitadas = set()
        urlVisitadas = set()
        colaDeUrls = Queue.Queue()
        urlVisitadas.add(url)

        agregarUrlsVecinas(url,dominio_original,urlNoVisitadas,urlVisitadas)


        # creamos el thread checkiador de urls toma como parametro la cantidad de threads
        # el cjto no visitado y la cola de urls 
        semaforo = threading.Semaphore()
        threadCheckiadorDeUrls = threading.Thread(target=checkiadorDeUrls, args=[colaDeUrls, urlNoVisitadas, cantidadDeThreads, semaforo])
        threadCheckiadorDeUrls.start()

        while not len(urlNoVisitadas) == 0:
            #Buscamos todos los enlaces del mismo dominio
            # aca habria que agregar un mutex para trabajar con las colas
            if len(urlNoVisitadas) > cota_maxima_de_urls:
                break
            semaforo.acquire()
            urlAvisitar = urlNoVisitadas.pop()
            urlVisitadas.add(urlAvisitar)
            colaDeUrls.put(urlAvisitar)
            semaforo.release()
            agregarUrlsVecinas(urlAvisitar,dominio_original,urlNoVisitadas,urlVisitadas)

        semaforo.acquire()
        for i in range(len(urlNoVisitadas)):
            colaDeUrls.put(urlNoVisitadas.pop())
        semaforo.release()

        # Una vez que ya vimos todas las url esperamos a que terminen de analizarse
        threadCheckiadorDeUrls.join()
        print "TERMINE!"

if __name__ == '__main__':
    """ Tomo argumentos """
    arg = sys.argv[1:]

    url = arg[0]
    cantidad_de_threads = arg[1]
    cota_maxima_de_urls = int(arg[2])

    xss_scraper(url, cantidad_de_threads, cota_maxima_de_urls)
