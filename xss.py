# Python 2.7.11
import sys
import requests
import bs4
import threading
import time
import Queue

from urlparse import urlparse

# Variable globlal


def checkearXSS(url):
    "TODO"
    time.sleep(2)
    print('Ya checkie '+url)
    return True


def guardarUrl(url,parametros_del_xss):
    # TODO
    print "Guardo "+url
    pass


def agregarUrlsVecinas(url, dominio_original, cjto_urls_no_visitadas, cjto_urls_visitadas):

    res = requests.get(url)
    res.raise_for_status()

    url_html = bs4.BeautifulSoup(res.text,"html.parser")
    links = url_html.select('a')

    for link in links:
        link_parseado = link.get('href')
        try:
            dominio_del_link_parseado = urlparse(link_parseado).netloc
            if dominio_del_link_parseado == dominio_original:
                if link_parseado not in cjto_urls_visitadas:
                    cjto_urls_no_visitadas.add(link_parseado)
        except AttributeError:
            pass


def checkiadorDeUrls(cola_de_urls,cjto_urls_no_visitadas,cantidad_de_threads,semaforo):
    """ Docsting for checkiadorDeUrls """
    while len(cjto_urls_no_visitadas) != 0 or not cola_de_urls.empty():
        print "LLEGUE ACA CON "+str(cola_de_urls.qsize())+" urls"
        # ACA ponemos un semaforo para eliminar el busy waiting y no hacer quilombo con las colas
        semaforo.acquire()
        if cola_de_urls.qsize() < cantidad_de_threads:
            rango = cola_de_urls.qsize()
        else:
            rango = cantidad_de_threads

        # creamos los threads que van a checkiar las urls
        threadsParaCheckear = []
        for i in range(rango):
            thread = threading.Thread(target= checkearXSS, args=[cola_de_urls.get()])
            threadsParaCheckear.append(thread)
        for t in threadsParaCheckear:
            t.start()
        semaforo.release()
        for t in threadsParaCheckear:
            t.join()



def xsscraper(url, cantidad_de_threads, cota_maxima_de_urls):
    #Guarda el dominio para filtrar los hipervinculos futuros
    dominio_original = urlparse(url).netloc

    if checkearXSS(url):
        #Si es vulnerable guardamos la url a la db y procedemos a checkiar el resto del sitio
        parametros_del_xss = 1
        guardarUrl(url,parametros_del_xss)
        cjto_urls_no_visitadas = set()
        cjto_urls_visitadas = set()
        cola_de_urls = Queue.Queue()
        cjto_urls_visitadas.add(url)

        agregarUrlsVecinas(url, dominio_original, cjto_urls_no_visitadas, cjto_urls_visitadas)


        # creamos el thread checkiador de urls toma como parametro la cantidad de threads
        # el cjto no visitado y la cola de urls 
        semaforo = threading.Semaphore()
        threadCheckiadorDeUrls = threading.Thread(target=checkiadorDeUrls, args=[cola_de_urls, cjto_urls_no_visitadas, cantidad_de_threads, semaforo])
        threadCheckiadorDeUrls.start()

        while not len(cjto_urls_no_visitadas) == 0:
            #Buscamos todos los enlaces del mismo dominio
            # aca habria que agregar un mutex para trabajar con las colas
            if len(cjto_urls_no_visitadas) > cota_maxima_de_urls:
                break
            semaforo.acquire()
            url_a_visitar = cjto_urls_no_visitadas.pop()
            cjto_urls_visitadas.add(url_a_visitar)
            cola_de_urls.put(url_a_visitar)
            semaforo.release()
            agregarUrlsVecinas(url_a_visitar, dominio_original, cjto_urls_no_visitadas, cjto_urls_visitadas)

        # Si nos pasamos de la cota de urls agregamos a la cola 
        # todas las urls que nos faltan verificar
        semaforo.acquire()
        for i in range(len(cjto_urls_no_visitadas)):
            cola_de_urls.put(cjto_urls_no_visitadas.pop())
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

    xsscraper(url, cantidad_de_threads, cota_maxima_de_urls)
