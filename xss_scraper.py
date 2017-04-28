# Python 2.7.11
import sys
import requests
import bs4
import threading
import time
import Queue

from urlparse import urlparse, urljoin

from clase_database.database import Database
from detector_xss import checkearXSS, requestAceptada


def es_relativo(url):
    return not bool(urlparse(url).netloc)


def agregarUrlsVecinas(url, dominio_original, cjto_urls_no_visitadas, cjto_urls_visitadas):
    
    res = requestAceptada(url,"get")
    if res == None:
        return

    url_html = bs4.BeautifulSoup(res.text,"html.parser")
    links = url_html.select('a')

    for link in links:
        link_parseado = link.get('href')
        try:
            if es_relativo(link_parseado):
                url_nueva = urljoin(url, link_parseado)
                if url_nueva not in cjto_urls_visitadas:
                    cjto_urls_no_visitadas.add(url_nueva)
            else:
                dominio_del_link_parseado = urlparse(link_parseado).netloc
                if dominio_del_link_parseado == dominio_original:
                    if link_parseado not in cjto_urls_visitadas:
                        cjto_urls_no_visitadas.add(link_parseado)
        except AttributeError:
            print "Error Tratando de parsear url"
            pass


def checkiadorDeUrls(cola_de_urls,cjto_urls_no_visitadas,cantidad_de_threads,semaforo, database):

    while len(cjto_urls_no_visitadas) != 0 or not cola_de_urls.empty():
        # Aca usamos un semaforo para eliminar el busy waiting
        # y evitar casos bordes con la cola y los cjtos
        semaforo.acquire()
        if cola_de_urls.qsize() < cantidad_de_threads:
            rango = cola_de_urls.qsize()
        else:
            rango = cantidad_de_threads

        threads_para_checkiar = []
        # Creamos un lock para que escriban correctamente en la database
        lock = threading.Lock()
        for i in range(rango):
            thread = threading.Thread(target= checkearXSS, args=[cola_de_urls.get(), database, lock])
            threads_para_checkiar.append(thread)
        semaforo.release()
        for t in threads_para_checkiar:
            t.start()
        for t in threads_para_checkiar:
            t.join()


def xsscraper(url, cantidad_de_threads, *args):
    
    existe_cota = False
    if len(args) > 0:
        existe_cota = True
        cota_maxima_de_urls = args[0]

    dominio_original = urlparse(url).netloc
    # Creamos instancia de la de database
    database = Database(dominio_original)
    if checkearXSS(url,database):
        cjto_urls_no_visitadas = set()
        cjto_urls_visitadas = set()
        cola_de_urls = Queue.Queue()
        cjto_urls_visitadas.add(url)

        agregarUrlsVecinas(url, dominio_original, cjto_urls_no_visitadas, cjto_urls_visitadas)


        # creamos el thread checkiador de urls que se va a 
        # encargar de lanzar los threads que analizan si una 
        # url es vulnerable a xss
        semaforo = threading.Semaphore()
        thread_checkiador_de_urls = threading.Thread(target=checkiadorDeUrls, args=[cola_de_urls, 
                                                                                    cjto_urls_no_visitadas, 
                                                                                    cantidad_de_threads, 
                                                                                    semaforo,
                                                                                    database])
        thread_checkiador_de_urls.start()

        while not len(cjto_urls_no_visitadas) == 0:
            if existe_cota and len(cjto_urls_no_visitadas) > cota_maxima_de_urls:
                break

            if len(cjto_urls_no_visitadas) < cantidad_de_threads:
                cant_urls_a_encolar = len(cjto_urls_no_visitadas)
            else:
                cant_urls_a_encolar = cantidad_de_threads

            urls_a_visitar = []
            semaforo.acquire()
            for i in range(cant_urls_a_encolar):
                proxima_url_a_checkiar = cjto_urls_no_visitadas.pop()
                urls_a_visitar.append(proxima_url_a_checkiar)
                cjto_urls_visitadas.add(proxima_url_a_checkiar)
                cola_de_urls.put(proxima_url_a_checkiar)
            semaforo.release()

            # Buscamos los vecinos
            for url in urls_a_visitar:
                agregarUrlsVecinas(url, dominio_original, cjto_urls_no_visitadas, cjto_urls_visitadas)

        # Si nos pasamos de la cota de urls no seguimos buscando vecinosy 
        # pasamos a la cola todas las urls que nos faltan verificar
        semaforo.acquire()
        for i in range(len(cjto_urls_no_visitadas)):
            cola_de_urls.put(cjto_urls_no_visitadas.pop())
        semaforo.release()

        # Una vez que ya vimos todas las url esperamos a que terminen de analizarse
        thread_checkiador_de_urls.join()
        print "Termine, Analize "+str(len(cjto_urls_visitadas))+" urls"


if __name__ == '__main__':
    """ Tomo argumentos """
    arg = sys.argv[1:]
    url = arg[0]
    cantidad_de_threads = arg[1]

    try:
        cota_maxima_de_urls = int(arg[2])
        xsscraper(url, cantidad_de_threads, cota_maxima_de_urls)
    except IndexError:
        print "Lanzando xss-scraper sin cota maxima de urls a analizar"
        xsscraper(url, cantidad_de_threads)
