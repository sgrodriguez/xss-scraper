# xss-Scraper
Toma una url y testea si es vulnerable a un ataque xss, luego busca todos los links del mismo dominio y los testea en busca de la misma vulnerabilidad.


# Requisitos
Python 2.7 y los packages que se encuentran en requirements.txt, para instalarlos simplemente correr en consola


``` pip install -r requirements.txt  ```

# Modo de uso
Para usar xss-Scrapper simplemente correr el xss_scrapper.py

Los parametros obligatorios son:
* URL
* cantidad de threads 

Los parametros opcionales son:
* cota maxima de urls 

### Ejemplo
```   
python xss_scraper.py [U] [T] [C]
        [U] = url
        [T] = cantidad de threads
        [C] = cota maxima de urls  

python xss_scraper.py https://google-gruyere.appspot.com/584007498737/ 5 20
```

En xss_scraper.py se encuentran las funciones destinadas a buscar urls y lanzar threads que checkean xss,
en detectar_xss.py estan las funciones destinadas a detectar xss dada una url y por ultimo en clase_database se encuentra la clase encargada de guardar en la db los resultados obtenidos.

# TODO

* Agregarle Tests
* Dar la posibilidad de usar custom payloads
* Poner mejores nombres a los archivos
