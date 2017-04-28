# Python 2.7.11
import dataset

class Database:

    def __init__(self, domain):
        self.database_table = domain 
        

    def escribir(self, url, form_names, metodo):
        with dataset.connect('sqlite:///xss_encontrados.db') as xss_db:
            # Comprimamos todos los names en uno solo para tener
            # una referencia a la hora que queramos replicar el ataque
            names = form_names.pop()
            for name in form_names:
                names= names+'-'+name

            xss_data = dict(url=url, names=names, metodo=metodo)
            xss_db[self.database_table].insert(xss_data)
