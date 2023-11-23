# -*- coding: UTF-8 -*-

#!/usr/bin/python
# 
# Filename:  networkAgR.py 
#
# Version: 1.0.0
#
# 
# ================================================================================================
#
# Función:  networkAgR
#
# Descripción:   Función que permite realizar las acciones dedicadas para el agente reactivo
#                simple "networkAgR.py". contiene     
#
# whoami:        Determina la dirección IP local para iniciar escaneo de red
#
# Nmap:          Permite realizar escaneo de red en busca de activos alcanzables
#                Realiza búsqueda de puertos y servicios en activos previamente descubiertos
#
# Parámetros: Recibe como parámetro una dirección IP o un segmento completo:
# 
#
# Ejemplo: 192.168.1.5 o también 192.168.1.0/24 
# 
# 
# ================================================================================================
from ipaddress import ip_address
from pickle import FALSE
from unittest import result
import agentspeak
import nmap
#import nmap3
import platform, socket, json
from netifaces import interfaces, ifaddresses, AF_INET
import os, json


actions = agentspeak.Actions(agentspeak.stdlib.actions)
sistema= platform.system()

#Ubicación en el entorno
@actions.add_function(".whoami",(str, ))
def whoami(mensaje):
    if (sistema=="Linux"):
        for ifaceName in interfaces():
            addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
        IP=(' '.join(addresses))
    if (sistema=="Windows"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
        s.close()
    f = open("resultados.txt","w")
    f.write(IP)
    f.close
    return (IP)
 

#Escaneo de red (búsqueda de activos alcanzables)
@actions.add_function(".network_scanning",(str, ))
def network_scanning(direccion):
    print("Buscando dispositivos en la red...")
    try:
        scan=nmap.PortScanner()
        IP=direccion+"/24"
        scan.scan (hosts=IP, arguments='-sP -sV ')
        hosts_list = [(x, scan[x]['status']['state']) for x in scan.all_hosts()]
        targets = open('targets.json', 'w')
        for host, status in hosts_list:
            print (host, status)
            targets.write(host+'\n')
        targets.close()
        return True
    except:
        print("Escaneo no realizado")
        return False


#Escaneo de versiones en activos alcanzables)
@actions.add_procedure(".service_scanning",(str, ))
def service_scanning(direccion):
    print("Escaneando servicios...")


#Escaneo de sistema operativo)
@actions.add_function(".os_detection",(bool, ))
def os_detection(mensaje):
    if (mensaje==True):
        print("Buscando servicios en los activos de red..")
        try:
            targets=open('targets.json', 'r')
            sys=open('results.json', 'w')
            os_detect=nmap.PortScanner()
            linea=targets.readline()
            while linea!="":
                linea=targets.readline()
                res=os_detect.scan(linea, arguments='-O ['scan']['127.0.0.1']['osmatch'][1]')
                print(res)
                json_string=json.dumps(res)
                try:
                    sys.write(json_string)
                except:
                    print("Error al escribir")
            sys.close()
            targets.close()
        except:
            return False
    else:
        print("no se detectaron activos qué escanear")
        return False