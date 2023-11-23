
#!/usr/bin/env python

from pickle import FALSE
import string
import agentspeak
import agentspeak.runtime
import agentspeak.stdlib
import nmap
from colorama import init, Fore, Back, Style
from netifaces import interfaces, ifaddresses, AF_INET
import os
import networkAgR
import json


whoami_confim=FALSE
Scan_confirm=FALSE

actions = agentspeak.Actions(agentspeak.stdlib.actions)

def ubicacion(agents):   
   plan= agentspeak.Literal("ubicacion", (str(),))
   agents.call(
      agentspeak.Trigger.addition, #agrega el logro
      agentspeak.GoalType.achievement,
      plan,
      agentspeak.runtime.Intention()
   )
   agents.run()

@actions.add_procedure(".creaArch", (str,))
def _creaArch(text):  
    print("---crea archivo----")
    f = open("archivo.txt","w")
    f.write(text)
    print("----------------")

#Ubicación en el entorno
@actions.add_function(".whoami",(str, ))
def whoami(mensaje):
    print(mensaje)
    for ifaceName in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
    print("mi dirección IP local es:")
    IP=(' '.join(addresses))
    f = open("resultados.txt","w")
    f.write(IP)
#    print(IP)
    return IP

#Escaneo de red (búsqueda de activos alcanzables)
@actions.add_procedure(".network_scanning",(int, ))
def network_scanning(mensaje):
    nmap=nmap.PortScanner()
    print(mensaje)
    f = open("resultados.txt","r")
    while(True):
        linea = f.readline()
        print(linea)
        network=linea
        if not linea:
            break
    f.close()
    os.system(nmap+linea+"/24")


env = agentspeak.runtime.Environment()

with open(os.path.join(os.path.dirname(__file__), "networkAgR.asl")) as source:
    agents = env.build_agents(source, 1, networkAgR.actions)

with open(os.path.join(os.path.dirname(__file__), "agDiscovery.asl")) as source:
    agents.append(env.build_agent(source, actions))

if __name__ == "__main__":
    logo=open("logo.dat","r")
    op=None
    if(logo.mode=="r"):
        content=logo.read()
        print(Fore.GREEN+content)
    logo.close()
    env.run()


