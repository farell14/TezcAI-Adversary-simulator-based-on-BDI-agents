/** -*- coding: UTF-8 -*-
# 
# Filename:  agDiscovery.asl 
#
# Version: 1.0.0
#
# 
# ================================================================================================
#
#
#   Agente BDI responsable de coordinar al agente reactivo simple NetworkAgR.asl
#   Posee las funciones:
#     *Whoami
#     *escaneo de activos
#     *Detección de SO 
# 
# ================================================================================================
     */

activos(C)[source(AG)]:- false.

!start.
+!start <-
   .print("Soy Agentdiscovery ...");
   .send(networkAgR, achieve, who(whoami));
   .print("Determinando direccion IP principal").

//+!send_IP:  <-
+!ip(IP)[source(AG)] <-
   .print("Esta es la IP que me mando", AG);
   .send(networkAgR, achieve, net(IP)).
   //.send(networkAgR, achieve, net(IP)).

+!conf(X) [source(AG)] <-
   .print("Iniciando confirmacion de escaneo realizado por", AG);
   ?activos(C);
   .print("la confirmacion del escaneo arrojo",C, "como resultado");
   !act(C).


+!act(C) <-
   .send(networkAgR, achieve, os_detection(C)).
   //.print("Se ha detectado el sistema operativo de los activos").