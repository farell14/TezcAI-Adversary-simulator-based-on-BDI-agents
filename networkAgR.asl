// Función de obtención de ubicación dentro de la red (dirección IP principal).

+!who(Msg)[source(agDiscovery)] <-
  .print("El agente", agDiscovery, "me pide iniciar", Msg);
  .whoami("Mostrando IP local desde la funcion Whoami", IP);
  .send(agDiscovery, achieve, ip(IP));
  .print(IP).

+!net(Msg)[source(AG)] <-
  .print("El agente ",AG, "me pide iniciar escaneo de red");
  .network_scanning(Msg, A);
  .send(agDiscovery, tell, activos(A));
  .send(agDiscovery, achieve, conf("inicia")).

+!os_detection(Msg)[source(AG)] <-
  .print("El agente",AG, "Me pide iniciar escaneo de S.O");
  .os_detection(Msg, A).
  
