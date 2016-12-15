Utilisation du code : 

Taper make pour générer l'executable
Taper ./analyse et vous aurez un message qui explique comment utiliser le programme


Réalisation : 

On a la présence des quatres options -i -o -v -f fonctionnels
-o Permet de lire un fichier pcap et de décoder les trames
-i pour choisir l'interace qu'on écoute
-v pour la verbosité
-f pour filtrer selon un argument

Dans l'en-tête ethernet on reconnaît les paquets IP et ARP.
Si on a de l'IP, on décode l'en-tête
On ne reconnaît que TCP et UDP.
Ensuite on décode les deux en-têtes.

On reconnaît les port applicatifs suivants : 
	FTP (côté client et serveur), HTTP (sécurisé ou non), DNS, SMTP (sécurisé ou non), TELNET et BOOTP

En verbosité 1 on affiche uniquement le nom du port
En verbosité 2 on décode HTTP, SMTP et BOOTP
En verbsoité 3 on décode HTTP, SMTP, BOOTP et TELNET. On affiche en ascii FTP, DNS, HTTP et SMTP

John-Nathan HILL