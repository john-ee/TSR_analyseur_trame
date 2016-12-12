/*
 * auteur : John-Nathan HILL
 */

/*
 * Cette fonction est appelé lorsque le programme n'est pas lancé avec les bons arguments
 * Elle affiche l'utilisation du programme
 */
void usage();

/*
 * On commence par utiliser la fonction getopt() pour récupérer les arguments en ligne de commande
 * On commence par regarder le fichier mis en entrée
 * Ensuite on vérifie qu'un interface est mis en entrée
 * Puis on reagrde les adresses liées à l'interface
 * On regarde si un filtre est demandé
 * Finalement on lance l'écoute sur l'interface
 */
int main(int argc, char *argv[]);