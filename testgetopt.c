#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>


int main(int argc, char **argv) {
	int option = 0;
	char *dev = NULL, *file = NULL;
	int verb;

	while((option=getopt(argc,argv,"i:o:v:"))) {
		switch(option) {
			case 'i' : dev = optarg;
				printf("%s  ",dev);
				break;
			case 'o' : file = optarg;
				break;
			case 'v' : verb = atoi(optarg);
				break;
			default : break;
		}
	}

	return 0;

}