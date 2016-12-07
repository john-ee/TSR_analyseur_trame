APPLI=main
CSRC= main.c complet.c concis.c
CC = gcc -g

COBJ=$(CSRC:.c=.o)

.c.o:
	$(CC) -c $*.c

$(APPLI):	$(COBJ)
	$(CC) -o $(APPLI) $(COBJ) -lpcap

clean:
	rm *.o
	rm $(APPLI)
