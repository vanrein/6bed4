all: 6bed4_plus_pubtsp strictlydemoclient

6bed4_plus_pubtsp: router.c
	gcc -DLINUX -ggdb3 -o $@ $<

strictlydemoclient: democlient.c
	gcc -DLINUX -ggdb3 -o $@ $<

