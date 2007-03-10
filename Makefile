all: fcgiwrap
go: all
	../../bin/spawn-fcgi -u admin -f ./fcgiwrap -a 172.16.0.2 -p 14017

fcgiwrap: fcgiwrap.c
	gcc -Wall -Werror -pedantic -O2 -g fcgiwrap.c -o fcgiwrap -lfcgi

clean:
	-rm fcgiwrap

