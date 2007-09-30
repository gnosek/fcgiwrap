all: fcgiwrap
install: all
	[ -f /usr/local/bin/fcgiwrap ] && mv /usr/local/bin/fcgiwrap /usr/local/bin/fcgiwrap~
	cp fcgiwrap /usr/local/bin
	rm /usr/local/bin/fcgiwrap~

fcgiwrap: fcgiwrap.c
	gcc -Wall -Wextra -Werror -pedantic -O2 -g3 fcgiwrap.c -o fcgiwrap -lfcgi

clean:
	-rm fcgiwrap

