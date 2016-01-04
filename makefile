prefix = analyseur

all: 
	gcc $(prefix).c -lpcap -o $(prefix) #-g -std=gnu99 -W -Wall -Wextra -Wmissing-declarations \
        #-Wmissing-prototypes -Wredundant-decls -Wshadow -Wbad-function-cast \
        #-Wcast-qual -Wno-discarded-qualifiers