prefix = analyseur

all: 
	gcc $(prefix).c -lpcap -o $(prefix) #-g -std=gnu99 -W -Wall -Wextra -Wmissing-declarations \
        #-Wmissing-prototypes -Wredundant-decls -Wshadow -Wbad-function-cast \
        #-Wcast-qual -Wno-discarded-qualifiers
        #-ansi -O2 -Wchar-subscripts -Wcomment -Wformat=2 -Wimplicit-int
	#-Werror-implicit-function-declaration -Wmain -Wparentheses
	#-Wsequence-point -Wreturn-type -Wswitch -Wtrigraphs -Wunused
	#-Wuninitialized -Wunknown-pragmas -Wfloat-equal -Wundef
	#-Wshadow -Wpointer-arith -Wbad-function-cast -Wwrite-strings
	#-Wconversion -Wsign-compare -Waggregate-return -Wstrict-prototypes
	#-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn
	#-Wformat -Wmissing-format-attribute -Wno-deprecated-declarations
	#-Wpacked -Wredundant-decls -Wnested-externs -Winline -Wlong-long
	#-Wunreachable-code
