LIBS=sqlite3
CFLAGS=-O2 -std=c11 -Wall -Wextra `pkg-config --cflags ${LIBS}`
LDFLAGS=`pkg-config --libs ${LIBS}`

.PHONY: all
all: spycy

%: source/%.c
	${CC} -o $@ $^ ${CFLAGS} ${LDFLAGS}
