LIBS=sqlite3
CFLAGS=-O2 -std=gnu11 -Wall -Wextra -Wno-unused-value `pkg-config --cflags ${LIBS}`
LDFLAGS=`pkg-config --libs ${LIBS}`

.PHONY: all
all: spycy

.PHONY: setcap
setcap: spycy
	setcap cap_net_admin+ep ./spycy

%: source/%.c
	${CC} -o $@ $^ ${CFLAGS} ${LDFLAGS}
