

RM=rm -fr
INC=-I../inc

CC=gcc
BIN=../bin/UIDAI

CFLAGS=-g -c -DXMLSEC_NO_SIZE_T -DXMLSEC_CRYPTO_OPENSSL -D__XMLSEC_FUNCTION__=__FUNCTION__ -DUNIX_SOCKETS -DXML_SECURITY -DDEBUG -I/usr/local/openssl-1.1.0e/include -I/usr/local/libxslt-1.1.29/include -I/usr/local/libxml2-2.9.3/include/libxml2 -I/usr/local/xmlsec1-1.2.23/include/xmlsec1


LDFLAGS=-L/usr/local/openssl-1.1.0e/lib -L/usr/local/libxslt-1.1.29/lib -L/usr/local/libxml2-2.9.3/lib -L/usr/local/xmlsec1-1.2.23/lib

LIBS=-lssl -lcrypto -lxml2 -lxmlsec1 -lxslt -lxmlsec1-openssl

SRC=$(shell find . -type f -name '*.c')

OBJ=$(SRC:.c=.o)


all: $(SRC) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LIBS) -o $@

.c.o:
	$(CC) $(INC) $(CFLAGS) $< -o $@

clean:
	$(RM) *.o
	$(RM) $(BIN)

