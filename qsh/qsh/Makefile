CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -O2 \
           -I/usr/local/include/postWolf -DWOLFSSL_USE_OPTIONS_H \
           -I/usr/include/libxml2 -I/usr/include/json-c \
           -I../../socket-level-wrapper-MQC \
           -I../../mtc-keymaster/read-config

MQC_LIB  = ../../socket-level-wrapper-MQC/libmqc.a
SRCS     = qsh.c ../../mtc-keymaster/read-config/read-config.c

LDLIBS   = $(MQC_LIB) -L/usr/local/lib -lpostWolf \
           -ljson-c -laugeas -lpthread -lunbound -lcrypto -lz

TARGET   = qsh

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)
