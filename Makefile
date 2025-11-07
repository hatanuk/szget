CC = cc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto
SRC = szget.c
OUT = szget

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    # macOS (Homebrew or system OpenSSL)
    OPENSSL_DIR ?= /opt/homebrew/opt/openssl
    CFLAGS += -I$(OPENSSL_DIR)/include
    LDFLAGS += -L$(OPENSSL_DIR)/lib
endif

ifeq ($(UNAME_S),Linux)
    # Linux (system OpenSSL)
    CFLAGS += $(shell pkg-config --cflags openssl 2>/dev/null)
    LDFLAGS += $(shell pkg-config --libs openssl 2>/dev/null)
endif

ifeq ($(UNAME_S),FreeBSD)
    # FreeBSD usually has OpenSSL in base system
    CFLAGS += -I/usr/include
    LDFLAGS += -L/usr/lib
endif

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OUT)

