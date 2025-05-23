CC = cc
CFLAGS = -Wall -O2 -D_GNU_SOURCE -I/usr/local/include -I/usr/local/include/event2
LDFLAGS = -L/usr/local/lib -levent -pthread

BIN = dnsproxy
SRC = dnsproxy.c
CONF = dnsproxy.conf
RC_SCRIPT = dnsproxy.rc

PREFIX = /usr/local
SBIN_DIR = $(PREFIX)/sbin
ETC_DIR = $(PREFIX)/etc
RC_DIR = $(ETC_DIR)/rc.d

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

install: $(BIN)
	install -d -m 755 $(SBIN_DIR)
	install -m 755 $(BIN) $(SBIN_DIR)/$(BIN)
	@if [ ! -f $(ETC_DIR)/$(CONF) ]; then \
		echo "Installing default config..."; \
		install -m 644 $(CONF) $(ETC_DIR)/$(CONF); \
	else \
		echo "Config file already exists, skipping."; \
	fi
	install -m 755 $(RC_SCRIPT) $(RC_DIR)/dnsproxy

clean:
	rm -f $(BIN)
