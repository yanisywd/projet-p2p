# Système de partage de fichiers P2P
#
#   make          compile les trois programmes
#   make test     lance tous les tests du système
#   make demo     prépare un dossier demo/ propre à partir d'exemples/
#   make clean    supprime les fichiers compilés
#   make distclean  remet le dossier à neuf (avant de rendre le projet)
#
# Pour vérifier la mémoire ou les threads :
#   make clean all SAN=address,undefined
#   make clean all SAN=thread

CFLAGS  ?= -O2 -g
override CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wstrict-prototypes -pthread
override CFLAGS  += -D_FILE_OFFSET_BITS=64
override LDFLAGS += -pthread

# Sur Linux, crypt() se trouve dans une bibliothèque séparée.
ifeq ($(shell uname -s),Linux)
override LDLIBS  += -lcrypt
endif

ifdef SAN
override CFLAGS  += -fsanitize=$(SAN) -fno-omit-frame-pointer
override LDFLAGS += -fsanitize=$(SAN)
endif

PROGRAMS := serveur_central serveur_ftp client_ftp
HEADERS  := $(wildcard src/*.h)

# Un dossier par système : un projet compilé sur Mac se recompile sous Linux.
BUILD    := build/$(shell uname -s)-$(shell uname -m)
SHARED   := $(BUILD)/common.o $(BUILD)/auth.o $(BUILD)/sha256.o

all: $(PROGRAMS)

$(PROGRAMS): %: $(BUILD)/%.o $(SHARED)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD):
	mkdir -p $@

test: all
	python3 tests/test_systeme.py

demo: all
	rm -rf demo utilisateurs.db
	cp -R exemples demo
	@echo
	@echo "Dossier demo/ prêt. Dans quatre terminaux :"
	@echo "  ./serveur_central 7777"
	@echo "  ./serveur_ftp localhost 7777 demo/alice"
	@echo "  ./serveur_ftp localhost 7777 demo/bob"
	@echo "  ./client_ftp localhost 7777 demo/bob"

clean:
	rm -rf build $(PROGRAMS)

distclean: clean
	rm -rf demo utilisateurs.db

.PHONY: all test demo clean distclean
