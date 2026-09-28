
CC=gcc

# Portable by default so the binary keeps working if the VM moves to another
# CPU model; build with "make MARCH=native" to tune for this machine.
MARCH ?= x86-64-v2
CFLAGS= -O3 -march=$(MARCH) -fno-strict-aliasing -std=gnu17 -MMD -MP
LDFLAGS=-O2

SOURCES=sph_jh.c sph_blake.c sph_bmw.c sph_groestl.c sph_skein.c sph_keccak.c sph_luffa.c sph_cubehash.c sph_shavite.c \
	sph_simd.c sph_echo.c sph_fugue.c sph_hamsi.c sph_shabal.c sph_whirlpool.c sph_sm3.c sph_streebog.c \
	sph_haval.c sph_hefty1.c sph_ripemd.c sph_sha2.c sph_sha2big.c sph_tiger.c sph_panama.c sph_radiogatun.c \
	blake2s.c blake2b.c

OBJECTS=$(SOURCES:.c=.o)
OUTPUT=libhash.a

all: $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	rm -f $@
	ar rcs $@ $(OBJECTS)

.cpp.o:
	$(CC) $(CFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

-include $(OBJECTS:.o=.d)

clean:
	rm -f *.o *.d $(OUTPUT)


