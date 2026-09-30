
CC=gcc
CXX=g++

#CFLAGS=-c -g -I /usr/include/mysql
#LDFLAGS=-g

# Portable by default so the binary keeps working if the VM moves to another
# CPU model; build with "make MARCH=native" to tune for this machine.
MARCH ?= x86-64-v2
CXXFLAGS = -O2 -I.. -march=$(MARCH) -fno-strict-aliasing -MMD -MP
CFLAGS= $(CXXFLAGS) -std=gnu17
LDFLAGS=-O2 -lgmp

SOURCES=lyra2re.c lyra2v2.c lyra2v3.c Lyra2.c lyra2z.c Lyra2-z.c lyra2zz.c Lyra2-zz.c lyra2z330.c lyra2vc0ban.c Sponge.c allium.c \
	c11.c x11.c x12.c x13.c hsr14.c x14.c x15.c x17.c x17r.c x18.c \
	x22i.c SWIFFTX/SWIFFTX.c lane.c x25x.c \
	blake.c blakecoin.c blake2b.c blake2s.c blake2-ref/blake2b.c blake2-ref/blake2s.c jha.c keccak.c lbry.c tribus.c exosis.c \
	deep.c fresh.c groestl.c neoscrypt.c nist5.c quark.c qubit.c skein.c skein2.c bmw512.c \
	bitcore.c timetravel.c x11evo.c x16r.c x16s.c x16rt.c x16rv2.c xevan.c bastion.c hmq17.c sonoa.c \
	bmw.c luffa.c pentablake.c vitalium.c whirlpool.c whirlpoolx.c zr5.c \
	scrypt.c scryptn.c sha256.c sha256t.c sha256q.c sha256-d.c minotaur.c \
	a5a.c a5amath.c m7m.c magimath.cpp velvet.c \
	blake2/blake2b.c argon2d/argon2.c argon2d/core.c argon2d/encoding.c argon2d/opt.c argon2d/thread.c \
	hive.c pomelo.c hex.c argon2m.c argon2d.c geek.c balloon.c \
	phi.c phi2.c polytimos.c rainforest.c skunk.c sib.c veltor.c gost.c aergo.c x20r.c x21s.c lbk3.c pipehash.c gltalgos.c \
	yespower/yespower-platform.c yespower/yespower-combined.c oshash.c oshash_prims.c oshash-stratum.c sha256-P.c dedal.c phi1612.c bcd.c \
	sha512256d.c sha3_256t.c verthash.c \
	blake3hash.c blake3/blake3.c blake3/blake3_dispatch.c blake3/blake3_portable.c \
	ghostrider.c flex.c cryptonote/cn_slow_hash.c cryptonote/aesb.c cryptonote/c_keccak.c cryptonote/c_blake256.c \
	cryptonote/c_groestl.c cryptonote/c_jh.c cryptonote/c_skein.c \
	progpow/keccak.c progpow/keccakf800.c progpow/keccakf1600.c progpow/primes.c progpow/progpow.cpp \
	equihash/equihash_verify.c cryptonote_block.c \
	$(RANDOMX_SOURCES)

# RandomX (tevador/RandomX, BSD-3, see randomx/README.yiimp): the portable
# interpreter plus the JIT compiler of the machine (x86-64 or ARMv8). The
# hardware AES and AVX2/SSSE3 Argon2 code is selected at run time
# (randomx_get_flags), as in the RandomX CMake build.
RANDOMX_SOURCES = randomx/aes_hash.cpp randomx/argon2_ref.c randomx/argon2_ssse3.c randomx/argon2_avx2.c \
	randomx/bytecode_machine.cpp randomx/cpu.cpp randomx/dataset.cpp randomx/soft_aes.cpp \
	randomx/virtual_memory.c randomx/vm_interpreted.cpp randomx/allocator.cpp \
	randomx/assembly_generator_x86.cpp randomx/instruction.cpp randomx/randomx.cpp \
	randomx/superscalar.cpp randomx/vm_compiled.cpp randomx/vm_interpreted_light.cpp \
	randomx/argon2_core.c randomx/blake2_generator.cpp randomx/instructions_portable.cpp \
	randomx/reciprocal.c randomx/virtual_machine.cpp randomx/vm_compiled_light.cpp \
	randomx/blake2/blake2b.c
UNAME_M := $(shell uname -m)
ifneq (,$(filter x86_64 amd64,$(UNAME_M)))
RANDOMX_SOURCES += randomx/jit_compiler_x86.cpp randomx/jit_compiler_x86_static.S
randomx/%.o: CXXFLAGS += -maes
randomx/%.o: CFLAGS += -maes
randomx/argon2_ssse3.o: CFLAGS += -mssse3
randomx/argon2_avx2.o: CFLAGS += -mavx2
endif
ifneq (,$(filter aarch64 arm64,$(UNAME_M)))
RANDOMX_SOURCES += randomx/jit_compiler_a64.cpp randomx/jit_compiler_a64_static.S
endif

# BLAKE3 (decred, blake3): portable C only, no SIMD code to keep the build
# independent of MARCH (a 180-byte header is a single BLAKE3 chunk anyway)
blake3/%.o: CFLAGS += -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_USE_NEON=0

# OSHash-Y (OSBTC): the vendored oshash.c includes "yespower.h"
oshash.o: CFLAGS += -Iyespower

OBJECTS=$(patsubst %.S,%.o,$(patsubst %.cpp,%.o,$(SOURCES:.c=.o)))
OUTPUT=libalgos.a

all: $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	rm -f $@
	ar rcs $@ $(OBJECTS)

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

#	$(CC) $(CFLAGS) -std=gnu99 -Wno-pointer-sign -Wno-pointer-to-int-cast -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16 -Ofast -flto -fuse-linker-plugin -ftree-loop-if-convert-stores -DUSE_ASM -pg $<

-include $(OBJECTS:.o=.d)

clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(OUTPUT)
	rm -f *.o
	rm -f ar2/*.o
	rm -f blake2/*.o
	rm -f SWIFFTX/*.o
	rm -f blake3/*.o blake3/*.d
	rm -f cryptonote/*.o cryptonote/*.d
	rm -f progpow/*.o progpow/*.d
	rm -f equihash/*.o equihash/*.d
	rm -f randomx/*.o randomx/*.d randomx/blake2/*.o randomx/blake2/*.d
