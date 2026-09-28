// Hash regression test for the stratum hash libraries (algos/ and sha3/).
//
//   make hashtest && ./hashtest            # print one line per algo
//   ./hashtest > new.txt; diff old.txt new.txt
//
// Checks sha256d against the bitcoin genesis block hash, runs the known-answer
// tests (real block headers, see kats[] below; the verthash one only when
// VERTHASH_DATAFILE points to verthash.dat) and prints the hash of a fixed
// header for every algo of the stratum, so that the output of two builds
// (compiler, flags, library changes...) can be compared.

#include "stratum.h"
#include "sha3/sph_blake.h"
#include "algos/equihash/equihash_verify.h"

// same wrappers as in stratum.cpp
static void scrypt_hash(const char* input, char* output, uint32_t len)
{
	scrypt_1024_1_1_256((unsigned char *)input, (unsigned char *)output);
}

static void scryptn_hash(const char* input, char* output, uint32_t len)
{
	scrypt_N_R_1_256(input, output, 2048, 1, len);
}

static void neoscrypt_hash(const char* input, char* output, uint32_t len)
{
	neoscrypt((unsigned char *)input, (unsigned char *)output, 0x80000620);
}

struct test_algo {
	const char *name;
	YAAMP_HASH_FUNCTION hash;
};

static const struct test_algo algos[] = {
	{ "a5a", a5a_hash },
	{ "aergo", aergo_hash },
	{ "allium", allium_hash },
	{ "argon2d-crds", argon2d_crds_hash },
	{ "argon2d-dyn", argon2d_dyn_hash },
	{ "argon2d-uis", argon2d_uis_hash },
	{ "argon2m", argon2m_hash },
	{ "astralhash", astralhash_hash },
	{ "balloon", balloon_hash },
	{ "bastion", bastion_hash },
	{ "bcd", bcd_hash },
	{ "bitcore", timetravel10_hash },
	{ "blake", blake_hash },
	{ "blake2b", blake2b_hash },
	{ "blake2s", blake2s_hash },
	{ "blake3", blake3_hash },
	{ "blakecoin", blakecoin_hash },
	{ "bmw", bmw_hash },
	{ "bmw512", bmw512_hash },
	{ "c11", c11_hash },
	{ "cpupower", cpupower_hash },
	{ "decred", decred_hash },
	{ "dedal", dedal_hash },
	{ "deep", deep_hash },
	{ "dmd-gr", groestl_hash },
	{ "exosis", exosis_hash },
	{ "fresh", fresh_hash },
	{ "flex", flex_hash },
	{ "geek", geek_hash },
	{ "ghostrider", ghostrider_hash },
	{ "groestl", groestl_hash },
	{ "hex", hex_hash },
	{ "hmq1725", hmq17_hash },
	{ "hsr", hsr_hash },
	{ "jeonghash", jeonghash_hash },
	{ "jha", jha_hash },
	{ "keccak", keccak256_hash },
	{ "keccakc", keccak256_hash },
	{ "lbk3", lbk3_hash },
	{ "lbry", lbry_hash },
	{ "luffa", luffa_hash },
	{ "lyra2", lyra2re_hash },
	{ "lyra2v2", lyra2v2_hash },
	{ "lyra2v3", lyra2v3_hash },
	{ "lyra2vc0ban", lyra2vc0ban_hash },
	{ "lyra2z330", lyra2z330_hash },
	{ "lyra2z", lyra2z_hash },
	{ "lyra2zz", lyra2zz_hash },
	{ "m7m", m7m_hash },
	{ "mike", mike_hash },
	{ "minotaur", minotaur_hash },
	{ "minotaurx", minotaurx_hash },
	{ "myr-gr", groestlmyriad_hash },
	{ "neoscrypt", neoscrypt_hash },
	{ "nist5", nist5_hash },
	{ "pawelhash", pawelhash_hash },
	{ "penta", penta_hash },
	{ "phi", phi_hash },
	{ "phi2", phi2_hash },
	{ "phi1612", phi1612_hash },
	{ "pipe", pipe_hash },
	{ "polytimos", polytimos_hash },
	{ "power2b", power2b_hash },
	{ "quark", quark_hash },
	{ "qubit", qubit_hash },
	{ "rainforest", rainforest_hash },
	{ "scrypt", scrypt_hash },
	{ "scryptn", scryptn_hash },
	{ "sha256", sha256_double_hash },
	{ "sha256q", sha256q_hash },
	{ "sha256t", sha256t_hash },
	{ "sha3-256t", sha3_256t_hash },
	{ "sha512256d", sha512256d_hash },
	{ "sib", sib_hash },
	{ "skein", skein_hash },
	{ "skein2", skein2_hash },
	{ "skunk", skunk_hash },
	{ "sonoa", sonoa_hash },
	{ "timetravel", timetravel_hash },
	{ "tribus", tribus_hash },
	{ "vanilla", blakecoin_hash },
	{ "veltor", veltor_hash },
	{ "velvet", velvet_hash },
	{ "verthash", verthash_hash }, // needs the data file, see main()
	{ "vitalium", vitalium_hash },
	{ "whirlcoin", whirlpool_hash },
	{ "whirlpool", whirlpool_hash },
	{ "whirlpoolx", whirlpoolx_hash },
	{ "x11", x11_hash },
	{ "x11evo", x11evo_hash },
	{ "x12", x12_hash },
	{ "x13", x13_hash },
	{ "x14", x14_hash },
	{ "x15", x15_hash },
	{ "x16r", x16r_hash },
	{ "x16rv2", x16rv2_hash },
	{ "x16rt", x16rt_hash },
	{ "x16s", x16s_hash },
	{ "x17", x17_hash },
	{ "x17r", x17r_hash },
	{ "x18", x18_hash },
	{ "x20r", x20r_hash },
	{ "x21s", x21s_hash },
	{ "x22i", x22i_hash },
	{ "x25x", x25x_hash },
	{ "xevan", xevan_hash },
	{ "yescrypt", yescrypt_hash },
	{ "yescryptR8", yescryptR8_hash },
	{ "yescryptR16", yescryptR16_hash },
	{ "yescryptR32", yescryptR32_hash },
	{ "yespower", yespower_hash },
	{ "yespowerADVC", yespowerADVC_hash },
	{ "yespowerARWN", yespowerARWN_hash },
	{ "yespowerIC", yespowerIC_hash },
	{ "yespowerLITB", yespowerLITB_hash },
	{ "yespowerLTNCG", yespowerLTNCG_hash },
	{ "yespowerMGPC", yespowerMGPC_hash },
	{ "yespowerR16", yespowerR16_hash },
	{ "yespowerRES", yespowerRES_hash },
	{ "yespowerSUGAR", yespowerSUGAR_hash },
	{ "yespowerTIDE", yespowerTIDE_hash },
	{ "yespowerurx", yespowerurx_hash },
	{ "zr5", zr5_hash },
	{ NULL, NULL }
};

// Known-answer tests: real mainnet block headers (80 bytes, hex as serialized)
// and their proof-of-work hash (displayed, big endian).  "exact" entries are
// checked against a hash published by the coin (genesis assert or block hash);
// the others were checked to be below the block's nBits target, with the
// header verified against the block hash (sha256d) given by an explorer.
struct kat {
	const char *algo;
	const char *header;
	const char *hash;
};

static const struct kat kats[] = {
	{ "lyra2v3", // Vertcoin block 1100000, below target 1b01d01c (header checked against the block id)
	  "00000020adbae4515b0d6add62220b780ee57ce4f193ac68669245f7c5e1f3db8b2566b48c3c1506a050e2ee71a28950e5cf83066d3cc539d20cfed4f16d472fe61776bbdcfb815c1cd0011b198fa83f",
	  "00000000000125a9466860669d38aea7d1241f925919a17fec88b02edd23f98f" },
	{ "lyra2v2", // Vertcoin block 500000, below target 1c009560 (header checked against the block id)
	  "04000000b231e06cbb6ac9d6f54f096cd4248ab6898f157665dfdf1f80591ba91ea098219b70dac1b72c40a2c21b230c3ca44a7becd7e118b8d6919acfd68aab783e6b4950a726576095001cc15950ff",
	  "0000000000088eef2f0e822b5e95aa478a0cf63850422f769184c87b1a13eed4" },
	{ "cpupower", // CPUchain genesis, exact (= hashGenesisBlock)
	  "0100000000000000000000000000000000000000000000000000000000000000000000009046a0f16062e319198ca56736b404a82c5922ad4aea6e775b897396e75737840036215dffff3f1ec01e0900",
	  "000024d8766043ea0e1c9ad42e7ea4b5fdb459887bd80b8f9756f3d87e128f12" },
	{ "power2b", // MicroBitcoin genesis, exact (= hashGenesisBlockWork)
	  "010000000000000000000000000000000000000000000000000000000000000000000000df88deb6f10587e13df6826ca867cabe31cb44aaddefb64a4ae11730adcc263425d99d5dffff3f1fc5020000",
	  "001cb6047ddf13074c4bce354ed3cf0cdd96a4287aa562b032eb81d03e183da8" },
	{ "sha3-256t", // BitcoinIII block 60000, exact (= block hash)
	  "0010002064a6ffc22ad8c07e6573beb8ffa90aefeab3a6f5d41dd91de30f0000000000000a97cb61fd5e5f3f056860c8134f6d749e45130f951b341811e14515e965a57a32679d6a804d6a1a837c0169",
	  "0000000000002b7101d9a41dc0c72284ce35860c2b8cd68a0f17f4a0ceed9914" },
	{ "sha512256d", // Radiant genesis, exact (= hashGenesisBlock)
	  "010000000000000000000000000000000000000000000000000000000000000000000000372cbaf89794aeed5e711b02e78ec4502ad8b315a987c2e2758a85e36a3f7c02aadeaf62ffff001d7980b72a",
	  "0000000065d8ed5d8be28d6876b3ffb660ac2a6c0ca59e437e1f7a6f4e003fb4" },
	{ "yescrypt", // GlobalBoost-Y block 600000, meets its target
	  "00000020d471ca3a815bc4c93fd22838a6b8bbaf30730b02aa35885be676f22bc5b3f93a800033859ee149e0daf13454ac6bcb76a062b0555af85584fb10e71207119b3a1152a76aba9c041d82c40020",
	  "000000028924f1138ff2a805c125ff1ab2dcb6894e7dff6b5f20432ff00757bf" },
	{ "yescryptR8", // BitZeny genesis, exact (= hashGenesisBlock)
	  "010000000000000000000000000000000000000000000000000000000000000000000000d2a4db3bce9f2044558211b401dc45c72806a9ffc7f8a3df9c3a58b491e526a6930e5d54ffff3f1ec2a40500",
	  "000009f7e55e9e3b4781e22bd87a7cfa4acada9e4340d43ca738bf4e9fb8f5ce" },
	{ "yescryptR16", // Yenten genesis (yescryptR16 era), exact (= hashGenesisBlock)
	  "0100000000000000000000000000000000000000000000000000000000000000000000002a67f93c1e533f3d383eda5c359496f703ee33f735732adeed2ca121724e8792687dd359ffff3f1e68930200",
	  "00001828d845205a951f9609e011775e035b00c7fb476310261ef30460cdccab" },
	{ "yescryptR32", // WAVI genesis, exact (= hashGenesisBlock)
	  "01000000000000000000000000000000000000000000000000000000000000000000000017b0c168c5d279adc600d25eaebe5e25f501645d6b2b5edcd93b82dbdbd495a9943ea55af0ff0f1e0c110c00",
	  "00000d39b78c04cc35653abe2442a106a428c5e92ba41ec4967a80a09abf4725" },
	{ "yescryptR32", // LuckyPepe block 290000, meets its target
	  "00000020004a5f73359c8d62d8c8f64e4aeeaf242be57b029a75d0d56bc3d2a663265002ce921cbd4e32210f5f628052eb339075cfe202652c6b6557eb63ab8cdd619165e14cb36a65b6021e23060000",
	  "0000027b8296a4bfa44dcbd7f7911097d3e72d6cf382559d063d3b8fdefb071a" },
	{ "yespowerADVC", // AdventureCoin genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000e43c2fd91767a1efc419c56634e42228737b90a834d644fb511911e5c50fc5e364540668ffff3f1e60700200",
	  "000034171f11f86c4764d4f9dc316cfb8a464f3aeebd131446de37ccc99ec68b" },
	{ "yespowerARWN", // Arowanacoin genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000ab193cca5966475336f429c96b99394c69e5323dbcf1266e9f4c79f23249e08209aac560ffff0f1fa3120000",
	  "000e40df84630b10a9e9004e0552e06e91865535d748dcfb19bba0fce65da313" },
	{ "yespowerLITB", // LightBit genesis, exact (= hashGenesisBlock)
	  "0100000000000000000000000000000000000000000000000000000000000000000000005989b04d9759f28de85cb729bd87a9836e0f8ef1f1e53976edd0a2f36119730fc0af4e5dffff1f1f07140000",
	  "001a37ca994627042609a8ff350c446b935bb912069c37ec543fbdb0a5ed77b3" },
	{ "yespowerLTNCG", // Crionic block 5700003, meets its target
	  "00000020d25eaf28dbc5b555024ed5f006e9f3c180afd24674261aa5eb3eb76a49d847d2daa7aa1db6408f83eaea0704cbdc6ea74065784f22a76616bc35f04d09b0cbc79cbcac6ad1dd001f31070000",
	  "00004d0f0f2dc316da271f0951c62abdbc0830c43b1d7a3c4aadd6088d116292" },
	{ "yespowerMGPC", // MagpieCoin genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000c925b94b786c237b25add6fc9d8b5aaccc641f3a3951a0b93baba12af0997c542c334a60f0ff0f1e071e0900",
	  "00000ad436508c04c3545a914bdb941310f1bdfa6d26877ec8e2964a1d781834" },
	{ "yespowerR16", // Yenten block 2200000, meets its target
	  "000000208e121b164248c7b6e59eef9a294dd6def092549e418b97499239438eda05c3128ca98435da280abb4aa8d2342fb8a8a731434b61ffc23e9550dd00658d6ba74740b6116aad1d011e213f3333",
	  "00000027a4fc66badfa63bc68a34f9c93eb1c2cdbe9a4cffcc2ac25375f3db30" },
	{ "yespowerSUGAR", // Sugarchain genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000b050e156acdac2cada87b39ce5f137f5b872901e6b9e1c1d41b09c572ace77767073555dffff3f1ff7000000",
	  "0031205acedcc69a9c18f79b84790179d68fb90588bedee6587ff701bdde04eb" },
	{ "yespowerTIDE", // Tidecoin block 2000000, meets its target
	  "000000200d6b220f491e0073eebaf8a90adf413a07bab12aaf52e1df46b259ec4487c42b60aadef295865efcb2bfe9ffcfa3aacb7782ff117d17be6c0c62de399151f34e5e34fb67948a081d8c180000",
	  "000000016d311f7e1109d806ae4deb76b1e470d8701f37327edd9ad3f6125543" },
	{ NULL, NULL, NULL }
};

// Vertcoin block 2686000 (sha256d 70ba0199...a320), nBits 1c0be894;
// verthash result checked to be below the target (36 zero bits)
static const char verthash_header[] =
	"000000200b0de86e752241c8f7cb517d3d6b36a51ea2b181492a16f4a02d0abb3705f6ad"
	"6ab2221872da74582f7513c9b2de733eb5b50c86acf936a37be2ba2de2e71a7fa5c2b46a"
	"94e80b1ce43faa00";
static const char verthash_hash_be[] =
	"0000000007e8dbfaab43d82179f0835cbd44907ab696e9e12be76f9682346542";

static YAAMP_HASH_FUNCTION find_algo(const char *name);

static void from_hex(const char *hex, unsigned char *bin, int len)
{
	for (int i = 0; i < len; i++) {
		unsigned int v;
		sscanf(hex + 2*i, "%02x", &v);
		bin[i] = (unsigned char) v;
	}
}

// bitcoin genesis block header (80 bytes)
static const char genesis_hex[] =
	"01000000"
	"0000000000000000000000000000000000000000000000000000000000000000"
	"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
	"29ab5f49" "ffff001d" "1dac2b7c";
static const char genesis_hash[] = // displayed (big endian) hash
	"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

// Known answer tests: 80-byte block headers (serialized, hex) and the expected PoW hash
// (displayed, big endian). "chain" vectors are real blocks whose hash was checked against
// the block target (the chain itself only stores the block id).
struct kat_vector {
	const char *name;
	YAAMP_HASH_FUNCTION hash;
	const char *header;
	const char *expected;
	const char *source;
};

static const struct kat_vector kat_vectors[] = {
	// Raptoreum mainnet block 1437000 (a4f85d05803cba9bcc17cbc68378b6c41b57b2cb4686dc5aef3ffcb056469668),
	// bits 1d0b1bcb; also checked on blocks 1, 5000, 250000, 800000, 1200000, 1436990
	{ "ghostrider", ghostrider_hash,
	  "00000020ec99747e276395fac51fa2fa06f7db4ba714c5d7de09f1e402b2201af97a81ea3eeee81e058f7ae783aa059eb57d8a633befcfa5202bf1cec2a59da30b8f4d9b2bcfb56acb1b0b1d62000700",
	  "000000049c87fbffb8a48536d82ded5c4d43e28ac85048eb08f137e0093c5a89", "RTM block 1437000" },
	// VKAX mainnet genesis (ef99ea0231cf5ccee64a5350f79d8b17348f9a72cc1899113c4082c9f6aa1987),
	// bits 20001fff, nonce 140 is the first nonce meeting the target
	{ "mike", mike_hash,
	  "0400000000000000000000000000000000000000000000000000000000000000000000003ce42dd41a0ead4764d88555bec2112f297d1319340c09b64a150713be0692c510f3a862ff1f00208c000000",
	  "001e00af492cad6158de291018e6a2674aa393d983cc9a28898e98c48d3e05c1", "VKAX genesis" },
	// Litecoin Cash mainnet block 4522303 (33045efb468ce515dc01b088df8dff36824f485d38cee0cbeeddd3fb0e708243),
	// MinotaurX block (nVersion 0x00010000), bits 1d3370ff
	{ "minotaurx", minotaurx_hash,
	  "00000100b95bc9244cac8ca986ecedc01bb64fe3988067ea44446503a4d3be02b2879e0d21be074001e6db4e298487aeab8bb1438d754a706d29f28fd3c64ed344f1dcba42fab56aff70331d372c55d1",
	  "00000009a63a77b3884a8e28c103efb5d263f7aa8b2de5364fbdd09fc84dfdae", "LCC block 4522303" },
	// no mainnet KCN/LCN header could be fetched: Kylacoin regtest block 115 accepted by
	// kylacoind (Kylacoin Core eeeeb47b), hash identical to Kylacoin Core's flex_hash()
	{ "flex", flex_hash,
	  "00800020b03d9892780e946e6eb5bd3ab9fc1d8177794ddbe8eb9328eb614863769d99d117dbc5be30a15f9df8730e3aa62e07e8f38edf19dc2757c31efac40bd23a3aba9d77b66affff7f20504f0000",
	  "00016053e4873256c467657a2aa4814d98050479b67c9568a4b374bc38035592", "KCN regtest block 115 / Kylacoin Core flex_hash" },
	// flex of the LCC header above, computed with Kylacoin Core's flex_hash()
	{ "flex", flex_hash,
	  "00000100b95bc9244cac8ca986ecedc01bb64fe3988067ea44446503a4d3be02b2879e0d21be074001e6db4e298487aeab8bb1438d754a706d29f28fd3c64ed344f1dcba42fab56aff70331d372c55d1",
	  "3f5f1b703df28379f41fb1e3121a6a3f72faf7869d16bb722e8ba94bed536571", "Kylacoin Core flex_hash" },
	{ NULL, NULL, NULL, NULL, NULL }
};

// Decred (DCP-0011): real mainnet 180-byte headers (dcrdata /api/block/<h>/header/raw).
// The block id is BLAKE-256 (14 rounds) of the header (exact, = block hash given by
// dcrdata); the proof of work hash is BLAKE3 of the header, exact values computed with
// dcrd's wire.BlockHeader.PowHashV2() and checked below the header nBits.
struct dcr_vector {
	const char *source;
	const char *header;
	const char *blockhash;
	const char *powhash;
};

static const struct dcr_vector dcr_vectors[] = {
	{ "DCR block 794368 (first BLAKE3 block)",
	  "0a000000f04e765c994d860e77afcd25ea4704965ed00974c6d893c20000000000000000609e379d61a43226fc875bf232c5406085109932"
	  "a13e3d226e1f6d0362772abe5ff6678090180b3534830a6daae8b02ccec81c628fca089907720ca15363838f01009f1e7b7d200705000b00"
	  "7d9f0000a6a5001b097f8c8205000000001f0c00cf7e00008af1ed64bd193281b6233e65040b01a000000000000000000000000000000000"
	  "00000000000000000a000000",
	  "071683030010299ab13f139df59dc98d637957b766e47f8da6dd5ac762f1e8c7",
	  "0000000000008346f98ac94f4c031d1b8544dd14566fcef233d40fbe3be7d1cc" },
	{ "DCR block 800000",
	  "0a000000845634a7f813fd81a63f035daa686ece8ab1d877f75ea072c4c2f5d0d6c1668b5b442bf92e1f8be2d1925b904327e5a4359a0cff"
	  "eaef994fe160bb2d8e11d2aa2287c96f5752bb19ac6c34f1bdb74cd33da0fcc6ce86af325242c7785bdc11db01007cd61ced0bfd05000000"
	  "919e000069c32f1af628072c0600000000350c00536a00006c7f066541e0e6a78e2b78b4d94fff304b000000000000000000000000000000"
	  "00000000000000000a000000",
	  "b06ef2f4796e90785ff950b202caae05adfc92f56f1ef6dc5829d09cf2aea433",
	  "0000000000002e77e2b03c9279ce04d342c946b1fabb18694d3f736a90d7f1f7" },
	{ "DCR block 1000000",
	  "0a0000000914d28a027a4e7dba7ff665319a5209e9422efbb73a6b5fc33f08c702e330d6f57af4012e77a7f06883dec8eccb94d4fdd26e91"
	  "00f0d414752e59a6bc1c98d4c2eac3ee2557a12c614b64bdba7c75e7cc001061fa57407d7205ef85eb57a00a010051a37db7f93f05000000"
	  "189f0000e40d131a0881f3a20500000040420f00338f000029289968e20e2443cf02fd1f3f0100ae00000000000000000000000000000000"
	  "00000000000000000a000000",
	  "b2b7e4e1b6ea5bf038d3cff04548c55d04ddba82ee940552ddbb6aa91be6ed22",
	  "0000000000000e534fd06e7a272ff5991ae09a43eadff3817caf136dfd5bf7e9" },
	{ NULL, NULL, NULL, NULL }
};

// official BLAKE3 test vectors (test_vectors.json: input byte i = i % 251, first 32 bytes of the hash)
static const struct { uint32_t len; const char *hash; } blake3_vectors[] = {
	{ 0,    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" },
	{ 1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7" },
	{ 1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444" },
	{ 0, NULL }
};

static void to_hex_be(const unsigned char *bin, int len, char *hex)
{
	for (int i = 0; i < len; i++)
		sprintf(hex + 2*i, "%02x", bin[len - 1 - i]);
}

static void to_hex(const unsigned char *bin, int len, char *hex)
{
	for (int i = 0; i < len; i++)
		sprintf(hex + 2*i, "%02x", bin[i]);
}

static YAAMP_HASH_FUNCTION find_algo(const char *name)
{
	for (int a = 0; algos[a].name; a++)
		if (!strcmp(algos[a].name, name)) return algos[a].hash;
	return NULL;
}

// returns the number of failures
static int run_kats(const char *only)
{
	unsigned char input[80];
	unsigned char output[64];
	char hex[129];
	int errors = 0;

	for (int k = 0; kats[k].algo; k++) {
		if (only && strcmp(only, kats[k].algo)) continue;
		YAAMP_HASH_FUNCTION fn = find_algo(kats[k].algo);
		from_hex(kats[k].header, input, 80);
		memset(output, 0, sizeof(output));
		fn((const char *) input, (char *) output, 80);
		to_hex_be(output, 32, hex);
		if (strcmp(hex, kats[k].hash)) {
			printf("FAIL %s KAT: %s\n", kats[k].algo, hex);
			errors++;
		} else {
			printf("OK   %s KAT\n", kats[k].algo);
		}
	}

	// verthash needs the 1.2 GB data file: VERTHASH_DATAFILE=/path ./hashtest
	const char *vh = getenv("VERTHASH_DATAFILE");
	if (only && strcmp(only, "verthash")) vh = NULL;
	if (vh && *vh) {
		char err[512];
		if (verthash_load_datafile(vh, 1, err, sizeof(err))) {
			printf("FAIL verthash data file: %s\n", err);
			errors++;
		} else {
			from_hex(verthash_header, input, 80);
			verthash_hash((const char *) input, (char *) output, 80);
			to_hex_be(output, 32, hex);
			if (strcmp(hex, verthash_hash_be)) {
				printf("FAIL verthash KAT: %s\n", hex);
				errors++;
			} else {
				printf("OK   verthash KAT\n");
			}
		}
	} else if (!only || !strcmp(only, "verthash")) {
		printf("SKIP verthash KAT (set VERTHASH_DATAFILE)\n");
	}

	return errors;
}


// ProgPoW family (kawpow stratum protocol): real 120 byte headers (80 bytes up to nHeight,
// nNonce64, mix_hash, as serialized). The mix hash is recomputed from the epoch light cache
// and compared with the one of the block, then the final (pow) hash with the expected one.
// Building the light cache of an epoch takes a few seconds.
struct progpow_kat {
	const char *algo;
	const char *header;
	const char *final;   // expected pow hash (displayed)
	bool check_mix;      // false: the block has no real mix hash (genesis), only the final hash is checked
	const char *source;
};

static const struct progpow_kat progpow_kats[] = {
	{ "kawpow", 
	  "000000305985e71a7421b997444ba853d289210025650f1612807f922f7500000000000027dd65621fab2ca7f4dcfd58f811b97ab9fcc9835817faf363caa49b61d2096325d81a6581a2001bc0c62d00cb9a4f31000000add4c22a736fcbc65c52abc1e1540680989793b94fd71d3f51cd8848935fdd349d",
	  "0000000000005201a0af104a92788105ebb3519ed2d5bb68625d8e89da8b32e4", true,
	  "RVN block 3000000, epoch 400 (= block hash)" },
	{ "firopow", 
	  "001000200e5d9b76b5f9a665feca86d18815f8b36b80d02280e468a55e27ae87caa56d552ad46e4432f1a24fdb7cccafbb4b39989c9069c21c316517e05450ad46e4d178814147677c4b601b40420f0043e03103c1fc8eaa4006ded037e8bee9a3dc73f876c922565e78f3c23c237c5cd79acb2a71376a6f",
	  "00000000005c903a34ec16172c6b3f82f2e473467dc3f74d8a4abd386d2bd02c", true,
	  "FIRO block 1000000 (d20e3730...a147), epoch 769" },
	{ "firopow", 
	  "00100020048bcda3be718f845f9730a996542ef84328be96db6b9901f6991a496c0393967a2ef94586d3cdf7046e894f75d1f66cc8b3a063531f4faeb7361f054e55e39d468bb56a5a80001c581a1500d81aa29c073f06bfa55662b7bf2ea4bf9de827ccd0269c197a8bd7e3fffd976061193756847d0605",
	  "00000000001bed0836b81ca3d82c8a92d0284d1ad70ca64db7fb1e4e6fc29d0d", true,
	  "FIRO block 1383000 (64159a62...9d98), epoch 1063 clamped to 650" },
	{ "meraki", 
	  "000000301676899cd9383285763bdf5333550d4a5062a6c27cbcb0aa72fed10700000000e5ad27bf37c7cf6ac21e19178e00627ec676b04191f81beedf90c309a5211c5b69d7b56a017d141c1813110051f4cb230020f17f97f89253640adbb026fcd14fd99114648a8c35562f9b4cd864a59eabd48ad983",
	  "0000000000346dfa0a16180390c5bff789896550d50831323b615e35e5bb8f80", true,
	  "TLS block 1119000 (= block hash), epoch 40" },
	{ "evrprogpow", 
	  "04000000000000000000000000000000000000000000000000000000000000000000000062929683d3ddfc68b5efa54fe8bef118a0b2951012b4ccfcf12a0db175c791c1ac805d63ffff001e00000000f41e1b00000000000000000000000000000000000000000000000000000000000000000000000000",
	  "0000007b11d0481b2420a7c656ef76775d54ab5b29ee7ea250bc768535693b05", false,
	  "EVR genesis (= hashGenesisBlock, null mix hash)" },
	{ NULL, NULL, NULL, false, NULL }
};

static int run_progpow_kats(const char *only)
{
	int errors = 0;
	for (int k = 0; progpow_kats[k].algo; k++) {
		const struct progpow_kat *t = &progpow_kats[k];
		if (only && strcmp(only, t->algo)) continue;
		const progpow_variant *v = progpow_find_variant(t->algo);
		unsigned char hdr[120], hh[32], hh_be[32], mix_be[32], mix[32], final[32];
		char hex[65];
		from_hex(t->header, hdr, 120);
		uint32_t height;
		uint64_t nonce;
		memcpy(&height, hdr + 76, 4);
		memcpy(&nonce, hdr + 80, 8);
		sha256_double_hash((const char *) hdr, (char *) hh, 80);
		for (int i = 0; i < 32; i++) {
			hh_be[i] = hh[31 - i];
			mix_be[i] = hdr[88 + 31 - i];
		}
		bool ok;
		if (t->check_mix) {
			ok = progpow_hash(v, (int) height, hh_be, nonce, mix, final) && !memcmp(mix, mix_be, 32);
		} else {
			progpow_hash_no_verify(v, (int) height, hh_be, nonce, mix_be, final);
			ok = true;
		}
		to_hex(final, 32, hex);
		ok = ok && !strcmp(hex, t->final);
		// the yiimp hash function of the algo gives the same (little endian) hash
		if (ok && t->check_mix) {
			unsigned char out[32];
			progpow_header_hash(v, (const char *) hdr, (char *) out, 120);
			to_hex_be(out, 32, hex);
			ok = !strcmp(hex, t->final);
		}
		if (!ok) {
			printf("FAIL %s KAT (%s): %s\n", t->algo, t->source, hex);
			errors++;
		} else {
			printf("OK   %s KAT (%s)\n", t->algo, t->source);
		}
	}
	return errors;
}

// Zcash family (equihash stratum protocol): real blocks, the 140 byte header, the compact
// size and the solution as serialized. The solution is verified with the parameters and the
// personalization of the coin and the block id (sha256d of the header and the solution) is
// compared with the one of the explorer/chainparams. The last entries must be rejected.
struct equihash_kat {
	const char *algo;
	int n, k;
	const char *pers;
	bool valid;
	const char *block;
	const char *hash;    // expected block hash (displayed)
	const char *source;
};

static const struct equihash_kat equihash_kats[] = {
	{ "equihash", 200, 9, "ZcashPoW", true,
	  "040000000000000000000000000000000000000000000000000000000000000000000000db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4000000000000000000000000000000000000000000000000000000000000000090041358ffff071f5712000000000000000000000000000000000000000000000000000000000000fd4005000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce157",
	  "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
	  "ZEC genesis (chainparams)" },
	{ "equihash", 200, 9, "ZcashPoW", true,
	  "0400000077f36aa43aeba34a284bdb6aeabf55b7035fd490589cf498ea2d5101000000005addfb1cac535809e025523319a1e3fe65228e837a19bfab0a1f0a250ea0d5a1d5834caa7ab34a6b3fa8dbd6d2277643654e4f1ee5216ddd4a6e03efab4ab9484dbb7f5fa2d0011c000000000000000000000000000000000000470000000000000000008003f82cfd40050051da0866d2c8b7cd1b61d00b6a04731efc5b46d314d4b746c75baf930234e31b34de8c6263ee79fc360368d4da72d5a6bfcecba8d4befdcc368adb9f0f8c03daf6726325494754537b5356dc0e32fc301df4551b457b82d069498f5e3186bc56ef0dee10d7fa3c4d5387339e75a127ef40cd77d3455e4589f8f2123113276bc210484f9f837d11a2d4671902192bdcb2ac3e38c89ac7b0943dc7faff05c3af74a1a5d1ffb7dd44006a0a4070c690d677a10202f0ef2bd1c87537c4a10566f1e41ed251f7fd398535a4336fb651ba7f0db103df834386e9deb972f5827beb997b7a5ca6da287c3260f3dd8d73a811acf85a0188fb5b33074cfd56c206a6bb84f2129b9cf01e687d47e8d2567dc8551631344cb4a33815a6cd5673d736f76b7de64a217f6fb0126263f46f1fc0e9efa9220791fd3598c88f921413236739282f231db92a8a33a21a3f1e1a701214cd2802e2c91a35ab40976a04913dc0f257850f23ef1ef1142e3e917a9058d72b0a9574e93c32ddc0d29c4a27121a642ad5cb16775cc0a28bd07015f5a89c128d802f033cfccc5c8f652773c9e92df4d1672d733d8fac08d98383a1f186bbbba078318e5f7902e40239bf2e1a47f208a1de92ffffc42250d63ffd40ece6edd88723082ab865ce7b76bd9bb242ae777802453d55cbd72914fdca2d103c9d5b2fd2d9a4d08840d54e1f3a89032d07fb7e16233b3732e071232ae1a2943017a10435628a4fb96fa39b970206b59ae8f24e31edb769140a801d31b048b3b9aa46a0cc6ff17d091ecd31fa361aff4cccebc7d2caf8780645fb58ad4e9f9dbfed0407e90adf8506be6dc8f1b37c993d834e240a778a77261dd3d18e1c07c547edc6f7e0f5902e2e225e320e107f855096d6ae85d3ba630e4028f11ac79b37ceb61686b6bce0884308e9a8d3d636d1fd81377173be3e013c1625eaf019d3baad42f7bf25086581a56d8e120c6b72cc4a5a7203cebf50d4a8f50ca1af4f951f4a0ce20783844982416d4d46f575f88582717a3cc2b86a81e3d0fd9b9c0dfb79a88beec7123a5c5d9f978503c63189620a112cf0734b11f8e8372b0ebf7c95ea3fc98ef4bed98c11313e08cb19eeced3cf05ffedee3c706b4f0cd42fc763b6a4c9f1568f360c9bbe6ba03e4c7450365942efd5b7171329632836b6f09d3b1301882bf9df7db09df41a902ca0c985e8d23706b18b0572d2f1c4d3afa96189a07db874aa40cd0cb0e234280dc571e9f6d33bf8e6f4504fbd8b4a66b35dd0965c818c828619583da5a066a9eaebeec5f645f4e66805bd74c9810c9c29724712ca091ac569b59d1d3e7d0988d0964fa5fd7df0d0f09eaa1a71cd8df53763db07a786b7ca5adf0ff519b3dd8b1f48ea4e4975a96422dc43207094e291d30f34a1307c7b91ca8bd53ef5020a1763e85a5107e0f5c64213c13923540c5d0e751bae76a3b68ab028b4817324385a1e1b0c837dc2c7021e2534bf93150b0220958ea7e5d1057dd4b359a127d67ad98a91814583c193fb6a44e82f3df09cd0400838104c5831973fc74a812d35def1704dccbd95772198bca9ef4c16f6bac912d7fe99bcae3969f6bc523549db00b555713eef0a2655343df25652d434388642140d3f32d3278dd7e6e5cbfcca192982320f1d0f03bad5a3f4c80e1c69123137add41fa776e39c708c0781a0f74e44baeb968be1a110308198951370d400111079e0e40b0d25a6a29231765316059fb0f904fa117dcb7c434d4f458bf021e68f4a27058074748565149a7c01036f9a8feac2e38d5960f033cb0c9f6ebb3a3e89d3745fa99de1a74469f6497559259b321dce294d0f9577cffc7af80bd2c40b4a0879cae4fcd68f70b4cf0eb69f9caf1786196d5053f4e2781d1e53a9",
	  "000000000062eff9ae053020017bfef24e521a2704c5ec9ead2a4608ac70fc7a",
	  "ZEC block 1000000 (Sapling)" },
	{ "equihash", 200, 9, "ZcashPoW", true,
	  "04000000f422b78a2e62950300c05b24a267558bf372c24fe0af8937a2d70001000000006ab2e58795bb275ffe1c7e2c828e9442dd8630f4f38db642a557c4638dceeb683f6bde387088b1735c99a573248144575614edf7d8dbc1d47746e3b6dc588264b1677c684101021c5049d1030000000000000000000000000000020000000000000000000007ab22fd400500096b3698c892636dd3420c9c3ec812acd41f4e09047a08b36083a2355ebfc36477e2fb02b2377ad3e9312f6b1597de2c35153157c9bed062be8ddfbaad308a10e4a3e6e2b825358fc91fdbf211167d051fb9ce0455bcbbc8638e8f9105f0c9da50571e8f36de19e3086f83a114dcab9de577275d07f7400b0ed69f734c099e1a569545c163894f32041b51788c815d8ec71a36834d7f906501a1800563d437acbcde08c812bded047cea72471d01d7486d80cd16b5414671ac1b89ad21503c9ea44bff5763beb55573ffab95679efe9c1c0f7c274a44365d23d0fc8150f92e2cfd65399dea751812c43ce5c73f16cf1b562460ef7e0e4039f573ff22ca9c83014baac51c3063a960d110d6ce48f6ade3316374501d15bcc7129d84635df7b735981bde723c3ef9d6beb413df7f9c57e41f885982ed9e12fa15fc502dff74c91a953b1f3816f96f7321767a317bf0c30021433cb6a5dff33ea7137a92e081d976885c8a6d2e7e2db679574f9ec2a2358d7355bc21e163913b1b0a62f198fc06b451ca8b05638cc3053e4dc5b78b2f10a28db483890c312781311dbeed819cd6648b54b708e8bfa251e0e5cb5eadc2f4cae54709cc4d9e0833478a9cc05ddb3b43029a2916d479746a654cd4e0ab0c6216f3dd8f6b41e793169b65f492fed6c5bf3dc36b6a0e83f561aef594543739aefd81465d8f7af470043c39212e2039c9a41693c01d3bd8d20eac9374f81b031404048fc2b1a893855bd0c851fd9ef7353d272dcc56060597a1ef0952d49d3a2dcb0248fffda9704352fe29d515c675ecb4e4de144537ae2ed2d19b9f0a83b7618172211f98f82309a33d7d4d9bfbae20d73f83f405175fbcc1b4bad4c31d63ee3580beed67ea0cbf4382e5a53399d6841133450bd5257ddbee824018966d045e86a16f530e923075b76a50b284b5c5d40069743bf104e9f741e9d46e35cc028d201d5756e8040a4f8bcf865d06ed6841426b18e0ba790318987c0702996fb887ef955df6d0d66efbca36e4b6ff9d953a0799ef0853129dec6da53e443f45117aeeb2114001c505f7c05056caad9e5229d7467fe93ab9b32c8611933d758f0a8334b3f3732fcf3b0e0d0e00585fa005111f2fbb462f3aea6d83642e2e0adef25cff5eab27438d73a2eb6d2d702627c2253fa8aa998838dafe01906079b78240294cbf705e781535626b2bfbb3730a33c53a96b36137cf143485f45c05a3f4319fcd4705ec0f0f5ee67b358c92f1deb2272b5503ad6e4bc128caad05898cf22bfd37e29ee929c4a9818f0e4120052c7c62e7f05cc7f9fe0357a35bd3bd4a6d9ed89c3f5a86b688683451e22047544ad70d99f58c95d6b80910fd43388eb1b3ed6154e31df4a661ff80f1d48a2022e9a0a14c5fe2dd68725fbb4cd3410062fff4ad026adf3ce453cd0fea7b204e6eb511be0b79b85f46182cb93750263a03eda052cf8ba5e4aed92b3e9fdf09602c2bb67b7f13fa4b109b891f33f0eaa5a9f0cb5a9a77641a620b993242e62e5b68d47f95cc1f55b61119d6f613625b218fc501b70e20691cf4686e0c3f4fc84348d6df1dfbc1a586bb0bc2479a4bc0f5bb95137a34e54d852b4b759ee749fc771e365329d40a72242dfb011564bb4fb3d243803a9d94e1bfa44f54c10952fc81b35fada95cd4f4f2c53258a9e898160af81a5a479916dbf48f591e628725396754d02fb31c211acbcfb839942ecf71e0b28137b301a1dc63162be41e3951326c6e0d49953742eaf9f0a9f198eb3600da097550a9259e48b97a63816cef3b4ae87d96354b2e16cbf46e6059921f6b92d5184e563d3dfdc4346c460a7f1e56e0dea751898002799e977ced9a6af9da5f15eb53975ee64d214c5a05d86c78fcb97c76396db2",
	  "0000000000573729e4db33678233e5dc0cc721c9c09977c64dcaa3f6344de8e9",
	  "ZEC block 3000000 (NU6, hashBlockCommitments)" },
	{ "equihash", 200, 9, "ZcashPoW", true,
	  "040000002ed12647808c0f246e1000e9429ee233ba970d18d1464db23a932903000000002bd0766a90e0c889604aedef5b565986ce708fb00fdc7b9aeb79d9397cb8e81ba2d8a734eb73a4dc734072dbfd12406f1e7121bfe0e3d6c10922495c44e5cc1c48138566b39e001d0c00f58198a46cb610190fbb31d944206bfaad76000000000000000000000000fd400500191e3e0b8e227684e40006e95ec2540b2a3f128f55e254ea52960b99ccd70985425bc572a83496b7a904dda88834274029d8662140b750f6ad56fad1f03711a3ce88a2a59357bcde47abdd5f3cd6b11a7a8020029d24f4ccc75dc7a363c1495059672cbf1dc9a5f00312e2625a8c9c00c201a1550af3445c991affe11f0d16164749e913a9f85c54775f32c0974211dc1b241bb2a5f2951812433c25e370265d0ee1020f98defd06bb51e1ee4fe2bd1c12a2f636d7d78dc646bab3531f09c8fa6ae04ba96e1cc23a97e24f0dadc2322fb9191ec4334a4fb2eca2a15821f77288ef1762fc257b207342e15d09f979e1a722ad672c90a9f86af3cd980b57426a44a82dcbeb3643bdff46ad6e1e0c1dd0873030c20ae34c908159052311c8198115ee6cb0f21c143a6b3b0d8c0378ed3b817ccc9627c0c869966c9c5b05b4a17deabab1d1a9670228f18aba0e547e749e00dcfc49d6c48f0dafd760e1896aab7215fb77385217c40a0e26273775ab0c7435dcb26619175ceb4953140cfdcfeea071f1e3451276737e258db49339c8c5185d27466957f08fe1fd71ce1f4d385d3c8a1840f50764b4f4da843c6fdd1d00bda315853ea8f69b998b086375e59d89d5fbfbf48228b925501951e87c3f3510776b59288c03ffd645e13f660fa3d8abc877e2e42427c67882588c6bbcc2e65776575d36cb221c155701651c405f1c62673da211680d36aab0967eb59b782646c2e16ae8d92f4995b2fa07a16bf0e35d1761850ce52509d56aaa7d840f0a1e266f5d36cee4fbd3c50d6cf35871923822e2f8b47573ca73df54a19f8b19022b05faacaf6b57ce4cc510463e62e5a05ad63b8e58616e828bd751a53bc2c64a0c371eddb5f11939be1174c4b7df6667fbc070220fd524af3f1bbf5ea3be14324c4c1cae8c95ac3ce7713a6c719a22b7b68df801d2ba57081cea1507bce16fb86adb592983396d6905192e84f39b624d498b2147dc6fdea96502d3f080150e8bbb0405757848c58531bec5eacdc73eb255b2178fffbab9d1cf559038717c3c7a1b319d674ed82a03f2b4c52f54a6cf10c140a04facd305273c9c2436100486ef2708c8851b7862bbd2edb21cd895b42a8a0d31c19ce50db566a775039777e91c391b4e5c09dc170ebe1acc08012249e396fc636bc83a0cd37c5d40027c1dc57fb2c01bc24264a5f74e647179b3b503d8435d9d8273d96d80e77c6592503ecc89bdcef9a64b1f26ef1801561c774708529dddac10ea3d047937553cafbac74292ace3ecd6b43c016abf0139094e895202e3d641eee7bfa79301915b8b4cf2f875806b8cbc14c84de39d957778ff36345264b8ba313f2eee16f613b2b9434ccbb3706bdac8ca1c74916288bcfb7eec184b7752e3ad709fdd20e3cfeaf76cb1a27331a742024a2ee490430ddcc3916178da25bc6a0f559e405c14051d0dc7ded6fb85bdd6ee727a57c272db37e4b616cc9644e0aa028f76cd82dc625958653b3e8a297440239fcb9e14d935e210f617ab4d1fa733ccfb57491c2d7e68c19e0e69a18e635331c68b23172bbf8f521c8563ada6523395b7d3e1e0691cf74599a4b50bb51e0cfafbb191200e91c0e36caf49f29d0c15ad50bc229e85dded788b01d95894a494a636c9a36376221909cb0eea569d8451aa6e718b5d58229dd5c8fb2c8b357856060cd51bd6ad42c4db1cc70cbe4851d2fde31196e9edf688c64efd36c39798612cf9d917d44b6e1237ac41b786eb10e2300bdc02ea95871a333c9ac8133b86788bc74ddf99dce16601b09671f4651971711dda2481bc18427f176df76679c91fc6192c75a17f15f81a96b28eaaad896ae17e7fbd6c3211a67c1f121721ab25a0898d31b8d7c1abd6fe50cdf7c27ee2ca",
	  "0e838a1c45de349d3a91f7c88be2bbdebdb4fb6b358216e47ece2694d8373b63",
	  "KMD block 4000000" },
	{ "equihash", 200, 9, "ZcashPoW", true,
	  "04000000963dbc4dae938a38f6dd8ee8ad9090819a8d7859035fa0cac7021f9205000000ccb3bedb38ec291ebeb90ae499f3087787e6f1f539034354003ef23163fe9691fb2a18d96b69bed896e845d3e81429ef8000fbcf8467945f4a2d745fae2f6c1ecf12896a9c95221d8001b304000000000000000000000000000002000000000000000000000e22d1fd4005000538e356de980364ec5271616234e604eb7daf700e97f64cae9468bd07f56510e259f1536205fc607c1e75e4b6eaa2c8ad5de5f282485b55f9ba3dfe2d2047b7346a545b39db9fcfc6cd02eb79b67df7ddcd0b03582947cd8a9b6e948d1928237de59b68f07f66b82747aab551d902fbb3006808f065e3ca1b40f4dc8c097aff6872f48279d2e4876ce1d303f1ebaa391dca0a89da89d1c62897e4a1e7fce6ec652e3f1314bd38010c19633811e7fb458043e90826768e39859b1bff081813a082dc724d754193e91ab1ea11fd3af17b3a04e359d88f6b2897f5b68359d13eb466a445d5e6b00ef1aaa9de9859b34d5602f1f4e4d2f3065298e4cf17be599a14c83c9599b1b251494306adb1826e44953dab82618cd9f457a83029c9ed61152ec66059f93f22d62a11404bf71539cd149792695d656d55982cce71053dfdf32443a7beece7320b71f6fedc9cfd04630139f508d18bf12a72a8d3ac7ec3b805278cf5ae8b041065dd1392bffb0d83a6df5fcd6731ea3bf12e410863e85b17542af1ac4df6c98bdc350f3fc39c69cb39b5b5a9cb70c1df8f6249ac0d75ed9e6e923df43e06aad5de4c2e598dbf96013ea69eb8df0cf9be175a2d10878d299fcaa97e3a43a7d8bfe7ba29fbfa027916f11aed84f46c13c0d078b3066c44b7ca79bf7f5723078fb80596e0c9850252feedd88dc6ffca5a6cd20223bdcdd6aa5263d61717f127605b5ad8dbfe5a921e0f9f27749de837ff2072116bca46728fcc7edefc04a8752c23273d21ac5523e5734d6fc119bcb704c12aedac2cd633a565fb99d3af27239ba1cb8e3be54c12749186035d54c748de371b215867f62bfb3b56e63d3b4dcaeeaa27b78f8f778d2b59a8b2679599e14c2575628e55e35d5bb9a41bf51c6b006f1defbbde843d5a6ce7c327ddcfb645248feafa11ed86debb218f00e2832d394dc8cd079432c5f6788e35a7ad9da92b096a9f11100490195127c3485e5e81499099f10a43010f0d8269c5a0a63eb5f5fb5cce9a464ffa3b6fba1dab9dbda2d278a4c521c465b2ac1616895f759322036328dc510f4d43ff6d082dd6cf725223403e05b8683eaf2e6e1cea02eb7c4848f65cecb6e81b7abdda04ad852ed98ba4d36f4ce096e6ff42d63f46d90bbe4067fa3a3a12fe49ad56c4b0e8fa6c2dc28454106803f4a10b622cd69fba6065e5c3bf33a99d48ffab9413c7f3db530bb2e7142aa1d58b2025018b18b39a4a0694cc7f1b106a76c33c1119fe2f4ed71d311b31fe0d0fa3026fd8a1e3749b35f9d5ddfb6dc7ab4f6a930531d8b653487b6ca57d621b657068ac994e1124bf0ce94c3a96c58492f1621357c1356a525cc2bdffc411ea7e73e744b1af976f02c4e2ad749971d33addec1321e65325d6e40558f9fb859769ffab3b415fc53f056d710a22e788b3f10501d8286664628be675f0093fba426013e0cc739750f410855ac8f65cac9ba3a228341525558faa67141294919ea97f36613c5b7a733023be849f14b833f58b440fb450c37d4bbc54d35a0cb9e300db21cab3efbc016a20fa080a0f24f242963448676bcaefe3b7cae553d7112f126b3a783c23bf0fed2febd8657a99e5e8d21b19333b5a69a734ab12166e5d022acaeacd5e5b62f5f7b806716eafb577ba0bf4ddb7638f430f9e73f1aca0b95bdad27b9fdc6315e2c4b93f46f63955c2c44e8a5f7705e11f9815e01847accde496165ef45a1235bb69882913e57ae7042deee5d6af1361f51d9817096b713ab2ca027e57d417c43e0e11b30153fb7cf39d33a4f28a0bcff63b962ce6bc00902f6735941324e41938f137622e5ea91b45bb026c1123689ffce4347a9e2888b541d02f543b4c97e269c2d7ac2baed795b02aad9e9a4d723506fc",
	  "0000001e89783c338d6c0eeeda102388f4922efdf8793ccc0d5c4834fe301154",
	  "ARRR block 4100000" },
	{ "equihash192", 192, 7, "ZcashPoW", true,
	  "04000000e5b5d64e16fd6bcae67b27977ff487dfccbac6eee1d678e3c894a3131800000063e984332ac97f7cf69e09e6c71360984ba41629669c735957730a2013ddb020a762e8f3272a69a588e35f2461d868a4ec3ba171ff8c4893292552a34044c12da20cb36ab5950b1e8000027f920dfad1a04ce63d16b04316c3d68e300000000000000000aa18768afd900100b66a8b1163139e4253a59244a3f11e42c8f176cd6534b16b3aa228af2e042d1ba6fc5123a8efab3ea6efb67cc049db18db01b298466abb1f631c7a9a58374a9d0c6a2af21305d92a015910caf09054989a210536de1e95f4cdc5d8463195cd58e31ef00250ae4b36271f3551f5b77de2026672eb58991547fd03164a4068adf041de1194bb90100837a4d60c19bccab9432d6358ec1cc7b25054e4e487ecb5b2856442d925e39eea54ec357628e11ea083e9ea24ce8cf2f2dc28f9e2f5275c67b6c68ecbf15b8311b885949a389ed96bfc680ca86ac4fda087c719ad39a143b51b18e97370d5689407dde9d1f75b6486df410df3bedded8f58263dd9679633901027fee7948300b8ec112ee0d82adf07605a27bf937b932e5dc908fe303c36297395abef6f167151dd046d11e03ee5470893b8800caa317713baf47f8625e8ec13618b92223ab44808b4a43508ffafaef31d591ef62f551b4679088142192760950ec38f6518793af61718b78fcd1139da08afb7e55725e70d5a1b480d4d247f50b773a4ca5c4ca581fac203dab856",
	  "000004c14c35808d565fedc7d1f5cc0664e81892dbac8b2bd414f0826a9e5d8e",
	  "ZCL block 3260000" },
	{ "equihash144", 144, 5, "BgoldPoW", true,
	  "000000203ac0d5dfc5a227127295b729043bed0810657f8bd046b7c23edaab6700000000628f966f19287f4e21544fb759b5f79a0c850032352d0b24845c6054fe4bd3eb00350c00000000000000000000000000000000000000000000000000000000009225b864e1b1011da26fea08379bafe22e940d87670a26f41ba72ad20000000000000000f18ccb2664003889b22a879c9eec171ddb5354a091fa1d8535d7dec05974008a148e9310884d6eb98d3710b6dcae97dcf321fb79a7be68172258b2baae51126fae7a87d2a5c0ab4c1a4cae683a94ea9019afbfdd54ffe709e056b3ad069707255a61fda5d9e7972716",
	  "00000001246592f8ab46f3fbd9ea9ff859b302457472212516639283792dcc30",
	  "BTG block 800000" },
	{ "equihash144", 144, 5, "BgoldPoW", true,
	  "000000200a9de9620faac742a8bcf555a34c5f7cfc738fb395fb51aac8978fac13000000702771fa7f708751795c3a34d0033d0ef0085f7836fb9130578c3d4658a70cea00a60e00000000000000000000000000000000000000000000000000000000008a027e6aaa69611d0000000121052b000000000000000000000000000000000000000000f9bda1026403138bcd38bb8c6d9e77caeb80fa45271296b1f40bb938fe2d146273d822b155895f1d0ca3a3a814ad2e56ea580c91b6a45e0bb06a14bd9c72791db9fa1b70efc71acdac5cbb58a9971d9f1580eea422485765c08c409db4d12ee74720ce2eb9bfee6fba",
	  "0000005ad4aa251a388188c136818f0495a1adcbdfd74ba40d8c76e4f46d21e5",
	  "BTG block 960000" },
	{ "equihash", 48, 5, "ZcashPoW", true,
	  "040000000000000000000000000000000000000000000000000000000000000000000000db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac40000000000000000000000000000000000000000000000000000000000000000dae5494d0f0f0f2009000000000000000000000000000000000000000000000000000000000000002401936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3",
	  "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327",
	  "ZEC regtest genesis (48,5)" },
	{ "equihash", 200, 9, "BgoldPoW", false,
	  "04000000f422b78a2e62950300c05b24a267558bf372c24fe0af8937a2d70001000000006ab2e58795bb275ffe1c7e2c828e9442dd8630f4f38db642a557c4638dceeb683f6bde387088b1735c99a573248144575614edf7d8dbc1d47746e3b6dc588264b1677c684101021c5049d1030000000000000000000000000000020000000000000000000007ab22fd400500096b3698c892636dd3420c9c3ec812acd41f4e09047a08b36083a2355ebfc36477e2fb02b2377ad3e9312f6b1597de2c35153157c9bed062be8ddfbaad308a10e4a3e6e2b825358fc91fdbf211167d051fb9ce0455bcbbc8638e8f9105f0c9da50571e8f36de19e3086f83a114dcab9de577275d07f7400b0ed69f734c099e1a569545c163894f32041b51788c815d8ec71a36834d7f906501a1800563d437acbcde08c812bded047cea72471d01d7486d80cd16b5414671ac1b89ad21503c9ea44bff5763beb55573ffab95679efe9c1c0f7c274a44365d23d0fc8150f92e2cfd65399dea751812c43ce5c73f16cf1b562460ef7e0e4039f573ff22ca9c83014baac51c3063a960d110d6ce48f6ade3316374501d15bcc7129d84635df7b735981bde723c3ef9d6beb413df7f9c57e41f885982ed9e12fa15fc502dff74c91a953b1f3816f96f7321767a317bf0c30021433cb6a5dff33ea7137a92e081d976885c8a6d2e7e2db679574f9ec2a2358d7355bc21e163913b1b0a62f198fc06b451ca8b05638cc3053e4dc5b78b2f10a28db483890c312781311dbeed819cd6648b54b708e8bfa251e0e5cb5eadc2f4cae54709cc4d9e0833478a9cc05ddb3b43029a2916d479746a654cd4e0ab0c6216f3dd8f6b41e793169b65f492fed6c5bf3dc36b6a0e83f561aef594543739aefd81465d8f7af470043c39212e2039c9a41693c01d3bd8d20eac9374f81b031404048fc2b1a893855bd0c851fd9ef7353d272dcc56060597a1ef0952d49d3a2dcb0248fffda9704352fe29d515c675ecb4e4de144537ae2ed2d19b9f0a83b7618172211f98f82309a33d7d4d9bfbae20d73f83f405175fbcc1b4bad4c31d63ee3580beed67ea0cbf4382e5a53399d6841133450bd5257ddbee824018966d045e86a16f530e923075b76a50b284b5c5d40069743bf104e9f741e9d46e35cc028d201d5756e8040a4f8bcf865d06ed6841426b18e0ba790318987c0702996fb887ef955df6d0d66efbca36e4b6ff9d953a0799ef0853129dec6da53e443f45117aeeb2114001c505f7c05056caad9e5229d7467fe93ab9b32c8611933d758f0a8334b3f3732fcf3b0e0d0e00585fa005111f2fbb462f3aea6d83642e2e0adef25cff5eab27438d73a2eb6d2d702627c2253fa8aa998838dafe01906079b78240294cbf705e781535626b2bfbb3730a33c53a96b36137cf143485f45c05a3f4319fcd4705ec0f0f5ee67b358c92f1deb2272b5503ad6e4bc128caad05898cf22bfd37e29ee929c4a9818f0e4120052c7c62e7f05cc7f9fe0357a35bd3bd4a6d9ed89c3f5a86b688683451e22047544ad70d99f58c95d6b80910fd43388eb1b3ed6154e31df4a661ff80f1d48a2022e9a0a14c5fe2dd68725fbb4cd3410062fff4ad026adf3ce453cd0fea7b204e6eb511be0b79b85f46182cb93750263a03eda052cf8ba5e4aed92b3e9fdf09602c2bb67b7f13fa4b109b891f33f0eaa5a9f0cb5a9a77641a620b993242e62e5b68d47f95cc1f55b61119d6f613625b218fc501b70e20691cf4686e0c3f4fc84348d6df1dfbc1a586bb0bc2479a4bc0f5bb95137a34e54d852b4b759ee749fc771e365329d40a72242dfb011564bb4fb3d243803a9d94e1bfa44f54c10952fc81b35fada95cd4f4f2c53258a9e898160af81a5a479916dbf48f591e628725396754d02fb31c211acbcfb839942ecf71e0b28137b301a1dc63162be41e3951326c6e0d49953742eaf9f0a9f198eb3600da097550a9259e48b97a63816cef3b4ae87d96354b2e16cbf46e6059921f6b92d5184e563d3dfdc4346c460a7f1e56e0dea751898002799e977ced9a6af9da5f15eb53975ee64d214c5a05d86c78fcb97c76396db2",
	  NULL,
	  "ZEC block 3000000, wrong personalization" },
	{ "equihash", 200, 9, "ZcashPoW", false,
	  "04000000f422b78a2e62950300c05b24a267558bf372c24fe0af8937a2d70001000000006ab2e58795bb275ffe1c7e2c828e9442dd8630f4f38db642a557c4638dceeb683f6bde387088b1735c99a573248144575614edf7d8dbc1d47746e3b6dc588264b1677c684101021c5049d1030000000000000000000000000000020000000000000000000007ab22fd400500096b3698c892636dd3420c9c3ec812acd41f4e09047a08b36083a2355ebfc36477e2fb02b2377ad3e9312f6b1597de2c35153157c9bed062be8ddfbaad308a10e4a3e6e2b825358fc91fdbf211167d051fb9ce0455bcbbc8638e8f9105f0c9da50571e8f36de19e3086f83a114dcab9de577275d07f7400b0ed69f734c099e1a569545c163894f32041b51788c815d8ec71a36834d7f906501a1800563d437acbcde08c812bded047cea72471d01d7486d80cd16b5414671ac1b89ad21503c9ea44bff5763beb55573ffab95679efe9c1c0f7c274a44365d23d0fc8150f92e2cfd65399dea751812c43ce5c73f16cf1b562460ef7e0e4039f573ff22ca9c83014baac51c3063a960d110d6ce48f6ade3316374501d15bcc7129d84635df7b735981bde723c3ef9d6beb413df7f9c57e41f885982ed9e12fa15fc502dff74c91a953b1f3816f96f7321767a317bf0c30021433cb6a5dff33ea7137a92e081d976885c8a6d2e7e2db679574f9ec2a2358d7355bc21e163913b1b0a62f198fc06b451ca8b05638cc3053e4dc5b78b2f10a28db483890c312781311dbeed819cd6648b54b708e8bfa251e0e5cb5eadc2f4cae54709cc4d9e0833478a9cc05ddb3b43029a2916d479746a654cd4e0ab0c6216f3dd8f6b41e793169b65f492fed6c5bf3dc36b6a0e83f561aef594543739aefd81465d8f7af470043c39212e2039c9a41693c01d3bd8d20eac9374f81b031404048fc2b1a893855bd0c851fd9ef7353d272dcc56060597a1ef0952d49d3a2dcb0248fffda9704352fe29d515c675ecb4e4de144537ae2ed2d19b9f0a83b7618172211f98f82309a33d7d4d9bfbae20d73f83f405175fbcc1b4bad4c31d63ee3580beed67ea0cbf4382e5a53399d6841133450bd5257ddbee824018966d045e86a16f530e923075b76a50b284b5c5d40069743bf104e9f741e9d46e35cc028d201d5756e8040a4f8bcf865d16ed6841426b18e0ba790318987c0702996fb887ef955df6d0d66efbca36e4b6ff9d953a0799ef0853129dec6da53e443f45117aeeb2114001c505f7c05056caad9e5229d7467fe93ab9b32c8611933d758f0a8334b3f3732fcf3b0e0d0e00585fa005111f2fbb462f3aea6d83642e2e0adef25cff5eab27438d73a2eb6d2d702627c2253fa8aa998838dafe01906079b78240294cbf705e781535626b2bfbb3730a33c53a96b36137cf143485f45c05a3f4319fcd4705ec0f0f5ee67b358c92f1deb2272b5503ad6e4bc128caad05898cf22bfd37e29ee929c4a9818f0e4120052c7c62e7f05cc7f9fe0357a35bd3bd4a6d9ed89c3f5a86b688683451e22047544ad70d99f58c95d6b80910fd43388eb1b3ed6154e31df4a661ff80f1d48a2022e9a0a14c5fe2dd68725fbb4cd3410062fff4ad026adf3ce453cd0fea7b204e6eb511be0b79b85f46182cb93750263a03eda052cf8ba5e4aed92b3e9fdf09602c2bb67b7f13fa4b109b891f33f0eaa5a9f0cb5a9a77641a620b993242e62e5b68d47f95cc1f55b61119d6f613625b218fc501b70e20691cf4686e0c3f4fc84348d6df1dfbc1a586bb0bc2479a4bc0f5bb95137a34e54d852b4b759ee749fc771e365329d40a72242dfb011564bb4fb3d243803a9d94e1bfa44f54c10952fc81b35fada95cd4f4f2c53258a9e898160af81a5a479916dbf48f591e628725396754d02fb31c211acbcfb839942ecf71e0b28137b301a1dc63162be41e3951326c6e0d49953742eaf9f0a9f198eb3600da097550a9259e48b97a63816cef3b4ae87d96354b2e16cbf46e6059921f6b92d5184e563d3dfdc4346c460a7f1e56e0dea751898002799e977ced9a6af9da5f15eb53975ee64d214c5a05d86c78fcb97c76396db2",
	  NULL,
	  "ZEC block 3000000, one solution bit changed" },
	{ "equihash", 48, 5, "ZcashPoW", false,
	  "040000000000000000000000000000000000000000000000000000000000000000000000db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac40000000000000000000000000000000000000000000000000000000000000000dae5494d0f0f0f200900000000000000000000000000000000000000000000000000000000000000242680eb7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3",
	  NULL,
	  "ZEC regtest genesis, first two indices swapped (ordering)" },
	{ NULL, 0, 0, NULL, false, NULL, NULL, NULL }
};

// Resistance genesis (chainparams.cpp): 140 byte header, yespower pow hash and sha256d block id
static const char res_genesis[] =
	"0400000000000000000000000000000000000000000000000000000000000000000000009a9a946a268da67cff783124e547f1887ca80b636427180e8fa2ede016cb9677"
	"0000000000000000000000000000000000000000000000000000000000000000e1f53e5dffff071f3263000000000000000000000000000000000000000000000000000000000000";

static int run_equihash_kats(const char *only)
{
	int errors = 0;
	for (int k = 0; equihash_kats[k].algo; k++) {
		const struct equihash_kat *t = &equihash_kats[k];
		if (only && strcmp(only, t->algo)) continue;
		int len = (int) strlen(t->block) / 2;
		unsigned char *blk = (unsigned char *) malloc(len);
		from_hex(t->block, blk, len);
		size_t sol_size = equihash_solution_size(t->n, t->k);
		int prefix = sol_size < 253 ? 1 : 3;
		bool ok = (size_t) len == 140 + prefix + sol_size;
		ok = ok && equihash_verify(t->n, t->k, t->pers, blk, 140, blk + 140 + prefix, sol_size);
		char hex[65] = "";
		if (ok && t->hash) {
			unsigned char h[32];
			sha256_double_hash((const char *) blk, (char *) h, len);
			to_hex_be(h, 32, hex);
			ok = !strcmp(hex, t->hash);
		}
		free(blk);
		if (ok != t->valid) {
			printf("FAIL %s KAT (%d,%d %s, %s) %s\n", t->algo, t->n, t->k, t->pers, t->source, hex);
			errors++;
		} else {
			printf("OK   %s KAT (%d,%d %s, %s)%s\n", t->algo, t->n, t->k, t->pers, t->source,
				t->valid ? "" : ": rejected");
		}
	}

	if (!only || !strcmp(only, "yespowerRES")) {
		unsigned char hdr[140], out[32];
		char hex[65];
		from_hex(res_genesis, hdr, 140);
		yespowerRES_hash((const char *) hdr, (char *) out, 140);
		to_hex_be(out, 32, hex);
		bool ok = !strcmp(hex, "000242261b14bd5271d49f7549bc258ef4dc01b3b9d559efd641918c2fcbab76");
		sha256_double_hash((const char *) hdr, (char *) out, 140);
		char id[65];
		to_hex_be(out, 32, id);
		ok = ok && !strcmp(id, "328ab5de52cf3b7c1a5dbd02909b7e23a25d1715143c8b41aba903cf2b48754f");
		if (!ok) {
			printf("FAIL yespowerRES KAT (RES genesis): %s %s\n", hex, id);
			errors++;
		} else {
			printf("OK   yespowerRES KAT (RES genesis, pow hash and block id)\n");
		}
	}
	return errors;
}

int main(int argc, char **argv)
{
	unsigned char input[256];
	unsigned char output[256];
	char hex[513];
	int errors = 0;

	memset(input, 0, sizeof(input));
	for (int i = 0; i < 80; i++) {
		unsigned int v;
		sscanf(genesis_hex + 2*i, "%02x", &v);
		input[i] = (unsigned char) v;
	}

	memset(output, 0, sizeof(output));
	sha256_double_hash((const char *) input, (char *) output, 80);
	to_hex_be(output, 32, hex);
	if (strcmp(hex, genesis_hash)) {
		printf("FAIL sha256d genesis: %s\n", hex);
		errors++;
	} else {
		printf("OK   sha256d genesis\n");
	}

	errors += run_kats(argc > 1 ? argv[1] : NULL);
	errors += run_progpow_kats(argc > 1 ? argv[1] : NULL);
	errors += run_equihash_kats(argc > 1 ? argv[1] : NULL);
	for (int k = 0; kat_vectors[k].name; k++) {
		unsigned char hdr[80];
		if (argc > 1 && strcmp(argv[1], kat_vectors[k].name)) continue;
		for (int i = 0; i < 80; i++) {
			unsigned int v;
			sscanf(kat_vectors[k].header + 2*i, "%02x", &v);
			hdr[i] = (unsigned char) v;
		}
		memset(output, 0, sizeof(output));
		kat_vectors[k].hash((const char *) hdr, (char *) output, 80);
		to_hex_be(output, 32, hex);
		if (strcmp(hex, kat_vectors[k].expected)) {
			printf("FAIL %s KAT (%s): %s\n", kat_vectors[k].name, kat_vectors[k].source, hex);
			errors++;
		} else {
			printf("OK   %s KAT (%s)\n", kat_vectors[k].name, kat_vectors[k].source);
		}
	}

	if (argc < 2 || !strcmp(argv[1], "blake3")) {
		for (int k = 0; blake3_vectors[k].hash; k++) {
			unsigned char buf[1025];
			for (uint32_t i = 0; i < blake3_vectors[k].len; i++) buf[i] = (unsigned char) (i % 251);
			memset(output, 0, sizeof(output));
			blake3_hash((const char *) buf, (char *) output, blake3_vectors[k].len);
			to_hex(output, 32, hex);
			if (strcmp(hex, blake3_vectors[k].hash)) {
				printf("FAIL blake3 KAT (official vector, len %u): %s\n", blake3_vectors[k].len, hex);
				errors++;
			} else {
				printf("OK   blake3 KAT (official vector, len %u)\n", blake3_vectors[k].len);
			}
		}
	}

	for (int k = 0; dcr_vectors[k].source; k++) {
		unsigned char hdr[180];
		if (argc > 1 && strcmp(argv[1], "decred")) continue;
		from_hex(dcr_vectors[k].header, hdr, 180);
		uint32_t nbits = hdr[116] | (hdr[117] << 8) | (hdr[118] << 16) | ((uint32_t) hdr[119] << 24);
		// target as a 64-hex string (big endian) to compare with the displayed hash
		char target[65];
		memset(target, '0', 64); target[64] = 0;
		int nbytes = nbits >> 24;
		char mant[7];
		sprintf(mant, "%06x", nbits & 0xffffff);
		memcpy(target + 64 - 2*nbytes, mant, 6);

		memset(output, 0, sizeof(output));
		decred_block_hash((const char *) hdr, (char *) output, 180);
		to_hex_be(output, 32, hex);
		bool ok = !strcmp(hex, dcr_vectors[k].blockhash);
		if (!ok) printf("FAIL decred block id (%s): %s\n", dcr_vectors[k].source, hex);

		memset(output, 0, sizeof(output));
		decred_hash((const char *) hdr, (char *) output, 180);
		to_hex_be(output, 32, hex);
		if (strcmp(hex, dcr_vectors[k].powhash) || strcmp(hex, target) >= 0) {
			printf("FAIL decred KAT (%s): %s, target %s\n", dcr_vectors[k].source, hex, target);
			ok = false;
		}
		if (ok) printf("OK   decred KAT (%s)\n", dcr_vectors[k].source);
		else errors++;
	}

	// extend the header with a pattern for the algos using longer headers
	for (int i = 80; i < (int) sizeof(input); i++)
		input[i] = (unsigned char) (i * 7);

	for (int a = 0; algos[a].name; a++) {
		const char *name = algos[a].name;
		if (argc > 1 && strcmp(argv[1], name)) continue;
		uint32_t len = 80;
		if (!strcmp(name, "decred")) len = 180;
		else if (!strcmp(name, "lbry")) len = 112;

		// sph_blake256 keeps its round count in a global (blakecoin sets 8): start
		// every algo from the default 14 rounds, like in its own stratum process
		sph_blake256_set_rounds(14);
		memset(output, 0, sizeof(output));
		algos[a].hash((const char *) input, (char *) output, len);
		to_hex(output, 32, hex);
		printf("%-14s %s\n", name, hex);
	}

	return errors ? 1 : 0;
}
