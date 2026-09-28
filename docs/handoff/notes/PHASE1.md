# Phase 1: new algorithms in the YiiMP stratum — shared spec

Repo: the owner's fork github.com/mygiglifeinc-glitch/yiimp (default branch `next`). GPL-3 project, so reference code
under MIT/BSD/ISC/Apache/CC0/GPL-3-compatible licenses may be imported; keep original copyright headers and note the
source (repo + commit) in a comment at the top of each imported file.

Public GitHub repos can be cloned READ-ONLY for reference (git clone --depth 1 https://github.com/<owner>/<repo>
/tmp/claude-0/-home-user/940fe17f-d697-51b7-8fd2-02f52b656791/scratchpad/ref/<repo>) — the session's git proxy serves
anonymous reads of public repos. Never push anywhere except your own branch of the fork.
Research notes with exact algorithm parameters and sources:
/tmp/claude-0/-home-user/940fe17f-d697-51b7-8fd2-02f52b656791/scratchpad/algo_research.md (read sections 1 and 3).

## How an algo is wired into the stratum (do all of these)
1. hash implementation under stratum/algos/ (C or C++), function signature `void <name>_hash(const char* input, char* output, uint32_t len)`
   (look at existing ones, e.g. algos/x25x.c, algos/yespower/). Add objects to stratum/algos/makefile (or the sub-makefile).
2. `#include` in stratum/stratum.h and an entry in `g_algos[]` in stratum/stratum.cpp: {"name", hashfn, diff_multiplier,
   merkle_func?, ...} — copy the conventions of similar algos (e.g. yespower family uses 0x10000 multiplier, so miners'
   difficulty matches other pools: check what zpool/cpuminer-opt use for each algo and match the de-facto convention;
   the research file lists zpool "mbtc factor"/difficulty info where known).
3. stratum/config.sample/<name>.conf (copy x25x.conf; set `algo = <name>`, the port below, a sensible `difficulty`).
4. stratum/hashtest.cpp: add the algo. Where possible add a REAL known-answer test: take a mainnet block header
   (genesis or any block, fetched from the coin's source/chainparams or a public block explorer) and assert the pow hash
   matches. List which algos have a verified KAT and which only have "hash is deterministic" coverage.
5. Do NOT edit web/ (the lead integrates web/yaamp/core/functions/yaamp.php). Instead, at the end report for each algo:
   port, stratum diff multiplier, suggested web `yaamp_algo_mBTC_factor` (hashrate unit: 1 for MH/s-class algos,
   1000 for GH/s, 0.001 for kH/s CPU algos etc. — match what the existing similar algos use in
   web/yaamp/core/functions/yaamp.php), a color hex, and coins/tickers.
6. Build must stay clean: `make -C blocknotify && make -C stratum -j8 && make -C stratum hashtest && ./stratum/hashtest`
   with gcc 13 (and gcc-14 if installed). Don't commit build artifacts.
7. Commit in logical commits on your branch. Every commit message ends with exactly:
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   Claude-Session: https://claude.ai/code/session_01PuCJWisqxCymEgkURmDpuA
   Do NOT push. Don't touch other worktrees/repos.

## Ports (fixed — use exactly these)
yescrypt 6233, yescryptR8 6353, yescryptR16 6333, yescryptR32 6343,
yespowerR16 6236, yespowerTIDE 9101, yespowerSUGAR 9102, yespowerADVC 9103, yespowerLTNCG 9104, yespowerMGPC 9105,
yespowerARWN 9106, yespowerRES 9107, yespowerIC 9108, yespowerLITB 9109, cpupower 9110, power2b 9111,
sha512256d 9201, sha3-256t 9202, verthash 9203,
ghostrider 9301, mike 9302, minotaurx 9303, flex 9304.
extra ports: bmw 9401 whirlcoin 9402 whirlpoolx 9403 x17r 9404 yespowerurx 9405 (lead)
