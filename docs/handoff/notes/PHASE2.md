# Phase 2: new stratum protocols in YiiMP — shared rules

Repo: owner's fork github.com/mygiglifeinc-glitch/yiimp (GPL-3). Base: branch claude/multipool-installer-update-s3rama
(Phase 1: 121 algos, MWEB, per-algo version rules, Raptoreum coinbase). Each agent works in its own git worktree/branch.

- Reference code: public GitHub repos can be cloned read-only (git clone --depth 1 https://github.com/<o>/<r>
  /tmp/claude-0/-home-user/940fe17f-d697-51b7-8fd2-02f52b656791/scratchpad/ref/<name>). Import only MIT/BSD/ISC/Apache-2.0/
  CC0/GPL-3-compatible code; keep copyright headers; note repo+commit at the top of imported files.
- The DB contract must stay the same (tables accounts, workers, shares, blocks, stratums, coins) so the web front end,
  payouts and blocknotify keep working. Share/difficulty accounting must be consistent with how the web computes hashrate
  (look at share.cpp and web/yaamp/core/functions/yaamp.php yaamp_pool_rate / yaamp_hashrate_constant / algo factors), so a
  miner's hashrate displays correctly. Report the web values needed (port, color, mBTC factor) — do NOT edit web/ (lead does).
- Existing Bitcoin-style algos must behave byte-for-byte as before (hashtest output unchanged, existing KATs pass).
- Build: `make -C blocknotify && make -C stratum -j8 && make -C stratum hashtest && ./stratum/hashtest` clean with gcc 13
  (and gcc-14 if installed). Portable flags (MARCH, -fno-strict-aliasing) are already set; keep them.
- Real end-to-end validation is expected: build/download the coin daemon, run regtest/testnet/simnet locally, point the
  real stratum at it (use your own MariaDB database name, e.g. yiimp_<yourtask>, loaded from sql/2019-11-10-yiimp.sql.gz;
  MariaDB and memcached are local, start them with `mysqld_safe &` / `memcached -u memcache -d` if not running), mine with
  a small test miner (write one if needed; /tmp/claude-0/-home-user/940fe17f-d697-51b7-8fd2-02f52b656791/scratchpad/miner.py
  is a Bitcoin-stratum example), and show the daemon accepts the blocks. Don't kill processes you didn't start
  (never `pkill -x stratum`; kill by PID).
- Ports: 9500-9599 kawpow family (kawpow 9501, evrprogpow 9502, meowpow 9503, firopow 9504, sccpow 9505, meraki 9506),
  9600-9649 equihash family, 9650 yespowerRES, 9660 decred (existing decred.conf port may be kept if unique).
- Commit in logical commits on your branch; every message ends with exactly:
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01PuCJWisqxCymEgkURmDpuA
  Do NOT push. Don't touch other worktrees or repos.
- If you are interrupted by an API/usage limit, your uncommitted work stays in the worktree; commit early and often.
