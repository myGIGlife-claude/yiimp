# Integrating other stratum engines with YiiMP (the bridge contract)

YiiMP is two programs that only talk through the database (MariaDB) and the coin
daemons/wallets:

- the **stratum** (`stratum/`, C++): one process per algo (or per coin with
  `dedicatedport`). It builds jobs from the coin daemon, checks the miners' shares,
  submits the blocks, and writes the miners, shares and blocks to the database;
- the **web** (`web/`, PHP/Yii): the site, and the cron jobs (`screens` main, loop2,
  blocks) that confirm the blocks, share the rewards, and pay the miners from the coin
  wallet.

So any stratum engine can be plugged into YiiMP, whatever its daemon (Kaspa kHeavyHash,
Ergo Autolykos, Alephium Blake3, ...), if it:

1. writes the tables `stratums`, `accounts`, `workers`, `shares` and `blocks` exactly as
   the YiiMP stratum does (section 2);
2. tells the web about found blocks, either through the stratum's blocknotify path or by
   inserting the `blocks` rows itself (section 3);
3. has a **wallet adapter** in the web (`WalletRPC`, selected by `coins.rpcencoding`) so
   that the cron can confirm the blocks and send the payouts (section 4);
4. is declared in the web algo tables and started like the stratums (sections 5 and 6).

There are two ways to do it:

- **In the YiiMP stratum**, as a protocol family (`stratum/protocol.h`): the share
  accounting, the database writes, vardiff, blocknotify and the job loop are then
  shared; the family only implements the daemon (templates, block submission) and the
  miner protocol. This is what `randomx` (Monero) does, and it is the easiest way when
  the daemon has a "template + submit" RPC.
- **As an external engine** (another program, any language): it must then write the
  tables itself, following section 2 to the letter.

Everything below comes from the code: `stratum/share.cpp`, `db.cpp`, `user.cpp`,
`client*.cpp`, `protocol*.cpp`, and `web/yaamp/core/backend/blocks.php`, `payment.php`,
`coins.php`, `users.php`, `stats.php`, `clear.php`, `core/rpc/wallet-rpc.php`,
`core/functions/yaamp.php`.

## 1. The worked example: `randomx` (Monero)

| Part | What it is |
|---|---|
| Stratum family | `stratum/protocol_randomx.cpp` (hooks `create_template`, `request`, `send_error`, `coind_config`, `coind_init`), RandomX in `stratum/algos/randomx`, block helpers in `stratum/algos/cryptonote_block.c` |
| Daemon | `monerod` JSON-RPC: `get_block_template`, `submit_block`, `get_block_count`; `--block-notify` runs the YiiMP `blocknotify` |
| Miners | xmrig protocol (`login`, `job`, `submit`, `keepalived`) |
| Stratum config | `stratum/config.sample/randomx.conf`, port 9701 |
| Web adapter | `rpcencoding = XMR`: `CryptoRPC` (`core/rpc/xmr-rpc.php`) and the CryptoNote branch of `WalletRPC` (monerod + `monero-wallet-rpc`) |
| Web tables | `randomx` in `yaamp.php`: color, port, mBTC factor 0.001 (per kH/s), hashrate constant 2^10 |

Its setup is in section 7.

## 2. Database contract

The schema is `sql/2019-11-10-yiimp.sql.gz` plus `sql/2018-09-22-workers.sql`
(`workers.name` is `VARCHAR(98)`). Columns that are not listed are not used by the
stratum; leave them to their defaults.

### 2.1 `stratums`: one row per running engine process

Written by `db_register_stratum()` at startup and on every main loop (~20 s), and
`db_update_algos()`:

```sql
INSERT INTO stratums (pid, time, started, algo, url, port) VALUES (...)
  ON DUPLICATE KEY UPDATE time=..., algo=..., url=..., port=...;
UPDATE stratums SET workers=<connected miners>, fds=<open fds>, symbol=<'SYM' or NULL> WHERE pid=<pid>;
```

- `pid` (primary key) identifies the process. The same value goes into `workers.pid` and
  `shares.pid`. An external engine can use its OS pid or any unique integer.
- `time` must be refreshed **at least every 2 minutes**: `BackendStatsUpdate` deletes the
  rows older than 2 min, then `DELETE FROM workers WHERE pid NOT IN (SELECT pid FROM stratums)`.
- `symbol` is the coin symbol when the process mines a single coin (the site lists the
  ports per algo and symbol from this table), else NULL.
- `url`, `port`: where the miners connect (shown on the site).

### 2.2 `accounts`: the miners (payout addresses)

Written by `db_add_user()` when a miner logs in (the login name is the payout address,
an optional worker name follows a `.`):

- look up `SELECT id, is_locked, logtraffic, coinid, donation FROM accounts WHERE username=?`;
- refuse the login if `is_locked` (the stratum also blocks the ip);
- insert a new one with `INSERT INTO accounts (username, coinsymbol, balance, donation, hostaddr) VALUES (?, ?, 0, ?, ?)`;
- `coinsymbol` comes from the `c=SYM` (or `s=`) password option; it is only updated
  while the balance and pending payouts are 0.

`username` is `varchar(128)` and unique. **`coinid`** is the coin the account is paid
in: `BackendUsersUpdate` (web) sets it for the accounts with a NULL `coinid` by calling
`validateaddress` on the wallets of the enabled coins, so the wallet adapter must answer
`validateaddress` (section 4). An engine may also set it itself
(`UPDATE accounts SET coinid=? WHERE id=? AND IFNULL(coinid,0)=0`). `balance` belongs to
the web. Addresses must be validated before inserting (the YiiMP stratum strips the
characters `db_check_user_input` does not allow, and refuses names longer than the
columns).

### 2.3 `workers`: the connected miners

- On login (`db_add_worker()`): `INSERT INTO workers (userid, ip, name, difficulty,
  version, password, worker, algo, time, pid)`, where `name` is the account username
  (at most 98 characters), `difficulty` the current share difficulty, `version` the miner
  agent (64), `password` (64), `worker` the rig name (64), `pid` the `stratums.pid`.
- When the share difficulty changes (`db_update_workers()`, every loop):
  `UPDATE workers SET difficulty=?, subscribe=? WHERE id=?`.
- On disconnect (`db_clear_worker()`): `DELETE FROM workers WHERE id=?`.

The site counts the workers and shows their difficulty; the shares reference `workers.id`.

### 2.4 `shares`: the work, aggregated

The stratum does **not** write one row per share. `share_add()` adds each share to an
in-memory aggregate keyed by (userid, workerid, coinid or remote job, valid), and
`share_write()` flushes them every loop (~20 s):

```sql
INSERT INTO shares (userid, workerid, coinid, jobid, pid, valid, extranonce1,
                    difficulty, share_diff, time, algo, error) VALUES (...), (...);
```

| Column | Meaning |
|---|---|
| `userid`, `workerid` | `accounts.id`, `workers.id` |
| `coinid` | the coin whose job the share was for (`coins.id`); 0 for rented remote jobs |
| `jobid` | 0 for the pool's own coins (the renting code uses remote job ids) |
| `pid` | `stratums.pid` |
| `valid` | 1 for the accepted shares, 0 for the rejected ones (one aggregate each) |
| `extranonce1` | 1 if the miner supports extranonce changes (`mining.extranonce.subscribe`), else 0 |
| `difficulty` | **sum** of the share difficulties of the aggregate (valid ones; 0 for invalid), divided by the algo `diff_multiplier` |
| `share_diff` | the difficulty of the first share hash of the aggregate (informative) |
| `time` | flush time (unix) |
| `algo` | the algo name (as in `yaamp_get_algos()`) |
| `error` | error code of the rejected shares, named in `miners_results.php`: 20 invalid nonce, 21 invalid job, 22 duplicate, 23 time rolling, 24 extranonce2 size, 25 invalid share, 26 low difficulty, 27 invalid extranonce |

What the web does with them:

- **Hashrate**: `yaamp_pool_rate()` and the user/worker pages compute
  `SUM(difficulty) * yaamp_hashrate_constant(algo) / 300 / 1000` over the valid shares of
  the last 300 s (`yaamp_hashrate_step()`). The difficulty unit is the engine's choice,
  but the constant must match it: `hashes per difficulty unit * 1.024` (the 1000/1024
  factor is a historical convention of every algo):

  | Share difficulty unit | Constant | Algos |
  |---|---|---|
  | 2^32 hashes (Bitcoin difficulty 1) | 2^42 (default) | all the Bitcoin style algos, kawpow |
  | 1 hash (CryptoNote difficulty) | 2^10 | randomx |
  | 2^13 solutions | 2^23 | equihash |

- **Rewards**: `BackendBlockNew()` splits a block reward between the accounts in
  proportion to `SUM(difficulty)` of their valid shares of the algo (and of the coin when
  `YAAMP_ALLOW_EXCHANGE` is false), then deletes the shares older than 5 minutes. So the
  shares must be flushed often, and a block must never be inserted before the shares
  that found it.

The `share_write` INSERT uses `%f` (6 decimals): keep the unit large enough that a
share is not rounded to 0 (that is why randomx stores hashes, not 2^32 hash units).

### 2.5 `blocks`: found blocks and their life cycle

The stratum inserts **only blocks the daemon accepted and that were confirmed by
blocknotify** (`block_add()`, then `block_confirm()`, then `block_prune()`):

```sql
INSERT INTO blocks (height, blockhash, coin_id, userid, workerid, category, difficulty,
                    difficulty_user, time, algo, segwit)
VALUES (?, '<block id>', ?, ?, ?, 'new', ?, ?, ?, '<algo>', 0|1);
```

- `blockhash` is the hash the wallet adapter's `getblock` accepts (for Bitcoin coins the
  block hash, for Monero the CryptoNote block id).
- `difficulty` is the network difficulty, in the unit of `coins.difficulty` (2^32
  hashes for all the algos, see section 4.3); `difficulty_user` the difficulty of the
  found hash in the same unit.

Then the web cron (`blocks` screen) owns the row:

| Step | Function | Change |
|---|---|---|
| `new` → `immature` | `BackendBlockFind1` | `getblock(blockhash)`, then `gettransaction(tx[0])`: sets `txhash`, `amount` (`details[0].amount`), `confirmations`, `price`; creates the `earnings` rows (status 0) and deletes the old shares (`BackendBlockNew`) |
| `new` → `orphan` | `BackendBlockFind1` | the block or its first transaction is not found (amount 0) |
| `immature` → `generate` | `BackendBlocksUpdate` | `gettransaction(txhash)`: `details[0].category` becomes `generate`: earnings status 1 (`mature_time`), `coins.mature_blocks` learnt |
| `immature` → `orphan` | `BackendBlocksUpdate` | `confirmations == -1`: the earnings are deleted |
| `orphan` → `new` | `BackendBlocksUpdate` | within 1 h, if `getblock` has more than 2 confirmations and a `nextblockhash` |
| earnings → balance | `BackendClearEarnings` | status 1 earnings older than `YAAMP_PAYMENTS_FREQ / 2` are added to `accounts.balance` (status 2) |
| payout | `BackendPayments` (main screen, every `YAAMP_PAYMENTS_FREQ`) | accounts of the coin (`accounts.coinid`) with `balance > max(YAAMP_PAYMENTS_MINI, coins.payout_min, coins.txfee)`: one `sendmany` (or `sendtoaddress` per user when `coins.payout_max` is set), `payouts` rows with the tx id; failed payouts are retried (and, for DCR and XMR, users with an invalid address are locked) |

`BackendBlockFind2` also imports the blocks the wallet received outside the stratum
(`listsinceblock`); adapters may return false there.

### 2.6 `coins`: what an engine reads

The YiiMP stratum mines the rows `WHERE enable AND auto_ready AND algo='<algo>'` and
reads (`db_update_coinds()`): `id, name, symbol, symbol2, algo, rpchost, rpcport,
rpcuser, rpcpasswd, rpcencoding, rpccurl, rpcssl, rpccert, master_wallet, account,
reward, reward_mul, price, charity_*, hassubmitblock, txmessage, auxpow, pool_ttf,
actual_ttf, network_ttf, usememorypool, hasmasternodes, multialgos, usesegwit,
max_miners, max_shares`. `master_wallet` is the pool address the blocks pay.

The web keeps `enable`, `auto_ready` (daemon ready: `BackendCoinsUpdate` sets it from the
adapter), `difficulty`, `reward`, `block_height`, `balance`, `immature`, `txfee`,
`mature_blocks` up to date. When the stratum loses a daemon it sets
`auto_ready=0` itself (`UPDATE coins SET auto_ready=0 WHERE id=?`).

The engine should only mine a coin while `enable AND auto_ready`, and must pay the block
rewards to `master_wallet` (the wallet of the web adapter), since the payouts come from
there.

## 3. blocknotify and block confirmation

The daemons run, for every new block of the chain:

```
blocknotify <stratum host>:<stratum port> <coins.id> <block hash>
```

which sends one line to the stratum port:

```json
{"id":1,"method":"mining.update_block","params":["<TCP password of the .conf>",<coinid>,"<hash>"]}
```

(the installer writes the password in `blocknotify/blocknotify.cpp` and the
`[TCP] password` of the .conf files). The stratum then (`client_update_block()`):

- remembers the hash (`lastnotifyhash`) and confirms a pending block of that coin whose
  block id (`hash1`) or pow hash (`hash2`) is the hash (`block_confirm()`; multi-algo
  coins are looked up with `getblock`);
- makes a new job (new height) and sends it to the miners.

A block the daemon accepted but blocknotify never confirmed is dropped after 30 s (15
min for decred), so **the hash the daemon notifies must be the one the engine records**.
If blocknotify came before the submit answer, the submit path confirms it at once.

An external engine can:

- speak `mining.update_block` on its own port (then the daemon runs the YiiMP
  `blocknotify` pointing at the engine), or
- confirm the block itself (the daemon accepted it and it is the chain tip at its
  height) and insert the `new` row directly: the web does not care who writes it.

The YiiMP stratum also refreshes the templates every loop, and the `randomx` family polls
the daemon block count every second (`randomx_poll_ms`), so a missed notification only
delays the job.

## 4. The web wallet adapter (`WalletRPC`, `rpcencoding`)

### 4.1 Selection

`web/yaamp/core/rpc/wallet-rpc.php`, class `WalletRPC`: the constructor switches on
`coins.rpcencoding` (varchar 16). `GETH` (Ethereum) and `XMR` (CryptoNote) have their own
branch; any other value uses the Bitcoin RPC. A new daemon family adds:

1. a `case 'NEWFAMILY':` in the constructor (its RPC client, like `CryptoRPC` in
   `xmr-rpc.php`);
2. a branch in `__call()` translating the Bitcoin methods below;
3. a branch in `BackendCoinsUpdate` (`core/backend/coins.php`), next to the `XMR` one, that
   sets `reward`, `difficulty` and `auto_ready` from the adapter's `getblocktemplate` or
   `getinfo` (the Bitcoin branch needs `coinbasevalue`/`bits`);
4. if the addresses need it, `DCR`/`XMR` style address checks in `payment.php`.

Other coin types are untouched as long as the branches are keyed on the new
`rpcencoding`.

### 4.2 Methods the backend calls

| Method | Caller | Must return |
|---|---|---|
| `getinfo()` | coins.php, payment.php, blocks.php | array: `blocks` (last block height), `difficulty` (see 4.3), `connections`, `balance` (spendable, in coins), optional `paytxfee`, `errors`, `version`; false if the daemon is down (the coin is then disabled) |
| `getblocktemplate(json)` | coins.php | whatever the coins.php branch uses (XMR: `reward` in coins, `difficulty`) |
| `getdifficulty()` | coins.php (when no `difficulty` in getinfo) | number |
| `getblock(hash)` | blocks.php | array: `tx` (list, `tx[0]` = the coinbase/miner tx id), `height`, `confirmations` (-1 if not in the main chain), `difficulty`, `nonce` (non-zero), `nextblockhash` (when it has a successor) |
| `gettransaction(txid)` | blocks.php | for the coinbase of a pool block: `confirmations` (-1 = orphan), `details[0].category` (`immature`, `generate` once spendable, `orphan`), `details[0].amount` (the pool reward, in coins) |
| `validateaddress(address)` | users.php, payment.php | array with `isvalid` (true only for an address of this coin and network) |
| `sendmany(account, {address: amount})` | payment.php | the txid **string**, or false with `$this->error` set |
| `sendtoaddress(address, amount)` | payment.php (`payout_max`) | txid string or false |
| `getaccountaddress(account)` | coins.php (empty `master_wallet`) | the pool address |
| `listsinceblock(hash)` | blocks.php `BackendBlockFind2` | false when the blocks only come from the stratum |
| `listtransactions(account, count)`, `getbalance`, `getrawtransaction` | admin pages (coin wallet, explorer) | Bitcoin-like arrays |
| `submitblock('')`, `getauxblock()` | coins.php (feature probes) | an error; "method not found" disables the feature |

Amounts are in coins (floats); the adapter converts from/to the wallet units.

### 4.3 Difficulty units

`coins.difficulty` (and the `blocks` difficulties) are in **2^32 hash units** for every
algo: `coins.php` computes `network_ttf` and `pool_ttf` as
`difficulty * 2^32 / hashrate`, and `yaamp_profitability()` as
`20116.56761169 / difficulty * reward * price` (BTC per day per MH/s) times the algo's
`yaamp_algo_mBTC_factor` (1 = per MH/s, 1000 = per GH/s, 0.001 = per kH/s). A daemon whose
difficulty is a number of hashes (CryptoNote, Kaspa...) divides it by 2^32 in the adapter
(`cryptonote_difficulty()`), and so does the stratum for `coind->difficulty` and the
`blocks` rows.

## 5. Web algo tables

In `web/yaamp/core/functions/yaamp.php`:

- `yaamp_get_algos()`, `getAlgoColors()`, `getAlgoPort()`: generated by
  `python3 docs/handoff/tools/sync_algos.py <repo> <algo>=#color` from the stratum's
  `g_algos[]` and `stratum/config.sample/*.conf` (an external engine adds a config sample
  with `algo =` and `port =`, or the entries by hand);
- `yaamp_algo_mBTC_factor()`: the display unit of the profitability;
- `yaamp_hashrate_constant()`: the share difficulty unit (section 2.4).

An `algos` row (`INSERT INTO algos (name, profit, rent, factor) VALUES ('<algo>', 0, 0, 1)`)
lets the stratum read the algo profit; the web fills it.

## 6. Configuration and installer hooks

- Stratum configs: `stratum/config/<algo>.conf` (`[TCP] server/port/password`, `[SQL]`,
  `[STRATUM] algo, difficulty, diff_min, diff_max...`). Ports in use: 3xxx-8xxx (Bitcoin
  algos), 91xx-93xx (Phase 1), 9501-9506 (kawpow), 9600-9650 (equihash), 9660-9661
  (decred/blake3), **9701 (randomx)**. Pick a free port and add a config sample.
- Start/stop: the installers' `stratum start|stop|restart <algo>` helper runs
  `screen -dmS <algo> bash $STRATUM_DIR/run.sh <config>` for any algo with a config file;
  the single-server boot list (`stratum.start.sh`, written by `server_cleanup.sh`) starts
  the listed algos at boot. An external engine gets the same: its own screen (or a
  systemd unit) started as the stratum user, with the DB credentials of the stratum
  configs, and the port opened in ufw.
- blocknotify: the daemons need `blocknotify` (built by `make -C blocknotify`, installed
  next to the stratum) with the right stratum port and coin id.
- Web: `serverconfig.php` settings of the adapter (for XMR `$configWalletRPC`, section 7).

## 7. randomx setup (monerod, monero-wallet-rpc)

### Daemon and wallet

```
monerod --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081 --rpc-login <user>:<password> \
    --block-notify '/var/stratum/blocknotify 127.0.0.1:9701 <coins.id> %s' \
    --non-interactive [--prune-blockchain]
monero-wallet-rpc --daemon-address 127.0.0.1:18081 --daemon-login <user>:<password> \
    --trusted-daemon --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18082 \
    --rpc-login <wuser>:<wpassword> --wallet-file /path/pool --password-file /path/pool.pass
```

- `get_block_template` needs a synchronized daemon (the web sets `auto_ready` from
  `get_info.synchronized`).
- The pool wallet (the one of `monero-wallet-rpc`) is `coins.master_wallet`: the blocks
  pay it directly, and the payouts are sent from it with `transfer_split` (atomic units,
  priority default). Its address must be a standard address (the stratum checks it).
- Block rewards are spendable after 60 blocks (`unlock_time`), about 2 hours.

### `coins` row

`algo = 'randomx'`, `rpcencoding = 'XMR'`, `rpchost`/`rpcport` = monerod,
`rpcuser`/`rpcpasswd` = its `--rpc-login` (basic or digest, the stratum and the web use
curl), `master_wallet` = the pool wallet address, `enable`, `installed`, `visible`.
`payout_min` as wanted (the wallet fee comes on top: `txfee` is estimated from
`get_fee_estimate`).

### Web

`serverconfig.php`:

```php
// monero-wallet-rpc of the pool wallets: 'host:port' or 'host:port:user:password';
// default: the daemon host, rpcport + 1, the coin rpcuser/rpcpasswd
$configWalletRPC = array(
    'XMR' => '127.0.0.1:18082:<wuser>:<wpassword>',
);
// atomic units of other CryptoNote coins (default 1e12)
// $configCryptonoteUnits = array('XYZ' => 1e8);
```

### Stratum

`stratum/config/randomx.conf` from the sample: port 9701, share difficulty 20000
(CryptoNote: hashes per share; vardiff aims at 5 to 20 shares per minute), `randomx_poll_ms`.
Memory: RandomX light mode, 256 MiB per seed hash (current and next seeds, plus a spare:
up to ~800 MiB) and ~2 MiB per verification running at the same time. Each share costs
one light RandomX hash (20 to 40 ms of CPU on a VM core; with JIT and hardware AES), so a
busy pool needs a core per ~30-50 shares/s.

Miners: `xmrig -o pool:9701 -u <address>[.worker] -p x` (`-p d=50000` or `address+50000`
fixes the difficulty). Integrated addresses are refused (the payouts use no payment id;
use a subaddress).

### What goes into the tables

- `workers.difficulty`, `shares.difficulty`: share difficulty in hashes; web constant 2^10.
- `blocks.blockhash`: the CryptoNote block id (keccak of the hashing blob), as
  `--block-notify` gives it; `difficulty` and `difficulty_user` in 2^32 hash units.
- The adapter answers `getblock` with the miner tx as `tx[0]`, and `gettransaction` from
  the daemon (reward = the miner tx outputs; `generate` once the chain reaches its
  `unlock_time` and 10 blocks).

## 8. Checklist for a new engine

1. Choose the algo name, port and share difficulty unit; add a config sample and the web
   tables (section 5) with the hashrate constant of the unit.
2. Engine: register in `stratums` every ≤ 2 min; accounts/workers on login/logout; share
   aggregates flushed every ≤ 60 s with the right `algo`, `coinid`, `pid`; block rewards
   paid to `coins.master_wallet`; `blocks` rows (`new`) only for blocks the daemon
   accepted, with the id the adapter's `getblock` understands.
3. Web adapter for the coin family (`rpcencoding`), section 4, and its coins.php branch.
4. Daemon: blocknotify (or the engine's own confirmation), wallet for the payouts.
5. Test on a regtest/testnet chain: blocks go `new` → `immature` → `generate`, earnings
   become balances, and a payout transaction is made (the `randomx` test below).

### How `randomx` was tested

monerod 0.18.5.1 `--regtest --offline --fixed-difficulty`, monero-wallet-rpc 0.18.5.1 and
xmrig 6.26.0 (release binaries, SHA-256 checked) on one machine; the stratum and the web
cron functions on a test database: blocks mined by xmrig through the stratum were
accepted by monerod (the block ids of the `blocks` rows are the chain's), confirmed by
`--block-notify`, went `new` → `immature` → `generate` in the web cron, the earnings were
cleared to the account balance, and `BackendPayments` sent a `transfer_split` payout
from the pool wallet, which the miner wallet received. See the Phase 3 notes in
`docs/handoff/HANDOFF.md` for the details.
