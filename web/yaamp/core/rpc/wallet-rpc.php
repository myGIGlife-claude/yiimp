<?php
/**
 * Common yiimp Wallet RPC object
 */
class WalletRPC {

	public $type = 'Bitcoin';
	protected $rpc;
	protected $rpc_wallet;
	protected $hasGetInfo = false;

	// cache
	protected $account;
	protected $accounts;
	protected $coin;
	protected $info;
	protected $height = 0;

	// Information and debugging
	public $error;
	// public $status;
	// public $raw_response;
	// public $response;

	function __construct($userOrCoin, $pw='', $host='localhost', $port=8332, $url=null)
	{
		if (is_object($userOrCoin)) {

			$coin = $userOrCoin;
			switch ($coin->rpcencoding) {
			case 'GETH':
				$this->type = 'Ethereum';
				$this->account = empty($coin->account) ? $coin->master_wallet : $coin->account;
				$this->rpc = new Ethereum($coin->rpchost, $coin->rpcport);
				break;
			case 'XMR':
				// CryptoNote coins: the daemon (monerod) is the coin rpchost/rpcport, the pool
				// wallet a monero-wallet-rpc, see cryptonote_wallet_config()
				$this->type = 'CryptoNote';
				$this->rpc = new CryptoRPC($coin->rpchost, $coin->rpcport, $coin->rpcuser, $coin->rpcpasswd);
				$w = cryptonote_wallet_config($coin);
				$this->rpc_wallet = new CryptoRPC($w['host'], $w['port'], $w['user'], $w['password']);
				$this->coin = $coin;
				break;
			default:
				$this->type = 'Bitcoin';
				$this->rpc = new Bitcoin($coin->rpcuser, $coin->rpcpasswd, $coin->rpchost, $coin->rpcport, $url);
				$this->hasGetInfo = $coin->hasgetinfo;
			}

		} else {
			// backward compat
			$user = $userOrCoin;
			$this->rpc = new Bitcoin($user, $pw, $host, $port, $url);
		}
	}

	// the wallet answered the last call with an error, so a send that failed this way was not
	// made and can be redone. False after a timeout or a bad answer, and for the errors given
	// once the transaction is in the wallet (commit failed, rejected): it may still be sent
	function rejected()
	{
		$rpc = $this->type == 'CryptoNote' ? $this->rpc_wallet : $this->rpc;
		if ($this->type == 'Ethereum' || !is_array($rpc->response) || empty($rpc->response['error']))
			return false;
		return !preg_match('/commit|reject/i', (string) $this->error);
	}

	function __call($method, $params)
	{
		if (stripos($method, "dump") !== false || stripos($method, "backupwallet") !== false) {
			$this->error = "$method not authorized!";
			debuglog("$method rpc method is not authorized!");
			return false;
		}

		if ($this->type == 'Ethereum') {
			if (!isset($this->accounts)) {
				$this->accounts = $this->rpc->eth_accounts();
				$this->error = $this->rpc->error;
			}
			if (!is_array($this->accounts)) {
				// if wallet is stopped
				return false;
			}
			// convert common methods used by yiimp
			switch ($method) {
			case 'getaccountaddress':
				if (!empty($params[0]))
					return $params[0];
				return $this->account;
			case 'getinfo':
				if (!isset($this->info)) {
					$info = array();
					$info['accounts'] = array();
					$balances = 0;

					foreach ($this->accounts as $addr) {
						// web3.fromWei(eth.getBalance("0x..."), "ether")
						$balance = (float) $this->rpc->eth_getBalance($addr,'latest', true);
						$balance /= 1e18;
						$balances += $balance;
						$info['accounts'][$addr] = $balance;
					}
					$info['balance'] = $balances;
					$this->height = $this->height ? $this->height : $this->rpc->eth_blockNumber();
					$info['blocks'] = $this->height;
					$info['gasprice'] = (float) $this->rpc->eth_gasPrice();
					$info['gasprice'] /= 1e18;
					$info['connections'] = $this->rpc->net_peerCount();
					$info['version'] = $this->rpc->web3_clientVersion();
					$this->info = $info;
				}
				return $this->info;
			case 'getdifficulty':
				$this->height = $this->height ? $this->height : $this->rpc->eth_blockNumber();
				$this->error = $this->rpc->error;
				$block = $this->rpc->eth_getBlockByNumber($this->height);
				$difficulty = objSafeVal($block, 'difficulty', 0);
				return $this->rpc->decode_hex($difficulty);
			case 'getmininginfo':
				$info = array();
				$this->height = $this->height ? $this->height : $this->rpc->eth_blockNumber();
				$info['blocks'] = $this->height;
				$block = $this->rpc->eth_getBlockByNumber($info['blocks']);
				$difficulty = objSafeVal($block, 'difficulty', 0);
				$info['difficulty'] = $this->rpc->decode_hex($difficulty);
				$info['generate'] = $this->rpc->eth_mining();
				$info['errors'] = '';
				$this->error = $this->rpc->error;
				return $info;
			case 'getblock':
				$hash = arraySafeVal($params,0);
				$block = $this->rpc->eth_getBlockByHash($hash);
				$this->error = $this->rpc->error;
				return $block;
			case 'getblockhash':
				$n = arraySafeVal($params,0);
				$block = $this->rpc->eth_getBlockByNumber($n);
				$this->error = $this->rpc->error;
				return $block->hash;
			case 'gettransaction':
			case 'getrawtransaction':
				$txid = arraySafeVal($params,0,'');
				$tx = $this->rpc->eth_getTransactionByHash($txid);
				$this->error = $this->rpc->error;
				return $tx;
			case 'getwork':
				return false; //$this->rpc->eth_getWork(); auto enable miner!
			// todo...
			case 'getpeerinfo':
				$peers = array();
				return $peers;
			case 'listtransactions':
				$txs = array();
				return $txs;
			case 'listsinceblock':
				$txs = array();
				return $txs;
			default:
				$res = $this->rpc->ether_request($method,$params);
				$this->error = $this->rpc->error;
				return $res;
			}
		}

		// CryptoNote (monerod + monero-wallet-rpc)
		else if ($this->type == 'CryptoNote')
		{
			return $this->cryptonote($method, $params);
		}

		// Bitcoin RPC
        	switch ($method) {
			case 'getinfo':
				if ($this->hasGetInfo) {
					$res = $this->rpc->__call($method,$params);
				} else {
					$miningInfo = $this->rpc->getmininginfo();
					$res["blocks"] = arraySafeVal($miningInfo,"blocks");
					$res["difficulty"] = arraySafeVal($miningInfo,"difficulty");
					$res["testnet"] = "main" != arraySafeVal($miningInfo,"chain");
					$walletInfo = $this->rpc->getwalletinfo();
					$res["walletversion"] = arraySafeVal($walletInfo,"walletversion");
					$res["balance"] = arraySafeVal($walletInfo,"balance");
					$res["keypoololdest"] = arraySafeVal($walletInfo,"keypoololdest");
					$res["keypoolsize"] = arraySafeVal($walletInfo,"keypoolsize");
					$res["paytxfee"] = arraySafeVal($walletInfo,"paytxfee");
					$networkInfo = $this->rpc->getnetworkinfo();
					$res["version"] = arraySafeVal($networkInfo,"version");
					$res["protocolversion"] = arraySafeVal($networkInfo,"protocolversion");
					$res["timeoffset"] = arraySafeVal($networkInfo,"timeoffset");
					$res["connections"] = arraySafeVal($networkInfo,"connections");
//                    			$res["proxy"] = arraySafeVal($networkInfo,"networks")[0]["proxy"];
					$res["relayfee"] = arraySafeVal($networkInfo,"relayfee");
				}
				break;
			default:
				$res = $this->rpc->__call($method,$params);
        	}

		$this->error = $this->rpc->error;
		return $res;
	}

	/////////////////////////////////////////////////////////////////////////////////////////
	// CryptoNote: the Bitcoin methods used by yiimp, from monerod (json_rpc) and the
	// monero-wallet-rpc of the pool wallet. Amounts are in coins (atomic units / 1e12 for
	// Monero), difficulties in 2^32 hash units like the other algos (and the stratum).

	protected function cryptonote($method, $params)
	{
		$units = cryptonote_atomic_units($this->coin);
		$this->error = null;
		$res = false;

		switch ($method) {
		case 'getinfo':
			$info = $this->rpc->get_info();
			if (!is_array($info)) {
				$this->error = $this->rpc->error;
				return false;
			}
			$res = array();
			$res['blocks'] = (int) arraySafeVal($info, 'height') - 1; // height of the last block
			$res['difficulty'] = cryptonote_difficulty($info);
			$res['connections'] = (int) arraySafeVal($info, 'incoming_connections_count', 0)
				+ (int) arraySafeVal($info, 'outgoing_connections_count', 0);
			$res['synchronized'] = (bool) arraySafeVal($info, 'synchronized', false) && !arraySafeVal($info, 'busy_syncing', false);
			$res['testnet'] = arraySafeVal($info, 'nettype', 'mainnet') != 'mainnet';
			$res['version'] = arraySafeVal($info, 'version', '');
			$res['errors'] = '';
			$fee = $this->rpc->get_fee_estimate();
			if (is_array($fee) && isset($fee['fee'])) // per byte, ~3 kB for a payout with a few outputs
				$res['paytxfee'] = round($fee['fee'] * 3000 / $units, 8);
			$balances = $this->rpc_wallet->get_balance(array('account_index' => 0));
			if (is_array($balances)) {
				$res['balance'] = arraySafeVal($balances, 'unlocked_balance', 0) / $units;
				$res['pending'] = arraySafeVal($balances, 'balance', 0) / $units - $res['balance'];
			} else {
				$res['balance'] = 0;
				$res['errors'] = 'wallet: '.$this->rpc_wallet->error;
			}
			$this->error = $this->rpc_wallet->error;
			break;

		case 'getmininginfo':
		case 'getnetworkinfo':
			$info = $this->rpc->get_info();
			if (!is_array($info)) {
				$this->error = $this->rpc->error;
				return false;
			}
			$res = array();
			$res['blocks'] = (int) arraySafeVal($info, 'height') - 1;
			$res['difficulty'] = cryptonote_difficulty($info);
			$target = max(1, (int) arraySafeVal($info, 'target', 120));
			$res['networkhashps'] = cryptonote_difficulty($info) * 4294967296 / $target;
			$res['connections'] = (int) arraySafeVal($info, 'incoming_connections_count', 0)
				+ (int) arraySafeVal($info, 'outgoing_connections_count', 0);
			$res['version'] = arraySafeVal($info, 'version', '');
			$res['errors'] = '';
			$header = arraySafeVal($this->rpc->get_last_block_header(), 'block_header');
			$res['reward'] = (float) arraySafeVal($header, 'reward', 0) / $units;
			break;

		case 'getdifficulty':
			$info = $this->rpc->get_info();
			$this->error = $this->rpc->error;
			$res = is_array($info) ? cryptonote_difficulty($info) : false;
			break;

		case 'getblockcount':
			$res = $this->rpc->get_block_count();
			$this->error = $this->rpc->error;
			$res = is_array($res) ? (int) arraySafeVal($res, 'count') - 1 : false;
			break;

		case 'getblocktemplate':
			// the template of the stratum, for the reward of the next block
			$res = $this->rpc->get_block_template(array(
				'wallet_address' => $this->coin->master_wallet,
				'reserve_size'   => 8,
			));
			$this->error = $this->rpc->error;
			if (is_array($res)) {
				$res['reward'] = arraySafeVal($res, 'expected_reward', 0) / $units;
				$res['difficulty'] = cryptonote_difficulty($res);
			}
			break;

		case 'getblockhash':
			$data = $this->rpc->get_block_header_by_height(array('height' => (int) arraySafeVal($params, 0)));
			$this->error = $this->rpc->error;
			$res = objSafeVal(arraySafeVal($data, 'block_header'), 'hash', false);
			break;

		case 'getblock':
			// Bitcoin like block: tx[0] is the miner tx, confirmations -1 if not in the main chain
			$hash = (string) arraySafeVal($params, 0, '');
			$data = $this->rpc->get_block(array('hash' => $hash));
			$this->error = $this->rpc->error;
			if (!is_array($data)) return false;
			$header = arraySafeVal($data, 'block_header', array());
			$height = (int) arraySafeVal($header, 'height');
			$res = array(
				'hash' => arraySafeVal($header, 'hash', $hash),
				'height' => $height,
				'version' => (int) arraySafeVal($header, 'major_version', 0),
				'confirmations' => arraySafeVal($header, 'orphan_status') ? -1 : (int) arraySafeVal($header, 'depth') + 1,
				'difficulty' => cryptonote_difficulty($header),
				'nonce' => arraySafeVal($header, 'nonce', 0),
				'time' => arraySafeVal($header, 'timestamp', 0),
				'previousblockhash' => arraySafeVal($header, 'prev_hash', ''),
				'reward' => arraySafeVal($header, 'reward', 0) / $units,
				'tx' => array_merge(array(arraySafeVal($data, 'miner_tx_hash', arraySafeVal($header, 'miner_tx_hash', ''))),
					(array) arraySafeVal($data, 'tx_hashes', array())),
			);
			if ($res['confirmations'] > 1) {
				$next = $this->rpc->get_block_header_by_height(array('height' => $height + 1));
				$res['nextblockhash'] = objSafeVal(arraySafeVal($next, 'block_header'), 'hash', '');
			}
			break;

		case 'gettransaction':
			$res = $this->cryptonote_gettransaction((string) arraySafeVal($params, 0, ''), $units);
			break;

		case 'getrawtransaction':
			$txid = (string) arraySafeVal($params, 0, '');
			$data = $this->rpc->get_transactions(array('txs_hashes' => array($txid), 'decode_as_json' => true));
			$this->error = $this->rpc->error;
			$tx = is_array($data) ? arraySafeVal(arraySafeVal($data, 'txs', array()), 0) : null;
			if (!$tx) return false;
			$res = json_decode(arraySafeVal($tx, 'as_json', '{}'), true);
			if (!is_array($res)) $res = array();
			$res['txid'] = $txid;
			$res['blockheight'] = arraySafeVal($tx, 'block_height');
			$res['in_pool'] = arraySafeVal($tx, 'in_pool');
			break;

		case 'getaccountaddress':
		case 'getaddress':
			$res = $this->rpc_wallet->get_address(array('account_index' => 0));
			$this->error = $this->rpc_wallet->error;
			if ($method == 'getaccountaddress') $res = arraySafeVal($res, 'address', false);
			break;

		case 'getbalance':
			$res = $this->rpc_wallet->get_balance(array('account_index' => 0));
			$this->error = $this->rpc_wallet->error;
			$res = is_array($res) ? arraySafeVal($res, 'unlocked_balance', 0) / $units : false;
			break;

		case 'getbalances':
			$res = $this->rpc_wallet->get_balance(array('account_index' => 0));
			$this->error = $this->rpc_wallet->error;
			break;

		case 'validateaddress':
			// standard, subaddress or integrated address of the network of the wallet
			$address = trim((string) arraySafeVal($params, 0, ''));
			$data = $this->rpc_wallet->validate_address(array('address' => $address, 'any_net_type' => false));
			$this->error = $this->rpc_wallet->error;
			if (!is_array($data)) return false;
			$res = array(
				'isvalid' => (bool) arraySafeVal($data, 'valid', false),
				'address' => $address,
				'integrated' => (bool) arraySafeVal($data, 'integrated', false),
				'subaddress' => (bool) arraySafeVal($data, 'subaddress', false),
				'nettype' => arraySafeVal($data, 'nettype', ''),
				'ismine' => $address == $this->coin->master_wallet,
			);
			break;

		case 'sendtoaddress':
			// address, amount: returns the tx hash
			$res = $this->cryptonote_transfer(array((string) arraySafeVal($params, 0) => arraySafeVal($params, 1, 0)), $units);
			break;

		case 'sendmany':
			// account (unused), {address: amount, ...}: returns the (first) tx hash
			$res = $this->cryptonote_transfer((array) arraySafeVal($params, 1, array()), $units);
			break;

		case 'listtransactions':
			$res = $this->cryptonote_listtransactions((int) arraySafeVal($params, 1, 100), $units);
			break;

		case 'listsinceblock':
			// the blocks come from the stratum (blocknotify), not from the wallet
			$res = false;
			break;

		case 'store':
		case 'refresh':
		case 'rescan_blockchain':
			$res = $this->rpc_wallet->__call($method, array());
			$this->error = $this->rpc_wallet->error;
			break;

		case 'submitblock':
			$res = $this->rpc->submit_block(array((string) arraySafeVal($params, 0, '')));
			$this->error = $this->rpc->error;
			break;

		default:
			// other daemon methods (json_rpc names)
			$res = $this->rpc->__call($method, $params);
			$this->error = $this->rpc->error;
		}

		return $res;
	}

	// a transaction as the Bitcoin wallets give it: the miner tx of a pool block (category
	// immature/generate/orphan, from the daemon) or a transfer of the pool wallet
	protected function cryptonote_gettransaction($txid, $units)
	{
		$data = $this->rpc->get_transactions(array('txs_hashes' => array($txid), 'decode_as_json' => true));
		if (!is_array($data)) {
			$this->error = $this->rpc->error;
			return false;
		}
		$tx = arraySafeVal(arraySafeVal($data, 'txs', array()), 0);
		if (!$tx) {
			// not in the main chain (anymore): orphan
			if (in_array($txid, (array) arraySafeVal($data, 'missed_tx', array()))) {
				return array('txid' => $txid, 'confirmations' => -1,
					'details' => array(array('category' => 'orphan', 'amount' => 0)));
			}
			return false;
		}
		$json = json_decode(arraySafeVal($tx, 'as_json', '{}'), true);
		$vin0 = arraySafeVal(arraySafeVal($json, 'vin', array()), 0, array());
		if (!isset($vin0['gen'])) {
			// a transfer of the pool wallet
			$t = $this->rpc_wallet->get_transfer_by_txid(array('txid' => $txid));
			$this->error = $this->rpc_wallet->error;
			$t = arraySafeVal($t, 'transfer');
			if (!$t) return false;
			$type = arraySafeVal($t, 'type');
			$amount = arraySafeVal($t, 'amount', 0) / $units;
			$address = arraySafeVal($t, 'address', '');
			$destinations = arraySafeVal($t, 'destinations', array());
			if ($type == 'out' && is_array($destinations) && count($destinations) == 1)
				$address = arraySafeVal(reset($destinations), 'address', $address);
			return array('txid' => $txid, 'amount' => $type == 'out' ? -$amount : $amount,
				'fee' => arraySafeVal($t, 'fee', 0) / $units, 'confirmations' => arraySafeVal($t, 'confirmations', 0),
				'time' => arraySafeVal($t, 'timestamp', 0),
				'details' => array(array('category' => $type == 'out' ? 'send' : 'receive',
					'address' => $address, 'amount' => $amount)));
		}
		if (arraySafeVal($tx, 'in_pool')) return false;

		$height = (int) arraySafeVal($tx, 'block_height');
		$count = arraySafeVal($this->rpc->get_block_count(), 'count', 0);
		$this->error = $this->rpc->error;
		if (!$count) return false;

		$amount = 0;
		foreach ((array) arraySafeVal($json, 'vout', array()) as $out)
			$amount += (float) arraySafeVal($out, 'amount', 0);
		$amount /= $units;

		// spendable (wallet2::is_transfer_unlocked): the unlock height and 10 blocks
		$unlock = (int) arraySafeVal($json, 'unlock_time', $height + 60);
		$mature = $count >= $unlock && $count >= $height + 10;

		return array('txid' => $txid, 'amount' => $amount, 'confirmations' => $count - $height,
			'blockheight' => $height, 'time' => arraySafeVal($tx, 'block_timestamp', 0), 'generated' => true,
			'details' => array(array('category' => $mature ? 'generate' : 'immature', 'amount' => $amount)));
	}

	// payments (amounts in coins) with transfer_split: returns the first tx hash or false
	protected function cryptonote_transfer($addresses, $units)
	{
		$destinations = array();
		foreach ($addresses as $address => $amount) {
			// atomic units as integers (the wallet rejects floats)
			$atomic = (int) round((float) $amount * $units);
			if ($atomic <= 0) continue;
			$destinations[] = array('address' => (string) $address, 'amount' => $atomic);
		}
		if (empty($destinations)) {
			$this->error = 'no destination';
			return false;
		}
		$res = $this->rpc_wallet->transfer_split(array(
			'destinations' => $destinations,
			'account_index' => 0,
			'priority' => 0,
			'get_tx_hex' => false,
		));
		$this->error = $this->rpc_wallet->error;
		if (!is_array($res)) return false;
		$hashes = (array) arraySafeVal($res, 'tx_hash_list', array());
		if (empty($hashes)) {
			$this->error = 'no transaction';
			return false;
		}
		if (count($hashes) > 1)
			debuglog("{$this->coin->symbol}: payment in ".count($hashes)." transactions: ".implode(' ', $hashes));
		$this->rpc_wallet->store();
		return (string) reset($hashes);
	}

	// wallet transfers, as the Bitcoin listtransactions (oldest first)
	protected function cryptonote_listtransactions($count, $units)
	{
		$data = $this->rpc_wallet->get_transfers(array('in' => true, 'out' => true, 'pending' => true,
			'pool' => true, 'account_index' => 0));
		$this->error = $this->rpc_wallet->error;
		if (!is_array($data)) return false;
		$txs = array();
		foreach (array('in', 'out', 'pending', 'pool') as $type) {
			foreach ((array) arraySafeVal($data, $type, array()) as $t) {
				$amount = arraySafeVal($t, 'amount', 0) / $units;
				$category = $type == 'in' ? (arraySafeVal($t, 'type') == 'block' ? 'generate' : 'receive') :
					($type == 'pool' ? 'receive' : 'send');
				if ($category == 'generate' && arraySafeVal($t, 'locked')) $category = 'immature';
				$txs[] = array(
					'txid' => arraySafeVal($t, 'txid'),
					'address' => arraySafeVal($t, 'address', ''),
					'category' => $category,
					'amount' => $category == 'send' ? -$amount : $amount,
					'fee' => $category == 'send' ? -arraySafeVal($t, 'fee', 0) / $units : 0,
					'confirmations' => arraySafeVal($t, 'confirmations', 0),
					'time' => arraySafeVal($t, 'timestamp', time()),
					'blockheight' => arraySafeVal($t, 'height', 0),
				);
			}
		}
		usort($txs, function ($a, $b) { return $a['time'] - $b['time']; });
		if ($count > 0 && count($txs) > $count) $txs = array_slice($txs, -$count);
		return $txs;
	}

	function __get($prop)
	{
		return $this->rpc->$prop;
	}

	function __set($prop, $value)
	{
		//debuglog("wallet set $prop ".json_encode($value));
		$this->rpc->$prop = $value;
	}

	function execute($query)
	{
		$result = '';

		if (!empty($query)) try {

			// if its a raw json query...
			if (strpos($query,"{") !== false && json_decode($query)) {
				try {
					$json = json_decode($query);
					debuglog("raw json query ".(is_object($json) && isset($json->method) && is_string($json->method) ? $json->method : ''));
					$result = $this->rpc->request_json($query);
				} catch (Exception $e) {
					$result = false;
				}
				return $result;
			}

			$params = explode(' ', trim($query));
			$command = array_shift($params);

			$p = array();
			foreach ($params as $param) {
				if ($param === 'true' || $param === 'false') {
					$param = $param === 'true' ? true : false;
				}
				else if (strpos($param, '0x') === 0)
					$param = "$param"; // eth hex crap
				else
					$param = (is_numeric($param)) ? 0 + $param : trim($param,'"');
				$p[] = $param;
			}

			switch (count($params)) {
			case 0:
				$result = $this->$command();
				break;
			case 1:
				$result = $this->$command($p[0]);
				break;
			case 2:
				$result = $this->$command($p[0], $p[1]);
				break;
			case 3:
				$result = $this->$command($p[0], $p[1], $p[2]);
				break;
			case 4:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3]);
				break;
			case 5:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4]);
				break;
			case 6:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4], $p[5]);
				break;
			case 7:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4], $p[5], $p[6]);
				break;
			case 8:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4], $p[5], $p[6], $p[7]);
				break;
			default:
				$result = 'error: too much parameters';
			}

		} catch (Exception $e) {
			$result = false;
		}

		return $result;
	}

}

/////////////////////////////////////////////////////////////////////////////////////////////
// CryptoNote helpers

// monero-wallet-rpc of the pool wallet of a coin: $configWalletRPC['SYMBOL'] in
// serverconfig.php ('host:port' or 'host:port:user:password'), else the host of the daemon,
// its rpcport + 1 and the rpcuser/rpcpasswd of the coin
function cryptonote_wallet_config($coin)
{
	global $configWalletRPC;
	$w = array('host' => $coin->rpchost ? $coin->rpchost : '127.0.0.1', 'port' => (int) $coin->rpcport + 1,
		'user' => $coin->rpcuser, 'password' => $coin->rpcpasswd);
	if (isset($configWalletRPC) && is_array($configWalletRPC) && !empty($configWalletRPC[$coin->symbol])) {
		$parts = explode(':', $configWalletRPC[$coin->symbol], 4);
		if (!empty($parts[0])) $w['host'] = $parts[0];
		if (!empty($parts[1])) $w['port'] = (int) $parts[1];
		if (count($parts) == 4) {
			$w['user'] = $parts[2];
			$w['password'] = $parts[3];
		}
	}
	return $w;
}

// atomic units per coin: 1e12 (Monero), $configCryptonoteUnits['SYMBOL'] for the others
function cryptonote_atomic_units($coin)
{
	global $configCryptonoteUnits;
	if ($coin && isset($configCryptonoteUnits) && is_array($configCryptonoteUnits) && !empty($configCryptonoteUnits[$coin->symbol]))
		return (float) $configCryptonoteUnits[$coin->symbol];
	return 1e12;
}

// difficulty of a get_info/block header/template answer, in 2^32 hash units like the other
// algos (the CryptoNote difficulty is a number of hashes)
function cryptonote_difficulty($data)
{
	$wide = arraySafeVal($data, 'wide_difficulty');
	if (is_string($wide) && strncasecmp($wide, '0x', 2) == 0 && strlen($wide) > 2) {
		$diff = 0.0;
		foreach (str_split(substr($wide, 2)) as $c)
			$diff = $diff * 16 + hexdec($c);
	} else {
		$diff = (float) arraySafeVal($data, 'difficulty', 0) + (float) arraySafeVal($data, 'difficulty_top64', 0) * 18446744073709551616.0;
	}
	return $diff / 4294967296.0;
}
