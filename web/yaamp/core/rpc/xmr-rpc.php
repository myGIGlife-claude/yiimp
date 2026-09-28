<?php
/**
 * JSON-RPC client of the CryptoNote daemons and wallets (monerod, monero-wallet-rpc and their
 * forks), used by the WalletRPC adapter (rpcencoding XMR).
 *
 * - JSON-RPC 2.0 methods go to /json_rpc with named params (an object), the result is returned
 *   as an array, or false with $this->error set.
 * - A few daemon methods have their own url (get_transactions, get_info...): rpcget/rpcpost.
 * - With a username (monerod --rpc-login, monero-wallet-rpc --rpc-login), curl negotiates the
 *   HTTP digest (or basic) authentication.
 */
class CryptoRPC
{
	// Configuration options
	private $username;
	private $password;

	private $proto;
	private $host;
	private $port;
	private $url;

	// Information and debugging
	public $status;
	public $error;
	public $raw_response;
	public $response;

	private $id = 0;

	function __construct($host='localhost', $port=18081, $username='', $password='')
	{
		$this->proto    = 'http';
		$this->host     = $host;
		$this->port     = $port;
		$this->url      = 'json_rpc';
		$this->username = $username;
		$this->password = $password;
	}

	function __call($method, $params=array())
	{
		switch ($method) {
			case 'getheight':
			case 'getinfo':
				return $this->rpcget($method, $params);

			case 'gettransactions': // decodetransaction
			case 'get_transactions':
			case 'sendrawtransaction':
				return $this->rpcpost($method, $params);
		}

		// named params: __call put them in the $params array
		if (count($params) == 1 && (is_array($params[0]) || is_object($params[0]))) {
			$params = (object) $params[0];
		} else if (count($params) == 1 && is_string($params[0]) && json_decode($params[0]) !== null) {
			$params = json_decode($params[0]); // json string
		} else if (empty($params)) {
			$params = new stdClass;
		}

		$data = array(
			'jsonrpc' => '2.0',
			'id'      => $this->id++,
			'method'  => $method,
			'params'  => $params,
		);

		$this->request("{$this->proto}://{$this->host}:{$this->port}/{$this->url}", json_encode($data));
		if ($this->error) {
			return false;
		}
		if (!is_array($this->response) || !array_key_exists('result', $this->response)) {
			$this->error = 'invalid answer';
			return false;
		}
		return $this->response['result'];
	}

	// run the request (POST if $postdata is not null), set response/status/error
	private function request($url, $postdata = null)
	{
		$this->status       = null;
		$this->error        = null;
		$this->raw_response = null;
		$this->response     = null;

		$curl = curl_init($url);
		$options = array(
			CURLOPT_CONNECTTIMEOUT => 10,
			CURLOPT_TIMEOUT        => 60,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_FOLLOWLOCATION => false,
		);
		if ($postdata !== null) {
			$options[CURLOPT_POST]       = true;
			$options[CURLOPT_POSTFIELDS] = $postdata;
			$options[CURLOPT_HTTPHEADER] = array('Content-Type: application/json');
		}
		if (!empty($this->username)) {
			$options[CURLOPT_USERPWD]  = "{$this->username}:{$this->password}";
			$options[CURLOPT_HTTPAUTH] = CURLAUTH_DIGEST | CURLAUTH_BASIC;
		}
		curl_setopt_array($curl, $options);

		$this->raw_response = curl_exec($curl);
		$this->status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$curl_error = curl_error($curl);
		if (PHP_VERSION_ID < 80000) curl_close($curl);

		if (!empty($curl_error)) {
			$this->error = $curl_error;
			return;
		}

		$this->response = json_decode((string) $this->raw_response, true);

		if (is_array($this->response) && !empty($this->response['error'])) {
			$error = $this->response['error'];
			$this->error = strtolower(is_array($error) ? (string) arraySafeVal($error, 'message', 'error') : (string) $error);
		}
		else if ($this->status != 200) {
			switch ($this->status) {
				case 400: $this->error = 'HTTP_BAD_REQUEST'; break;
				case 401: $this->error = 'HTTP_UNAUTHORIZED'; break;
				case 403: $this->error = 'HTTP_FORBIDDEN'; break;
				case 404: $this->error = 'HTTP_NOT_FOUND'; break;
				default:  $this->error = "HTTP_ERROR_{$this->status}";
			}
		}
		else if (!is_array($this->response)) {
			$this->error = 'invalid json answer';
		}
	}

	// methods of the daemon with their own url (GET)
	function rpcget($url, $params=array())
	{
		$url = "{$this->proto}://{$this->host}:{$this->port}/{$url}";
		if (!empty($params) && is_array(reset($params))) {
			$url .= '?'.http_build_query(reset($params));
		}
		$this->request($url);
		return $this->error ? false : $this->response;
	}

	// methods of the daemon with their own url (POST of a json object)
	function rpcpost($url, $params=array())
	{
		$pop = array_pop($params);
		$postdata = json_encode((is_object($pop) || is_array($pop)) ? (object) $pop : new stdClass);
		$this->request("{$this->proto}://{$this->host}:{$this->port}/{$url}", $postdata);
		return $this->error ? false : $this->response;
	}

}
