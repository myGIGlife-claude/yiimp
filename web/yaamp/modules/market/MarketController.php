<?php
class MarketController extends CommonController
{
    protected $postActions = array('enable', 'delete', 'sellto');

    public function actionUpdate()
    {
        if (!$this->admin) return;

        $market = getdbo('db_markets', getiparam('id'));
        if (!$market)
        {
            user()->setFlash('error', "invalid market");
            $this->goback();
            return;
        }
        $coin = getdbo('db_coins', $market->coinid);

        if (isset($_POST['db_markets']))
        {
            $market->setAttributes($_POST['db_markets'], false);
            if ($market->save()) $this->redirect(array(
                'site/coin',
                'id' => $coin->id
            ));
        }

        $this->render('update', array(
            'market' => $market,
            'coin' => $coin
        ));
    }

    public function actionEnable()
    {
        if (!$this->admin) return;

        $enable = (int)getiparam('en');
        $market = getdbo('db_markets', getiparam('id'));
        if ($market)
        {
            $market->disabled = $enable ? 0 : 9;
            $market->save();
        }
        $this->goback();
    }

    public function actionDelete()
    {
        if (!$this->admin) return;

        $market = getdbo('db_markets', getiparam('id'));
        if ($market) $market->delete();
        $this->goback();
    }

    public function actionSellto()
    {
        if (!$this->admin) return;

        $market = getdbo('db_markets', getiparam('id'));
        if (!$market)
        {
            user()->setFlash('error', "invalid market");
            $this->goback();
            return;
        }
        $coin = getdbo('db_coins', $market->coinid);
        $amount = getparam('amount');

        $remote = new WalletRPC($coin);

        $info = $remote->getinfo();
        if (!$info || !$info['balance']) return false;

        $deposit_info = $remote->validateaddress($market->deposit_address);
        if (!$deposit_info || !isset($deposit_info['isvalid']) || !$deposit_info['isvalid'])
        {
            user()->setFlash('error', "invalid address $coin->name, $market->deposit_address");
            $this->redirect(array(
                'site/coin',
                'id' => $coin->id
            ));
        }

        $amount = min($amount, $info['balance'] - $info['paytxfee']);
        //		$amount = max($amount, $info['balance'] - $info['paytxfee']);
        $amount = round($amount, 8);

        debuglog("selling ($market->deposit_address, $amount)");

        // claimed before the send (shared with the sell cron), kept after an unclear failure
        // until the market is cleared
        $key = "market-{$market->id}-sending";
        $tx = BackendWalletSendOnce($coin, $remote, $key, $market->deposit_address, $amount);
        if (!$tx)
        {
            if ($tx === null)
                $remote->error = settings_get($key) ?
                    "a previous send to $market->name may have been made: check the wallet, then clear the market" :
                    "a payment of $coin->symbol is running, try again later";
            else if (!$remote->rejected())
            {
                // may have been sent (timeout): no automatic sell to this market before its next trade
                $market->lastsent = time();
                $market->save();
                send_email_alert('sell', "{$coin->symbol} sell tx to check", "sending $amount {$coin->symbol} to $market->name $market->deposit_address: {$remote->error}\r\nCheck your wallet recent transactions to know if it was sent.");
            }
            user()->setFlash('error', $remote->error);
            $this->redirect(array(
                'site/coin',
                'id' => $coin->id
            ));
        }
        else
        {
            $market->lastsent = time();
            $market->save();
            BackendUpdatePoolBalances($coin->id);
        }

        $exchange = new db_exchange;
        $exchange->market = $market->name;
        $exchange->coinid = $coin->id;
        $exchange->send_time = time();
        $exchange->quantity = $amount;
        $exchange->price_estimate = $coin->price;
        $exchange->status = 'waiting';
        $exchange->tx = $tx;
        $exchange->save();

        $this->redirect(array(
            'site/coin',
            'id' => $coin->id
        ));
    }

}
