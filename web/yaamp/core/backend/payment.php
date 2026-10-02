<?php

function BackendPayments()
{
    // attempt to increase max execution time limit for the cron job
    set_time_limit(300);

    $list = getdbolist('db_coins', "enable and id in (select distinct coinid from accounts)");
    foreach ($list as $coin)
        BackendCoinPayments($coin);

    dborun("update accounts set balance=0 where coinid=0");
}

function BackendUserCancelFailedPayment($userid)
{
    $user = getdbo('db_accounts', intval($userid));
    if (!$user)
        return false;

    $amount_failed = 0.0;
    $failed        = getdbolist('db_payouts', "account_id=:uid AND IFNULL(tx,'') = ''", array(
        ':uid' => $user->id
    ));
    foreach ($failed as $payout) {
        if (BackendPayoutCancel($payout))
            $amount_failed += floatval($payout->amount);
    }

    return $amount_failed;
}

// payment amount of a balance: rounded down to the decimals sent, so never above the balance
function BackendPayoutAmount($balance, $decimals)
{
    $m = pow(10, $decimals);
    return floor(floatval($balance) * $m) / $m;
}

// claim a payment before it is sent: a payouts row without tx, and the amount taken from the
// balance, in one transaction. False when the balance does not cover it (anymore)
function BackendPayoutClaim($coin, $user, $amount)
{
    return dbotransaction(function () use ($coin, $user, $amount) {
        $payout             = new db_payouts;
        $payout->account_id = $user->id;
        $payout->time       = time();
        $payout->amount     = bitcoinvaluetoa($amount);
        $payout->fee        = 0;
        $payout->idcoin     = $coin->id;
        if (!$payout->save() || !db_accounts::addBalance($user->id, -$amount))
            return false;
        return $payout;
    });
}

// give back a payout that was not sent (no tx): the row is deleted and the balance credited, once
function BackendPayoutRestore($payout)
{
    return dbotransaction(function () use ($payout) {
        if (!dborun("DELETE FROM payouts WHERE id=:id AND IFNULL(tx,'')=''", array(':id' => $payout->id)))
            return false;
        db_accounts::addBalance($payout->account_id, floatval($payout->amount));
        return true;
    });
}

// one payment action per coin at a time (the payment runs of the cron and the admin, the
// cancel of unsent payouts): a MySQL lock, also released if the process dies.
// Returns the result of $fn, or false when the lock is held by another process
function BackendPaymentLocked($coinid, $fn)
{
    $lock = "CONCAT(DATABASE(), '.payment.', :id)";
    if (!dboscalar("SELECT GET_LOCK($lock, 0)", array(':id' => $coinid)))
        return false;
    try {
        return $fn();
    } finally {
        dboscalar("SELECT RELEASE_LOCK($lock)", array(':id' => $coinid));
    }
}

// admin cancel of an unsent payout: never while a payment run of its coin may be sending it
function BackendPayoutCancel($payout)
{
    return BackendPaymentLocked($payout->idcoin, function () use ($payout) {
        return BackendPayoutRestore($payout);
    });
}

function BackendCoinPayments($coin)
{
    $ran = BackendPaymentLocked($coin->id, function () use ($coin) {
        BackendCoinPaymentsLocked($coin);
        return true;
    });
    if (!$ran)
        debuglog("payment: {$coin->symbol} payment already running");
}

function BackendCoinPaymentsLocked($coin)
{
    //    debuglog("BackendCoinPayments $coin->symbol");
    $remote = new WalletRPC($coin);

    $info = $remote->getinfo();
    if (!$info) {
        debuglog("payment: can't connect to {$coin->symbol} wallet");
        return;
    }

    // payouts claimed but without tx: the send timed out or the run was interrupted, so they may
    // have been made. Never sent again here: check the wallet, then set their tx or cancel them
    // (user page) to give the amount back
    $unsent = dborow("SELECT COUNT(*) AS nb, SUM(amount) AS amount FROM payouts WHERE idcoin=:id AND IFNULL(tx,'')=''", array(
        ':id' => $coin->id
    ));
    if (!empty($unsent['nb'])) {
        $notice = "payment: {$unsent['nb']} {$coin->symbol} payouts without tx ({$unsent['amount']} {$coin->symbol}) to check";
        debuglog($notice);
        send_email_alert('payouts_tx', "{$coin->symbol} payout tx problems to check", "$notice\r\nCheck your wallet recent transactions to know if the payment was made, the RPC call timed out.");
    }

    $txfee      = floatval($coin->txfee);
    $decimals   = $coin->symbol == 'MBC' ? 4 : 6;
    $min_payout = max(floatval(YAAMP_PAYMENTS_MINI), floatval($coin->payout_min), $txfee);

    if (date("w", time()) == 0 && date("H", time()) > 18) { // sunday evening, minimum reduced
        $min_payout = max($min_payout / 10, $txfee);
        if ($coin->symbol == 'DCR')
            $min_payout = 0.01005;
    }

    $users = getdbolist('db_accounts', "balance>$min_payout AND coinid={$coin->id} ORDER BY balance DESC");

    // todo: enhance/detect payout_max from normal sendmany error
    if ($coin->symbol == 'BOD' || $coin->symbol == 'DIME' || $coin->symbol == 'BTCRY' || !empty($coin->payout_max)) {
        foreach ($users as $user) {
            $balance = floatval($user->balance);
            $amount  = $balance;
            while ($balance > $min_payout && $amount > $min_payout) {
                $amount = BackendPayoutAmount(min($amount, $balance), $decimals);
                $payout = BackendPayoutClaim($coin, $user, $amount);
                if (!$payout)
                    break;
                debuglog("$coin->symbol sendtoaddress $user->username $amount");
                $tx = $remote->sendtoaddress($user->username, $amount);
                if (!$tx) {
                    $error = $remote->error;
                    debuglog("RPC $error, {$user->username}, $amount");
                    if (!$remote->rejected()) {
                        // may have been sent: the claim stays, for a manual check
                        $payout->errmsg = $error;
                        $payout->save();
                        break;
                    }
                    BackendPayoutRestore($payout);
                    if (stripos($error, 'transaction too large') !== false || stripos($error, 'invalid amount') !== false || stripos($error, 'insufficient funds') !== false || stripos($error, 'transaction creation failed') !== false) {
                        $coin->payout_max = min((float) $amount, (float) $coin->payout_max);
                        $coin->save();
                        $amount /= 2;
                        continue;
                    }
                    break;
                }

                $payout->tx = $tx;
                $payout->save();

                $balance -= $amount;
            }
        }

        debuglog("payment done");
        return;
    }

    $total_to_pay = 0;
    $addresses    = array();


    foreach ($users as $user) {
        $amount = BackendPayoutAmount($user->balance, $decimals);
        $total_to_pay += $amount;
        $addresses[$user->username] = $amount;
        // transaction xxx has too many sigops: 1035 > 1000
        if ($coin->symbol == 'DCR' && count($addresses) > 990) {
            debuglog("payment: more than 990 {$coin->symbol} users to pay, limit to top balances...");
            break;
        }
    }

    if (!$total_to_pay) {
        //    debuglog("nothing to pay");
        return;
    }

    $coef = 1.0;
    if ($info['balance'] - $txfee < $total_to_pay && $coin->symbol != 'BTC') {
        $msg = "$coin->symbol: insufficient funds for payment {$info['balance']} < $total_to_pay!";
        debuglog($msg);
        send_email_alert('payouts', "$coin->symbol payout problem detected", $msg);

        $coef         = 0.5; // so pay half for now...
        $total_to_pay = $total_to_pay * $coef;
        foreach ($addresses as $key => $val) {
            $addresses[$key] = $val * $coef;
        }
        // still not possible, skip payment
        if ($info['balance'] - $txfee < $total_to_pay)
            return;
    }

    if ($coin->symbol == 'BTC') {
        global $cold_wallet_table;

        $balance = $info['balance'];
        $stats   = getdbosql('db_stats', "1 order by time desc");

        $renter = dboscalar("select sum(balance) from renters");
        $pie    = $balance - $total_to_pay - $renter - 1;

        debuglog("pie to split is $pie");
        if ($pie > 0) {
            foreach ($cold_wallet_table as $coldwallet => $percent) {
                $coldamount = round($pie * $percent, 6);
                if ($coldamount < $min_payout)
                    break;

                debuglog("paying cold wallet $coldwallet $coldamount");

                $addresses[$coldwallet] = $coldamount;
                $total_to_pay += $coldamount;
            }
        }
    }

    debuglog("paying $total_to_pay {$coin->symbol}");

    $payouts = array();
    foreach ($users as $user) {
        if (!isset($addresses[$user->username]))
            continue;

        $payout = BackendPayoutClaim($coin, $user, $addresses[$user->username]);
        if ($payout) {
            $payouts[$user->username] = $payout;
        } else {
            debuglog("payment: {$user->username} balance changed, paid next time");
            $total_to_pay -= $addresses[$user->username];
            unset($addresses[$user->username]);
        }
    }
    if (empty($payouts))
        return;

    // sometimes the wallet take too much time to answer, so use tx field to double check
    set_time_limit(120);

    // default account
    $account = $coin->account;

    if (!$coin->txmessage)
        $tx = $remote->sendmany($account, $addresses);
    else
        $tx = $remote->sendmany($account, $addresses, 1, YAAMP_SITE_NAME);

    $errmsg = NULL;
    if (!$tx) {
        debuglog("sendmany: unable to send $total_to_pay {$remote->error} " . json_encode($addresses));
        $errmsg = $remote->error;
    } else if (!is_string($tx)) {
        debuglog("sendmany: result is not a string tx=" . json_encode($tx));
        $errmsg = json_encode($tx);
    }

    if (!$tx && $remote->rejected()) {
        // nothing was sent: give the amounts back to the balances, paid by the next run.
        // A bad address would fail every run: its user is locked and its claim kept
        $mailmsg = '';
        foreach ($payouts as $username => $payout) {
            $data = $remote->validateaddress($username);
            if (is_array($data) && !arraySafeVal($data, 'isvalid')) {
                debuglog("Found bad address $username!! ({$payout->amount} {$coin->symbol})");
                dborun("UPDATE accounts SET is_locked=1 WHERE id=:id", array(':id' => $payout->account_id));
                $payout->errmsg = "invalid address, $errmsg";
                $payout->save();
                $mailmsg .= "{$payout->amount} {$coin->symbol} to $username - user id {$payout->account_id}: invalid address\n";
                continue;
            }
            BackendPayoutRestore($payout);
        }
        send_email_alert('payouts', "{$coin->symbol} payout problems detected\n $errmsg", $mailmsg);
        return;
    }

    // save processed payouts (tx), or the error: the claims stay, they may have been sent
    foreach ($payouts as $payout) {
        $payout->errmsg = $errmsg;
        if (empty($errmsg)) {
            $payout->tx        = $tx;
            $payout->completed = 1;
        }
        $payout->save();
    }

    if (!empty($errmsg)) {
        send_email_alert('payouts_tx', "{$coin->symbol} payout tx problems to check", "sendmany: $errmsg\r\nCheck your wallet recent transactions to know if the payment was made, the RPC call timed out.");
        return;
    }

    debuglog("{$coin->symbol} payment done");
}
