<?php

function BackendClearEarnings($coinid = NULL)
{
    //    debuglog(__FUNCTION__);

    if (YAAMP_ALLOW_EXCHANGE)
        $delay = time() - (int) YAAMP_PAYMENTS_FREQ;
    else
        $delay = time() - (YAAMP_PAYMENTS_FREQ / 2);
    $total_cleared = 0.0;

    $sqlFilter = $coinid ? " AND coinid=" . intval($coinid) : '';

    $list = getdbolist('db_earnings', "status=1 AND mature_time<$delay $sqlFilter");
    foreach ($list as $earning) {
        $user = getdbo('db_accounts', $earning->userid);
        if (!$user) {
            $earning->delete();
            continue;
        }

        $coin = getdbo('db_coins', $earning->coinid);
        if (!$coin) {
            $earning->delete();
            continue;
        }

        //         $refcoin = getdbo('db_coins', $user->coinid);
        //         if($refcoin && $refcoin->price<=0) continue;
        //         $value = $earning->amount * $coin->price / ($refcoin? $refcoin->price: 1);

        $value  = yaamp_convert_amount_user($coin, $earning->amount, $user);
        $credit = !($user->coinid == 6 && !YAAMP_ALLOW_EXCHANGE);

        // cleared once: the status change and the credit in one transaction
        $cleared = dbotransaction(function () use ($earning, $coin, $user, $value, $credit) {
            if (!dborun("UPDATE earnings SET status=2, price=:price WHERE id=:id AND status=1", array(
                ':price' => $coin->price,
                ':id' => $earning->id
            )))
                return false;
            if ($credit)
                db_accounts::addBalance($user->id, $value);
            return true;
        });

        if ($cleared && $credit && $user->coinid == 6)
            $total_cleared += $value;
    }

    if ($total_cleared > 0)
        debuglog("total cleared from mining $total_cleared BTC");
}
