<?php

class db_accounts extends CActiveRecord
{
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}

	public function tableName()
	{
		return 'accounts';
	}

	public function rules()
	{
		return array(
		);
	}

	public function relations()
	{
		return array(
		);
	}

	public function attributeLabels()
	{
		return array(
		);
	}

	// the balance only changes with addBalance() (or an UPDATE): saving a record read before
	// a credit or a payment must not write its old balance back
	public function update($attributes=null)
	{
		if ($attributes === null)
			$attributes = array_diff($this->attributeNames(), array('balance'));
		return parent::update($attributes);
	}

	// atomic balance change: a credit always applies, a debit only when the balance covers it.
	// Returns the number of accounts changed (0: unknown account, balance too low or no change)
	public static function addBalance($id, $amount)
	{
		$params = array(':id' => $id, ':amount' => $amount);
		$cond = '';
		if ($amount < 0) {
			$cond = ' AND balance >= :debit';
			$params[':debit'] = -$amount;
		}
		return dborun("UPDATE accounts SET balance = IFNULL(balance,0) + :amount WHERE id=:id$cond", $params);
	}

	public function deleteWithDeps()
	{
		$user = $this;
		dborun("DELETE FROM balanceuser WHERE userid=".$user->id);
		dborun("DELETE FROM hashuser WHERE userid=".$user->id);
		dborun("DELETE FROM shares WHERE userid=".$user->id);
		dborun("DELETE FROM workers WHERE userid=".$user->id);
		dborun("DELETE FROM earnings WHERE userid=".$user->id);
		dborun("UPDATE blocks SET userid=NULL WHERE userid=".$user->id);
		dborun("DELETE FROM payouts WHERE account_id=".$user->id);
		return $user->delete();
	}
}

