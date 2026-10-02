<?php

class db_renters extends CActiveRecord
{
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}

	public function tableName()
	{
		return 'renters';
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

	// as db_accounts: the balance only changes with addBalance() (or an UPDATE), a save()
	// of a record read earlier must not write its old balance back
	public function update($attributes=null)
	{
		if ($attributes === null)
			$attributes = array_diff($this->attributeNames(), array('balance'));
		return parent::update($attributes);
	}

	// atomic balance change: a credit always applies, a debit only when the balance covers it.
	// Returns the number of renters changed
	public static function addBalance($id, $amount)
	{
		$params = array(':id' => $id, ':amount' => $amount);
		$cond = '';
		if ($amount < 0) {
			$cond = ' AND balance >= :debit';
			$params[':debit'] = -$amount;
		}
		return dborun("UPDATE renters SET balance = IFNULL(balance,0) + :amount WHERE id=:id$cond", $params);
	}
}

