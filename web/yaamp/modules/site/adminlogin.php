<?php
// admin password prompt (YAAMP_ADMIN_PASSWORD_HASH), shown after the ip check
$this->pageTitle = 'Admin';
$csrf = $this->csrfField();
$message = empty($error) ? '' : '<p style="color: red; font-weight: bold;">' . CHtml::encode($error) . '</p>';

// action='' posts back to this (possibly renamed) entrance url
echo <<<END
<div class="yaamp-login-container" style="width: 400px; margin: 40px auto; padding: 20px;">
<h2>Administrator login</h2>
$message
<form action="" method="post" autocomplete="off">
$csrf
<p>Password: <input type="password" name="password" class="main-text-input" style="width: 200px;" autofocus></p>
<p><input type="submit" value="Login" class="main-submit-button"></p>
</form>
</div>
END;
