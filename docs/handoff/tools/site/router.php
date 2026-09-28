<?php
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path !== '/' && is_file(__DIR__.'/web'.$path) && substr($path,-4) !== '.php') return false;
$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = __DIR__.'/web/index.php';
chdir(__DIR__.'/web');
require __DIR__.'/web/index.php';
