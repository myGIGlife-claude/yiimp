<?php
// usage: php req.php /path [querystring]
$uri = $argv[1];
$_SERVER += ['REQUEST_URI'=>$uri,'SCRIPT_NAME'=>'/index.php','SCRIPT_FILENAME'=>getcwd().'/index.php','PHP_SELF'=>'/index.php','REQUEST_METHOD'=>'GET','REMOTE_ADDR'=>'127.0.0.1','HTTP_HOST'=>'localhost','SERVER_NAME'=>'localhost','SERVER_PORT'=>80,'HTTP_USER_AGENT'=>'test'];
$_SERVER['PATH_INFO'] = parse_url($uri, PHP_URL_PATH);
parse_str((string)parse_url($uri, PHP_URL_QUERY), $_GET);
require 'index.php';
