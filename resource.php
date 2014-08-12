<?php
session_start();
ini_set('display_errors', 1);
require_once(dirname(__FILE__).'/lib.php');
if(isset($_SERVER['HTTP_REFERER']))
{
	$p = [
		'id'=>1,
		'key'=>'secretKEY',
		'redirect_to'=>'http://localhost/center.php',
		'redirect_self'=>'http://localhost/resource.php',
		'redirect_hosts'=>['localhost'],
	];
	new \kistriver\libs\sso\Consumer($p);
}
else
{
	header('Location: about:blank');
}
