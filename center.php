<?php
session_start();
ini_set('display_errors', 1);
require_once(dirname(__FILE__).'/lib.php');
if(isset($_GET['id']))
{
	$p = [
		'token_expired'=>10,
		'data'=>isset($_SESSION['id'])?['id'=>$_SESSION['id']]:[],
	];
	new \kistriver\libs\sso\Server($p);
}
else
{
	header('Location: about:blank');
}
