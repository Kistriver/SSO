<?php
session_start();
$_SESSION['id'] = isset($_GET['id'])?$_GET['id']:$_SESSION['id'];
echo "Enter: ?id=ID<br />";
echo "Now ID is:".@$_SESSION['id'];