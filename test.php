<?php
require_once __DIR__ . '/vendor/autoload.php';  
use Crypt\Crypt;  
$data = [
    'sss' => 1111,
];
$key = 'YmEwYTZkZGQNCmQ1NTY2OTgyDQphMTgxYTYwMw0K';
$crypt = new Crypt($key);
$error = $crypt->encrypt(json_encode($data));
var_dump($error);

?>