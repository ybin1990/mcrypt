<?php
require_once __DIR__ . '/vendor/autoload.php';  
use Crypt\Crypt;  
$data = [
    'sss' => 1111,
];
$crypt = new Crypt();
$error = $crypt->encrypt(json_encode($data));
var_dump($error);

?>