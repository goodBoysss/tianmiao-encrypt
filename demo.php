<?php
require "./vendor/autoload.php";

//加密key
$key = '288519b466c231551384051d1';
//位移参数
$iv = '288519b4';
$des3=new \Tianmiao\Encrypt\DES3($key,$iv);

$output=$des3->encrypt("hello word");
var_dump($output);
var_dump($des3->decrypt($output));