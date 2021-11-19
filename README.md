# 对称加解密
支持3DES


## 环境要求

* PHP >= 5.6


## 安装（composer包）
```shell
composer require tianmiao/encrypt
```



## 示例
```php

require "./vendor/autoload.php";

//加密key
$key = '288519b466c231551384051d1';
//位移参数
$iv = '288519b41';
$des3=new \Tianmiao\Encrypt\DES3($key,$iv);

$output=$des3->encrypt("hello word");
var_dump($output);
var_dump($des3->decrypt($output));

```
