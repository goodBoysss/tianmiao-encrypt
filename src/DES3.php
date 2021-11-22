<?php
/**
 * DES3.php
 * ==============================================
 * Copy right 2015-2021  by https://www.tianmtech.com/
 * ----------------------------------------------
 * This is not a free software, without any authorization is not allowed to use and spread.
 * ==============================================
 * @desc : 3DES加密解密
 * @author: zhanglinxiao<zhanglinxiao@tianmtech.cn>
 * @date: 2021/11/19
 * @version: v1.0.0
 * @since: 2021/11/19 09:11
 */

namespace Tianmiao\Encrypt;
class DES3
{
    private $key = "288519b466c231551384051d";

    private $iv = "00000000";

    /**
     * DES3 constructor.
     * @param string $key
     * @param string $iv
     */
    public function __construct($key, $iv) {
        if (!empty($key)) {
            $this->key = $key;
        }

        if (!empty($iv)) {
            $this->iv = $iv;
        }

    }

    /**
     * 获取php大版本
     * @return false|string
     */
    public function getPhpVersion() {
        return substr(PHP_VERSION, 0, 1);
    }

    /**
     * @param string $input 需要加密的字符串
     * @return string 加密后的字符串
     * @des 3DES加密
     */
    public function encrypt($input) {
        $key = $this->key;
        $iv = $this->iv;

        if ($this->getPhpVersion() < 7) {
            $size = 8;
            $input = $this->pkcs5_pad($input, $size);
            $encryption_descriptor = @mcrypt_module_open(MCRYPT_3DES, '', 'cbc', '');
            @mcrypt_generic_init($encryption_descriptor, $key, $iv);
            $output = @mcrypt_generic($encryption_descriptor, $input);
            @mcrypt_generic_deinit($encryption_descriptor);
            @mcrypt_module_close($encryption_descriptor);
        } else {
            $output = openssl_encrypt($input, "des-ede3-cbc", $key, OPENSSL_RAW_DATA, $iv);
        }
        return base64_encode($output);
    }


    /**
     * @param string $input 需要解密的字符串
     * @return string 解密后的字符串
     * @des 3DES解密
     */
    function decrypt($input) {
        $key = $this->key;
        $iv = $this->iv;

        $input = base64_decode($input);
        if ($this->getPhpVersion() < 7) {
            $encryption_descriptor = @mcrypt_module_open(MCRYPT_3DES, '', 'cbc', '');
            @mcrypt_generic_init($encryption_descriptor, $key, $iv);
            $output = @mdecrypt_generic($encryption_descriptor, $input);
            @mcrypt_generic_deinit($encryption_descriptor);
            @mcrypt_module_close($encryption_descriptor);
            $output = $this->pkcs5_unpad($output);
        } else {
            $output = openssl_decrypt($input, "des-ede3-cbc", $key, OPENSSL_RAW_DATA, $iv);
        }
        return rtrim($output);
    }

    private function pkcs5_pad($text, $blocksize) {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    private function pkcs5_unpad($text) {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text)) {
            return false;
        }
        return substr($text, 0, -1 * $pad);
    }

}