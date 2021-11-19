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
     * @param string $str 需要加密的字符串
     * @return string $crypt 加密后的字符串
     * @des 3DES加密
     */
    public function encrypt($str) {
        $key = $this->key;
        $iv = $this->iv;
        $size = 8;

        $str = $this->pkcs5_pad($str, $size);
        $encryption_descriptor = @mcrypt_module_open(MCRYPT_3DES, '', 'cbc', '');
        @mcrypt_generic_init($encryption_descriptor, $key, $iv);
        $data = @mcrypt_generic($encryption_descriptor, $str);
        @mcrypt_generic_deinit($encryption_descriptor);
        @mcrypt_module_close($encryption_descriptor);
        return base64_encode($data);
    }


    /**
     * @param string $str 需要解密的字符串
     * @return string $input 解密后的字符串
     * @des 3DES解密
     */
    function decrypt($str) {
        $key = $this->key;
        $iv = $this->iv;

        $str = base64_decode($str);
        $encryption_descriptor = @mcrypt_module_open(MCRYPT_3DES, '', 'cbc', '');
        @mcrypt_generic_init($encryption_descriptor, $key, $iv);
        $decrypted_data = @mdecrypt_generic($encryption_descriptor, $str);
        @mcrypt_generic_deinit($encryption_descriptor);
        @mcrypt_module_close($encryption_descriptor);
        $decrypted_data = $this->pkcs5_unpad($decrypted_data);
        return rtrim($decrypted_data);
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