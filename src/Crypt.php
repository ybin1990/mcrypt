<?php 
 
namespace Crypt;
 
class Crypt
{
  public $handle = '';
  public $key = '';// 密钥


  public function __construct($key) {
    $this->key = $key;
  }
    /**
   * 实例化方法
   * @param  string $type 加密类型
   * @param  string $key  密钥
   */
  public function instance($type='', $key='')
  {
    // 获取加密类型与密钥
    $type = $type ?: 'desc';
    // 获取加密对象
    if ($type == 'desc') {
      $this->handle = new DescCrypt($this->key);
    } else {
      $this->handle = new AscCrypt($this->key);
    }
    // $this->handle = new $class($key);
  }

  /**
   * 加密
   * @param  string $data 明文
   * @return string       密文
   */
  public function encrypt($data)
  {
    // 数据为空，直接返回
    if (empty($data)) return array(true, '');
    // 获取加密对象
    if (empty($this->handle)) $this->instance();
  
    try {
      $enc_data = $this->handle->encrypt($data);
      return array(true, $enc_data);
    } catch (\Exception $e) {
      return array(false, $e->getMessage());
    }
  }

  /**
   * 解密
   * @param  string $data 密文
   * @return string       明文
   */
  public function decrypt($data)
  {
    // 数据为空，直接返回
    if (empty($data)) return array(true, '');
    // 获取加密对象
    if(empty($this->handle)) $this->instance();

    try {
      $dec_data = $this->handle->decrypt($data);
      return array(true, $dec_data);
    } catch(\Exception $e) {
      return array(false, $e->getMessage());
    }
  }
}