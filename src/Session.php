<?php
namespace Svgta\Lib;
use Svgta\Lib\Exception as Exception;

class Session
{
  private static $name = "SvgtaLib";
  private static $encKey = null;

  const DEFAULT_ENCALG = 'A256KW';
  const DEFAULT_ENCENC = 'A256CBC-HS512';

  private static $encAlg = null;
  private static $encEnc = null;

  public static function setSessionName(string $name){
    self::$name = $name;
  }
  public static function setEncAlg(string $alg){
    self::$encAlg = $alg;
  }
  public static function setEncEnc(string $alg){
    self::$encEnc = $alg;
  }
  private function encrypt(string $str): string{
    if(is_null(self::$encAlg))
      self::$encAlg = self::DEFAULT_ENCALG;
    if(is_null(self::$encEnc))
      self::$encEnc = self::DEFAULT_ENCENC;
    return JWT::encrypt($str, self::$encAlg, self::$encEnc, Session::$encKey);
  }

  private function decrypt(string $jwe): ?string{
    return JWT::decrypt($jwe, null, Session::$encKey);
  }

  public static function setSessionKey(string $key){
      self::$encKey = $key;
  }

  public function __construct(){
    if(session_id() == '' || !isset($_SESSION) || session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    if(!isset($_SESSION[self::$name]))
      $_SESSION[self::$name] = [];
  }

  public function put(string $key, mixed $value): void{
    $ser = serialize($value);
    if(is_null(Session::$encKey))
      $_SESSION[self::$name][$key] = $ser;
    else
      $_SESSION[self::$name][$key] = $this->encrypt($ser);
  }

  public function get(string $key): mixed{
    if(isset($_SESSION[self::$name][$key])){
      $val = $_SESSION[self::$name][$key];
      if(is_null(Session::$encKey)){
        $valAr = explode('.', $val);
        if(count($valAr) > 2){
          $head = Utils::base64url_decode($valAr[0]);
          if(!Utils::isJson($head))
            return unserialize($val);
          $headDec = json_decode($head);
          if(isset($headDec->alg) || isset($deadDec->enc))
            throw new Exception('You have to give the key of the session');
          return unserialize($val);
        }
        return unserialize($val);
      }
      $dec = $this->decrypt($val);
      if(is_null($dec))
        throw new Exception('The key of the session is wrong');
      return unserialize($dec);
    }
    return null;
  }

  public function delete(string $key): void{
    if(isset($_SESSION[self::$name][$key]))
      unset($_SESSION[self::$name][$key]);
  }

  public function clear(): void{
    $_SESSION[self::$name] = [];
  }
}
