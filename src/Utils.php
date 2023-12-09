<?php
namespace Svgta\Lib;
use Svgta\Lib\Exception as Exception;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Core\Util\ECKey;

class Utils
{
    private static $req = [];
    private static $logLevel = LOG_ERR;
    private static $logConvLevel = [
      LOG_EMERG => "Fatal error",
      LOG_ALERT => "Alert",
      LOG_CRIT => "Fatal error",
      LOG_ERR => "Error",
      LOG_WARNING => "Warning",
      LOG_NOTICE => "Notice",
      LOG_INFO => "Info",
      LOG_DEBUG => "Debug",
    ];

    public static function getCertInfo(string $pem): \stdClass{
      $key = JWKFactory::createFromCertificate($pem);
      return json_decode(json_encode($key));
    }
    public static function getCertInfoFile(string $certPath): \stdClass{
      $key = JWKFactory::createFromCertificate($certPath);
      return json_decode(json_encode($key));
    }
    public static function ctrlTypeTime(mixed $time): void{
      if(gettype($time) !== 'integer' && gettype($time) !== 'double')
        throw new Exception('Bad time format');
    }
    public static function ctrlHash(string $toVerify, string $hash, string $alg): bool{
      $hashString = self::getHash($alg, $toVerify);
      return ($hashString == $hash);
    }
    public static function getHash(string $alg, string $string): string{
      $bit = substr($alg, 2, 3);
      $len = ((int)$bit)/16;
      $hash = self::base64url_encode(substr(hash('sha' . $bit, $string, true), 0, $len));
      return $hash;
    }
    public static function genRsaKey(int $len = 2048, array $options = []): array{
      $pKey = JWKFactory::createRSAKey(
        $len,
        $options
      );
      $ar = [
        'JWK' => [
          'privateKey' => json_encode($pKey),
          'publicKey' => json_encode($pKey->toPublic()),
        ],
        'PEM' => [
          'privateKey' => RSAKey::createFromJWK($pKey)->toPem(),
          'publicKey' => RSAKey::createFromJWK($pKey->toPublic())->toPem(),
        ]
      ];
      return $ar;
    }
    public static function genEcKey(string $curv = 'P-256', array $options = []): array{
      $pKey = JWKFactory::createECKey(
        $curv,
        $options
      );
      $ar = [
        'JWK' => [
          'privateKey' => json_encode($pKey),
          'publicKey' => json_encode($pKey->toPublic()),
        ],
        'PEM' => [
          'privateKey' => ECKey::convertToPEM($pKey),
          'publicKey' => ECKey::convertToPEM($pKey->toPublic()),
        ]
      ];
      return $ar;
    }
    public static function randomString(int $bits = 512): string{
      return Base64UrlSafe::encodeUnpadded(random_bytes($bits / 8));
    }
    public static function isJson(string $string): bool{
      json_decode($string);
      return json_last_error() === JSON_ERROR_NONE;
    }
    public static function base64url_encode(string $string): string{
      //return Base64UrlSafe::encode($string, false);
      $enc = base64_encode($string);
      $enc = rtrim($enc, '=');
      $enc = strtr($enc, '+/', '-_');
      return $enc;
    }
    public static function base64url_decode($base64url): string{
      try{
        return Base64UrlSafe::decode($base64url, false);
      }catch(\Throwable $t){
        return \base64_decode(\strtr($base64url, '-_', '+/') . \str_repeat('=', 3 - (3 + \strlen($base64url)) % 4));
      }
    }
    public static function genUUID(): string{
      return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
        mt_rand( 0, 0xffff ),
        mt_rand( 0, 0x0fff ) | 0x4000,
        mt_rand( 0, 0x3fff ) | 0x8000,
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
      );
    }
    public static function getRequest(array $req = []): array{
      if(isset($_REQUEST)){
        foreach($_REQUEST as $k=>$v){
          if(is_string($v))
            $_REQUEST[$k] = rawurldecode($v);
        }
        $req = array_merge($req, $_REQUEST);
      }

      $in = file_get_contents("php://input");
      if(self::isJson($in)){
        $input = json_decode($in, TRUE);
        $req = array_merge($req, $input);
      }
      $req = array_merge($req, self::$req);
      $req['req_timestamp'] = time();
      return $req;
    }
    public static function setRequest(array $req = []): void{
      self::$req = array_merge(self::$req, $req);
    }
    public static function setLogLevel(int $level){
      if(!isset(self::$logConvLevel[$level]))
        throw new Exception('Log level not known');
      self::$logLevel = $level;
    }
    public static function log(int $level, mixed $message): void{
      if(gettype($message) != 'string' && gettype($message) != 'array')
        throw new Exception('Log message type not accepted');
      if(!isset(self::$logConvLevel[$level]))
        throw new Exception('Log level not known');
      if(self::$logLevel >= $level){
          $msg = 'Svgta_Lib ' . self::$logConvLevel[$level] . ': ';
          if(is_string($message))
            $msg .= $message;
          if(is_array($message) && isset($message['logMsg']))
            $msg .= $message['logMsg'];
          error_log($msg);
          if(is_array($message)){
            if(isset($message['logMsg']))
              unset($message['logMsg']);
            if(count($message) > 0)
            foreach($message as $k => $v){
              if(is_array($v) && count($v) === 0)
                continue;
              if(is_array($v) || is_object($v))
                error_log('# ' . $k . ': '. json_encode($v));
              else
                error_log('# ' . $k . ': ' . $v);
            }
          }
      }
    }
    public static function setDebug(string $class, string $method, array $info = []): void{
      $ar = [];
      foreach($info as $k => $v)
        $ar[$k] = $v;
      $ar['logMsg'] = $class . '->' . $method . '()';
      self::log(LOG_DEBUG, $ar);
    }
}
