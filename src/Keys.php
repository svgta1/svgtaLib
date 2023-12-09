<?php
namespace Svgta\Lib;
use Svgta\Lib\Exception as Exception;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

class Keys
{
  private static $sign_key_private = null;
  private static $sign_key_public = null;
  private static $enc_key_private = null;
  private static $enc_key_public = null;

  public static function clear(){
    self::$sign_key_private = null;
    self::$sign_key_public = null;
    self::$enc_key_private = null;
    self::$enc_key_public = null;
  }

  public static function genKeySetForVerif(?array $data = null, ?string $secret = null): JWKSet{
    $jwkSet = self::_init_keySet($data, $secret, 'sig');
    if(!is_null(self::$sign_key_public))
      $jwkSet = $jwkSet->with(self::$sign_key_public);
    return $jwkSet;
  }

  public static function genKeySetForDec(?array $data = null, ?string $secret = null): JWKSet{
    $jwkSet = self::_init_keySet($data, $secret, 'enc');
    if(!is_null(self::$enc_key_private))
      $jwkSet = $jwkSet->with(self::$enc_key_private);
    return $jwkSet;
  }

  public static function genKeySetForSig(?array $data = null, ?string $secret = null): JWKSet{
    $jwkSet = self::_init_keySet($data, $secret, 'sig');
    if(!is_null(self::$sign_key_private))
      $jwkSet = $jwkSet->with(self::$sign_key_private);
    return $jwkSet;
  }

  public static function genKeySetForEnc(?array $data = null, ?string $secret = null): JWKSet{
    $jwkSet = self::_init_keySet($data, $secret, 'enc');
    if(!is_null(self::$enc_key_public))
      $jwkSet = $jwkSet->with(self::$enc_key_public);
    return $jwkSet;
  }

  private static function _init_keySet(?array $data = null, ?string $secret = null, string $use = 'sig'): JWKSet{
    if(is_null($data))
      $data = ["keys" => []];
    $jwkSet = JWKSet::createFromKeyData($data);
    $jwkSet = $jwkSet->with(self::getNoneKey($use));
    if(!is_null($secret))
      $jwkSet = $jwkSet->with(self::genSecretKey($secret, $use));

    return $jwkSet;
  }

  public static function getNoneKey(string $use = 'sig'): JWK{
    return JWKFactory::createNoneKey([
      'use' => $use,
      'kid' => 'None',
    ]);
  }

  public static function genSecretKey(string $secret, $use = 'sig'): JWK{
    return JWKFactory::createFromSecret($secret, [
      'use' => $use,
      'kid' => 'secret'
    ]);
  }

  public static function get_private_key_sign(): ?JWK{
    return self::$sign_key_private;
  }

  public static function get_public_key_sign(): ?JWK{
    return self::$sign_key_public;
  }

  public static function get_private_key_enc(): ?JWK{
    return self::$enc_key_private;
  }

  public static function get_public_key_enc(): ?JWK{
    return self::$enc_key_public;
  }

  private $private_pem = null;
  private $public_pem = null;
  private $p12 = null;
  private $x509 = null;
  private $p12Pwd = '';
  private $pemPwd = null;
  private $kid = null;
  private $useSig = false;
  private $useEnc = false;
  private $secret = null;

  public function __construct(){

  }

  public function use_for_encDec(): self{
    if($this->useSig)
      throw new Exception('Can not been used for encryption and signature at the same time');
    $clone = clone $this;
    $clone->useEnc = true;
    return $clone;
  }

  public function use_for_signVerify(): self{
    if($this->useEnc)
      throw new Exception('Can not been used for encryption and signature at the same time');
    $clone = clone $this;
    $clone->useSig = true;
    return $clone;
  }

  public function set_secret_key(string $secret): self{
    $clone = clone $this;
    $clone->secret = $secret;
    return $clone;
  }

  public function set_private_key_pem(string $pem, ?string $password = null): self{
    if(!is_null($this->p12) || !is_null($this->secret))
      throw new Exception('Only one of p12 or private key or secret can been used');
    $clone = clone $this;
    $clone->private_pem = $pem;
    $clone->pemPwd = $password;

    return $clone;
  }

  public function set_public_key_pem(string $pem): self{
    if(!is_null($this->p12) || !is_null($this->x509) || !is_null($this->secret))
      throw new Exception('Only one of p12, X509 or public key or secret can been used');
    $clone = clone $this;
    $clone->public_pem = $pem;
    return $clone;
  }

  public function set_private_key_pem_file(string $path, ?string $paswword = null): self{
    $pem = \file_get_contents($path);
    return $this->set_private_key_pem($pem, $password);
  }

  public function set_public_key_pem_file(string $path): self{
    $pem = \file_get_contents($path);
    return $this->set_public_key_pem($pem);
  }

  public function set_x509_file(string $path): self{
    $x509 = \file_get_contents($path);
    return $this->set_x509($x509);
  }

  public function set_x509(string $x509): self{
    if(!is_null($this->p12) || !is_null($this->public_pem) || !is_null($this->secret))
      throw new Exception('Only one of p12, X509 or public key or secret can been used');
    $clone = clone $this;
    $clone->x509 = $x509;
    return $clone;
  }

  public function set_p12_file(string $path, string $password = ''): self{
    if(!is_null($this->private_pem) || !is_null($this->secret))
      throw new Exception('Only one of p12 or private key or secret can been used');
    if(!is_null($this->x509) || !is_null($this->public_pem) || !is_null($this->secret))
      throw new Exception('Only one of p12, X509 or public key or secret can been used');
    $clone = clone $this;
    $clone->p12 = $path;
    $clone->p12Pwd = $password;
    return $clone;
  }

  public function set_kid(string $kid): self{
    $clone = clone $this;
    $clone->kid = $kid;
    return $clone;
  }

  public function build(): array{
    if(!$this->useSig && !$this->useEnc)
      throw new Exception('You must specify the use of the key');
    $options = [];
    if($this->useSig)
      $options['use'] = "sig";
    if($this->useEnc)
      $options['use'] = "enc";
    if(!is_null($this->kid))
      $options['kid'] = $this->kid;

    $privateKey = null;
    $publicKey = null;
    if(!is_null($this->p12)){
      try{
        $content = file_get_contents($this->p12);
        if (!is_string($content))
            throw new Exception('Unable to read the file.');
        \openssl_pkcs12_read($content, $cert, $this->p12Pwd);
        if(!is_array($cert))
          throw new Exception('Unable to load the certificate.');
        if(isset($cert['pkey']))
          $privateKey = JWKFactory::createFromKey(
            $cert['pkey'],
            null,
            $options
          );
        if(isset($cert['cert']))
          $publicKey = JWKFactory::createFromCertificate(
            $cert['cert'],
            $options
          );
      }catch(\Throwable $t){
        throw new Exception('Unable to load the certificates');
      }
    }
    if(!is_null($this->x509)){
      $publicKey = JWKFactory::createFromCertificate($this->x509, $options);
    }
    if(!is_null($this->private_pem)){
      $privateKey = JWKFactory::createFromKey(
        $this->private_pem,
        $this->pemPwd,
        $options
      );
    }
    if(!is_null($this->public_pem)){
      $publicKey = JWKFactory::createFromKey(
        $this->public_pem,
        null,
        $options
      );
    }
    if(!is_null($this->secret)){
      $publicKey = $privateKey = JWKFactory::createFromSecret($this->secret, $options);
    }
    switch($options['use']){
      case 'sig':
        $this->set_sign_keys($privateKey, $publicKey);
        break;
      case 'enc':
        $this->set_enc_keys($privateKey, $publicKey);
        break;
    }

    $ar = [
      'ENC' => [
        'privateKey' => json_encode(self::get_private_key_enc()),
        'PublicKey' => json_encode(self::get_public_key_enc())
      ],
      'SIG' => [
        'privateKey' => json_encode(self::get_private_key_sign()),
        'PublicKey' => json_encode(self::get_public_key_sign())
      ]
    ];
    return $ar;
  }

  private function set_sign_keys(?JWK $privateKey = null, ?JWK $publicKey = null){
    if(!is_null($privateKey))
      self::$sign_key_private = $privateKey;
    if(!is_null($publicKey))
      self::$sign_key_public = $publicKey;
  }
  private function set_enc_keys(?JWK $privateKey = null, ?JWK $publicKey = null){
    if(!is_null($privateKey))
      self::$enc_key_private = $privateKey;
    if(!is_null($publicKey))
      self::$enc_key_public = $publicKey;
  }
}
