<?php
namespace Svgta\Lib;
use Svgta\Lib\Exception as Exception;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\NestedToken\NestedTokenLoader;

class JWT
{
  private static $expJwtForAuth = 300;
  private static $default_sig_alg = [
    'RSA' => 'RS256',
    'EC' => [
      'P-256' => 'ES256',
      'P-384' => 'ES384',
      'P-521' => 'ES512',
    ],
    'oct' => 'HS256',
    'none' => 'none',
  ];
  private $client_id = null;
  private $endpoint = null;
  private $JWK = null;
  private $sigAlg = null;
  private $JWT = null;

  public static $alg_sig_accepted = [
    'RSA' => [
      'RS256',
      'RS384',
      'RS512',
      'PS256',
      'PS384',
      'PS512'
    ],
    'EC' => [
      'ES256',
      'ES384',
      'ES512',
    ],
    'oct' => [
      'HS256',
      'HS384',
      'HS512'
    ],
    'none' => ['none']
  ];

  public static $conv_key_className = [
    'A128KW' => 'A128KW',
    'A192KW' => 'A192KW',
    'A256KW' => 'A256KW',
    'A128GCMKW' => 'A128GCMKW',
    'A192GCMKW' => 'A192GCMKW',
    'A256GCMKW' => 'A256GCMKW',
    'ECDH-ES' => 'ECDHES',
    'ECDH-ES+A128KW' => 'ECDHESA128KW',
    'ECDH-ES+A192KW' => 'ECDHESA192KW',
    'ECDH-ES+A256KW' => 'ECDHESA256KW',
    'PBES2-HS256+A128KW' => 'PBES2HS256A128KW',
    'PBES2-HS384+A192KW' => 'PBES2HS384A192KW',
    'PBES2-HS512+A256KW' => 'PBES2HS512A256KW',
    'RSA1_5' => 'RSA15',
    'RSA-OAEP' => 'RSAOAEP',
    'RSA-OAEP-256' => 'RSAOAEP256',
  ];
  public static $conv_enc_className = [
    'A128GCM' => 'A128GCM',
    'A192GCM' => 'A192GCM',
    'A256GCM' => 'A256GCM',
    'A128CBC-HS256' => 'A128CBCHS256',
    'A192CBC-HS384' => 'A192CBCHS384',
    'A256CBC-HS512' => 'A256CBCHS512',
  ];

  public static function encrypt(array|string|object $payload, string $keyAlg, string $encAlg, ?string $secret = null): string{
    $jweBuilder = self::JWEBuilder();
    $encProtectedHeader = [
      'alg' => $keyAlg,
      'enc' => $encAlg
    ];
    if(!is_null($secret))
      $encKey = Keys::genSecretKey($secret, 'enc');
    else
      $encKey = Keys::get_public_key_enc();
    if($encKey->has('kid'))
      $encProtectedHeader['kid'] = $encKey->get('kid');
    if(!is_string($payload))
      $payload = json_encode($payload);
    $jwe = $jweBuilder
      ->create()
      ->withPayload($payload)
      ->withSharedProtectedHeader($encProtectedHeader)
      ->addRecipient($encKey)
      ->build();
    $serializer = new JWECompactSerializer();
    return $serializer->serialize($jwe, 0);
  }

  public static function NestedBuilder(array $payload, string $sigAlg, string $keyAlg, string $encAlg): string{
    $jweSerializerManager = self::JWESM();
    $jwsSerializerManager = self::JWSSM();

    $jwsBuilder = self::JWSBuilder();
    $jweBuilder = self::JWEBuilder();

    $nestedTokenBuilder = new \Jose\Component\NestedToken\NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);
    $encKey = Keys::get_public_key_enc();
    $encProtectedHeader = [
      'alg' => $keyAlg,
      'enc' => $encAlg
    ];
    if($encKey->has('kid'))
      $encProtectedHeader['kid'] = $encKey->get('kid');

    $sigKey = Keys::get_private_key_sign();
    $sigProtectedHeader = [
      'alg' => $sigAlg,
    ];
    if($sigKey->has('kid'))
      $sigProtectedHeader['kid'] = $sigKey->get('kid');

    $token = $nestedTokenBuilder->create(
      json_encode($payload),
      [[
          'key' => $sigKey,
          'protected_header' => $sigProtectedHeader,
      ]],
      'jws_compact',
      $encProtectedHeader,
      [],
      [[
        'key' => $encKey,
        'header' => [],
      ]],
      'jwe_compact'
    );

    return $token;
  }

  public static function NestedLoader(string $jwe, ?array $jwkSet = null, ?string $client_secret = null, ?array $jwkSetDec = null): array{
    $nestedTokenLoader = new NestedTokenLoader(self::JWELoader(), self::JWSLoader());
    if(is_null($jwkSetDec))
      $jwkSetDec = $jwkSet;
    $SigKeySet = Keys::genKeySetForVerif($jwkSet, $client_secret);
    $EncKeySet = Keys::genKeySetForDec($jwkSetDec, $client_secret);
    $res = $nestedTokenLoader->load($jwe, $EncKeySet, $SigKeySet, $signature);
    return [
      'ressource' => $res,
      'signature' => $signature,
    ];
  }

  public static function decrypt(string $jwt, ?array $jwkSet = null, ?string $client_secret = null): string{
    $jweLoader = self::JWELoader();
    $EncKeySet = Keys::genKeySetForDec($jwkSet, $client_secret);
    $jwe = $jweLoader->loadAndDecryptWithKeySet($jwt, $EncKeySet, $recipient);
    return $jwe->getPayload();
  }

  private static function JWESM(): JWESerializerManager{
    $jweSerializerManager = new JWESerializerManager([
      new JWECompactSerializer(),
      new \Jose\Component\Encryption\Serializer\JSONFlattenedSerializer(),
      new \Jose\Component\Encryption\Serializer\JSONGeneralSerializer(),
    ]);
    return $jweSerializerManager;
  }

  private static function JWSSM(): JWSSerializerManager{
    $jwsSerializerManager = new JWSSerializerManager([
      new JWSCompactSerializer(),
      new \Jose\Component\Signature\Serializer\JSONFlattenedSerializer(),
      new \Jose\Component\Signature\Serializer\JSONGeneralSerializer(),
    ]);
    return $jwsSerializerManager;
  }

  private static function JWEBuilder(): JWEBuilder{
    $compressionMethodManager = new CompressionMethodManager([
      new Deflate(),
    ]);
    $jweBuilder = new JWEBuilder(
      self::_JWEAlgoManagerKey(),
      self::_JWEAlgoManagerContent(),
      $compressionMethodManager
    );
    return $jweBuilder;
  }

  private static function JWSBuilder(): JWSBuilder{
    $jwsBuilder = new JWSBuilder(self::_JWSAlgoManager());
    return $jwsBuilder;
  }

  private static function _JWSAlgoManager(): AlgorithmManager{
    $keySign = [];
    $key = [];
    foreach(self::$alg_sig_accepted as $k => $ar)
      $key = array_merge($key, $ar);

    foreach($key as $v){
      if($v == 'none')
        $v = 'None';
      $class = '\\Jose\\Component\\Signature\\Algorithm\\' . $v;
      $keySign[] = new $class();
    }
    return new AlgorithmManager($keySign);
  }
  private static function JWSLoader(): \Jose\Component\Signature\JWSLoader{
    $algorithmManager = self::_JWSAlgoManager();
    $jwsVerifier = new jwsVerifier($algorithmManager);
    $serializerManager = self::JWSSM();
    $jwsLoaded = new \Jose\Component\Signature\JWSLoader(
      $serializerManager,
      $jwsVerifier,
      null
    );
    return $jwsLoaded;
  }

  private static function _JWEAlgoManagerKey(): AlgorithmManager{
    $keyEnc = [];
    foreach(self::$conv_key_className as $k => $v){
      $class = '\\Jose\\Component\\Encryption\\Algorithm\\KeyEncryption\\' . self::$conv_key_className[$k];
      $keyEnc[] = new $class();
    }
    return new AlgorithmManager($keyEnc);
  }
  private static function _JWEAlgoManagerContent(): AlgorithmManager{
    $ContEnc = [];
    foreach(self::$conv_enc_className as $k => $v){
      $class = '\\Jose\\Component\\Encryption\\Algorithm\\ContentEncryption\\' . self::$conv_enc_className[$k];
      $ContEnc[] = new $class();
    }
    return new AlgorithmManager($ContEnc);
  }

  private static function JWELoader(): \Jose\Component\Encryption\JWELoader{
    $keyEncryptionAlgorithmManager = self::_JWEAlgoManagerKey();
    $contentEncryptionAlgorithmManager = self::_JWEAlgoManagerContent();
    $compressionMethodManager = new CompressionMethodManager([
      new Deflate(),
    ]);
    $jweDecrypter = new JWEDecrypter(
      $keyEncryptionAlgorithmManager,
      $contentEncryptionAlgorithmManager,
      $compressionMethodManager
    );
    $serializerManager = self::JWESM();
    $jweLoader = new \Jose\Component\Encryption\JWELoader(
      $serializerManager,
      $jweDecrypter,
      null
    );
    return $jweLoader;
  }

  public static function getJWTHeader(string $jwt): array{
    $ar = explode('.', $jwt);
    $header = json_decode(Utils::base64url_decode($ar[0]), true);
    return $header;
  }
  public static function parseJWE(string $jwt): array{
    $serializerManager = self::JWESM();
    $jwe = $serializerManager->unserialize($jwt);
    return [
      'header' => $jwe->getSharedProtectedHeader(),
      'ressource' => $jwe,
    ];
  }

  public static function parseJWS(string $jwt): array{
    $serializerManager = self::JWSSM();
    $jws = $serializerManager->unserialize($jwt);
    return [
      'header' => $jws->getSignature(0)->getProtectedHeader(),
      'payload' => json_decode($jws->getPayload(), true),
      'ressource' => $jws,
    ];
  }

  public static function signPEM(array $payload, string $privateKey, string $kid){
    $keys = new Keys();
    $res = $keys->set_private_key_pem($privateKey)
      ->set_kid($kid)
      ->use_for_signVerify()
      ->build();
    $jws = new JWT(Keys::get_private_key_sign());
    return $jws->SignPayload($payload, ['kid']);
  }
  public static function verifyPEM(string $jws, string $publicKey, string $kid){
    $keys = new Keys();
    $res = $keys->set_public_key_pem($publicKey)
      ->set_kid($kid)
      ->use_for_signVerify()
      ->build();

    $jwt = new JWT(Keys::genKeySetForVerif());
    $jwt->verifyJWSWithKeysSet($jws);
  }

  private function __construct(JWK | JWKSet $JWK){
    $this->JWK = $JWK;
    if($JWK instanceof JWK)
      $this->setSigAlg();
  }

  public function verifyJWSWithKeysSet(string $jws): void{
    $loader = self::JWSLoader();
    $res = $loader->loadAndVerifyWithKeySet($jws, $this->JWK, $signature);
  }

  public static function set_sign_params(string $alg, JWKSet $keySet): self{
    $res = new self($keySet);
    $res->setSigAlg($alg);
    return $res;
  }

  private function set_client_id(string $client_id): void{
    $this->client_id = $client_id;
  }

  private function set_endpoint(string $endpoint): void{
    $this->endpoint = $endpoint;
  }

  public function signPayload(array $payload, array $hOptions = []): string{
    $jwsBuilder = new JWSBuilder(self::_JWSAlgoManager());
    $options = [
      'alg' => $this->sigAlg,
      'typ' => 'JWT'
    ];
    if(!is_null(Keys::get_private_key_sign())){
      foreach($hOptions as $k){
        if(Keys::get_private_key_sign()->has($k))
          $options[$k] = Keys::get_private_key_sign()->get($k);
      }
    }
    $jws = $jwsBuilder
      ->create()
      ->withPayload(json_encode($payload))
      ->addSignature($this->JWK, $options)
      ->build();
    $serializer = new JWSCompactSerializer();
    $token = $serializer->serialize($jws, 0);
    return $token;
  }

  public function signPayloadAuth(array $hOptions = []): string{
    $payload = self::getPayloadForJwtAuth($this->client_id, $this->endpoint);
    return $this->signPayload($payload, $hOptions);
  }

  public function setSigAlg(?string $alg = null): void{
    if(!is_null($alg)){
      $this->sigAlg = $alg;
      return;
    }

    if(!($this->JWK instanceof JWK))
      throw new Exception('the key must be an instance of JWK');

    if(!$this->JWK->has('kty'))
      throw new Exception('Type of the key not set');
    $type = $this->JWK->get('kty');

    if(!isset(self::$alg_sig_accepted[$type]))
      throw new Exception('Type of the key not known');

    if($type == 'EC')
      $alg = self::$default_sig_alg[$type][$this->JWK->get('crv')];

    if(is_null($alg))
      $alg = self::$default_sig_alg[$type];
    if(!in_array($alg, self::$alg_sig_accepted[$type]))
      throw new Exception('Algorithm not allowed for this key');

    $this->sigAlg = $alg;
  }

  public static function gen_none_jwt(string $client_id, string $endpoint): self{
    $res = new self(Keys::getNoneKey());
    $res->set_client_id($client_id);
    $res->set_endpoint($endpoint);
    return $res;
  }
  public static function gen_client_secret_jwt(string $client_secret, string $client_id, string $endpoint): self{
    $res = new self(Keys::genSecretKey($client_secret));
    $res->set_client_id($client_id);
    $res->set_endpoint($endpoint);
    return $res;
  }
  public static function gen_private_key_jwt(JWK $privateKey, string $client_id, string $endpoint): self{
    $res = new self($privateKey);
    $res->set_client_id($client_id);
    $res->set_endpoint($endpoint);
    return $res;
  }

  private static function getPayloadForJwtAuth(string $client_id, string $endpoint): array{
    $ar = [
      'iss' => $client_id,
      'sub' => $client_id,
      'aud' => $endpoint,
      'jti' => Utils::genUUID(),
      'exp' => time() + self::$expJwtForAuth,
      'iat' => time(),
      'nbf' => time(),
    ];
    return $ar;
  }
}
