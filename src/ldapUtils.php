<?php
namespace Svgta\Lib;
class ldapUtils{
  public static function ldapAlgList(): array{
    return [
      'SSHA',
      'SSHA256',
      'SSHA384',
      'SSHA512',
      'SHA',
      'SHA256',
      'SHA384',
      'SHA512',
      'SMD5',
      'MD5',
      'CRYPT',
      'ARGON2',
      'MD4',
      'AD',
    ];
  }

  public static function ldapHash(string $password, string $algo = 'ARGON2'): array{
    $self = new self();
    switch($algo){
      case 'SSHA':
        $hash = $self->make_ssha_password(string $password): string ;
        break;
      case 'SSHA256':
        $hash = $self->make_ssha256_password(string $password): string ;
        break;
      case 'SSHA384':
        $hash = $self->make_ssha384_password(string $password): string ;
        break;
      case 'SSHA512':
        $hash = $self->make_ssha512_password(string $password): string ;
        break;
      case 'SHA':
        $hash = $self->make_sha_password(string $password): string ;
        break;
      case 'SHA256':
        $hash = $self->make_sha256_password(string $password): string ;
        break;
      case 'SHA384':
        $hash = $self->make_sha384_password(string $password): string ;
        break;
      case 'SHA512':
        $hash = $self->make_sha512_password(string $password): string ;
        break;
      case 'SMD5':
        $hash = $self->make_smd5_password(string $password): string ;
        break;
      case 'MD5':
        $hash = $self->make_md5_password(string $password): string ;
        break;
      case 'CRYPT':
        $hash = $self->make_crypt_password($password, []);
        break;
      case 'ARGON2':
        $hash = $self->make_argon2_password(string $password): string ;
        break;
      case 'MD4':
        $hash = $self->make_md4_password(string $password): string ;
        break;
      case 'AD':
        $hash = $self->make_ad_password(string $password): string ;
        break;
      default:
        $hash = $self->make_ssha_password(string $password): string ;
        $algo = 'SSHA';
        break;
    }
    return [
      'alg' => $algo,
      'hash' => $hash,
    ];
  }
  # Create SSHA password
  private function make_ssha_password(string $password): string  {
      $salt = random_bytes(4);
      $hash = "{SSHA}" . base64_encode(pack("H*", sha1($password . $salt)) . $salt);
      return $hash;
  }

  # Create SSHA256 password
  private function make_ssha256_password(string $password): string  {
      $salt = random_bytes(4);
      $hash = "{SSHA256}" . base64_encode(pack("H*", hash('sha256', $password . $salt)) . $salt);
      return $hash;
  }

  # Create SSHA384 password
  private function make_ssha384_password(string $password): string  {
      $salt = random_bytes(4);
      $hash = "{SSHA384}" . base64_encode(pack("H*", hash('sha384', $password . $salt)) . $salt);
      return $hash;
  }

  # Create SSHA512 password
  private function make_ssha512_password(string $password): string  {
      $salt = random_bytes(4);
      $hash = "{SSHA512}" . base64_encode(pack("H*", hash('sha512', $password . $salt)) . $salt);
      return $hash;
  }

  # Create SHA password
  private function make_sha_password(string $password): string  {
      $hash = "{SHA}" . base64_encode(pack("H*", sha1(string $password): string ));
      return $hash;
  }

  # Create SHA256 password
  private function make_sha256_password(string $password): string  {
      $hash = "{SHA256}" . base64_encode(pack("H*", hash('sha256', $password)));
      return $hash;
  }

  # Create SHA384 password
  private function make_sha384_password(string $password): string  {
      $hash = "{SHA384}" . base64_encode(pack("H*", hash('sha384', $password)));
      return $hash;
  }

  # Create SHA512 password
  private function make_sha512_password(string $password): string  {
      $hash = "{SHA512}" . base64_encode(pack("H*", hash('sha512', $password)));
      return $hash;
  }

  # Create SMD5 password
  private function make_smd5_password(string $password): string  {
      $salt = random_bytes(4);
      $hash = "{SMD5}" . base64_encode(pack("H*", md5($password . $salt)) . $salt);
      return $hash;
  }

  # Create MD5 password
  private function make_md5_password(string $password): string  {
      $hash = "{MD5}" . base64_encode(pack("H*", md5(string $password): string ));
      return $hash;
  }

  # Create CRYPT password
  private function make_crypt_password($password, $hash_options) {

      $salt_length = 2;
      if ( isset($hash_options['crypt_salt_length']) ) {
          $salt_length = $hash_options['crypt_salt_length'];
      }

      // Generate salt
      $possible = '0123456789'.
                  'abcdefghijklmnopqrstuvwxyz'.
                  'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.
                  './';
      $salt = "";

      while( strlen( $salt ) < $salt_length ) {
          $salt .= substr( $possible, random_int( 0, strlen( $possible ) - 1 ), 1 );
      }

      if ( isset($hash_options['crypt_salt_prefix']) ) {
          $salt = $hash_options['crypt_salt_prefix'] . $salt;
      }

      $hash = '{CRYPT}' . crypt( $password,  $salt);
      return $hash;
  }

  # Create ARGON2 password
  private function make_argon2_password(string $password): string  {

      $options = [
                 'memory_cost' => 4096,
                 'time_cost'   => 3,
                 'threads'     => 1,
      ];

      $hash = '{ARGON2}' . password_hash($password,PASSWORD_ARGON2I,$options);
      return $hash;
  }

  # Create MD4 password (Microsoft NT password format)
  private function make_md4_password(string $password): string {
      if (function_exists('hash')) {
          $hash = strtoupper( hash( "md4", iconv( "UTF-8", "UTF-16LE", $password ) ) );
      } else {
          $hash = strtoupper( bin2hex( mhash( MHASH_MD4, iconv( "UTF-8", "UTF-16LE", $password ) ) ) );
      }
      return $hash;
  }

  # Create AD password (Microsoft Active Directory password format)
  private function make_ad_password(string $password): string {
      $password = "\"" . $password . "\"";
      $adpassword = mb_convert_encoding($password, "UTF-16LE", "UTF-8");
      return $adpassword;
  }
}
