package Crypt::OpenSSL::BaseFunc;

use strict;
use warnings;

use Carp;

require Exporter;
use AutoLoader;
use FFI::CheckLib qw(find_lib_or_die);
use FFI::Platypus 1.00;
use FFI::Platypus::Buffer qw(buffer_to_scalar scalar_to_pointer);
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;
use POSIX;

#use Smart::Comments;

our $VERSION = '0.039';

our @ISA = qw(Exporter);

our @OSSLF= qw(
BN_bn2hex
OPENSSL_free
EC_POINT_invert
EC_POINT_add
EC_GROUP_get_curve
EC_POINT_get_affine_coordinates
EC_POINT_set_affine_coordinates
EVP_MD_get_block_size
EVP_MD_get_size
EVP_PKEY_get1_EC_KEY
EVP_get_digestbyname
EC_POINT_point2hex
OBJ_sn2nid
OBJ_nid2sn
EC_POINT_new
EC_GROUP_get0_order
);

our @FFIF = qw(
mul_ec_point
point2hex
hex2point
aead_decrypt
aead_encrypt
aes_cmac 
bn_mod_sqrt 
ecdh 
ecdsa_sign
ecdsa_verify
export_ec_pubkey
export_rsa_pubkey
gen_ec_key
gen_ec_pubkey
gen_ec_point
get_ec_params
get_pkey_bn_param
get_pkey_octet_string_param
get_pkey_utf8_string_param
hex2bn
hexdump
slurp
bin2hex
pkcs12_key_gen 
pkcs5_pbkdf2_hmac
print_pkey_gettable_params
read_key
read_pubkey
read_ec_pubkey
read_key_from_der
read_key_from_pem
read_pubkey_from_der
read_pubkey_from_pem
rsa_oaep_decrypt
rsa_oaep_encrypt
symmetric_decrypt
symmetric_encrypt
write_key_to_der
write_key_to_pem
write_pubkey_to_der
write_pubkey_to_pem
digest_array
);

our @PMF = qw(
hkdf
hkdf_expand
hkdf_extract
hmac
i2osp
random_bn
sn_point2hex
generate_ec_key
get_ec_params 
digest
);
#aead_encrypt_split

our @H2C = qw(
  sgn0_m_eq_1
  clear_cofactor
  CMOV

  calc_c1_c2_for_sswu
  map_to_curve_sswu_not_straight_line
  map_to_curve_sswu_straight_line

  sn2kv
  get_hash2curve_params
  expand_message_xmd
  hash_to_field
  map_to_curve
  encode_to_curve
  hash_to_curve
);

our @EXPORT = ( @OSSLF, @FFIF, @PMF, @H2C ); 

our @EXPORT_OK = @EXPORT;

my $ffi = FFI::Platypus->new( api => 1 );
$ffi->bundle;

my $crypto = FFI::Platypus->new( api => 1 );
$crypto->lib( find_lib_or_die( lib => 'crypto' ) );

sub _ptr {
    my ($obj) = @_;
    return undef unless defined $obj;
    return ref($obj) ? ${$obj} : $obj;
}

sub _obj {
    my ( $ptr, $class ) = @_;
    return undef unless $ptr;
    return bless \$ptr, $class;
}

sub _bytes_from_ptr {
    my ( $ptr, $len ) = @_;
    return undef unless $ptr;
    return undef if !defined($len) || $len < 0;
    my $out = buffer_to_scalar( $ptr, $len );
    OPENSSL_free($ptr);
    return $out;
}

$crypto->attach( [ CRYPTO_free => '_CRYPTO_free' ] => [ 'opaque', 'string', 'int' ] => 'void' );
sub OPENSSL_free {
    my ($ptr) = @_;
    _CRYPTO_free( _ptr($ptr), __FILE__, __LINE__ );
}

$crypto->attach( 'OBJ_nid2sn' => ['int'] => 'string' );
$crypto->attach( 'OBJ_sn2nid' => ['string'] => 'int' );
$crypto->attach( 'EVP_get_digestbyname' => ['string'] => 'opaque' );
$crypto->attach( 'EVP_MD_get_block_size' => ['opaque'] => 'int' );
$crypto->attach( 'EVP_MD_get_size' => ['opaque'] => 'int' );
$crypto->attach( 'EVP_MD_CTX_new' => [] => 'opaque' );
$crypto->attach( 'EVP_MD_CTX_free' => ['opaque'] => 'void' );
$crypto->attach( 'EVP_DigestInit_ex2' => [ 'opaque', 'opaque', 'opaque' ] => 'int' );
$crypto->attach( 'EVP_DigestUpdate' => [ 'opaque', 'string', 'size_t' ] => 'int' );
$crypto->attach( 'EVP_DigestFinal_ex' => [ 'opaque', 'opaque', 'uint*' ] => 'int' );
$crypto->attach( 'BN_bn2hex' => ['opaque'] => 'string' );
$crypto->attach( 'EC_GROUP_get0_order' => ['opaque'] => 'opaque' );
$crypto->attach( 'EC_GROUP_get_curve' => [ 'opaque', 'opaque', 'opaque', 'opaque', 'opaque' ] => 'int' );
$crypto->attach( 'EC_POINT_new' => ['opaque'] => 'opaque' );
$crypto->attach( 'EC_POINT_invert' => [ 'opaque', 'opaque', 'opaque' ] => 'int' );
$crypto->attach( 'EC_POINT_add' => [ 'opaque', 'opaque', 'opaque', 'opaque', 'opaque' ] => 'int' );
$crypto->attach( 'EC_POINT_set_affine_coordinates' => [ 'opaque', 'opaque', 'opaque', 'opaque', 'opaque' ] => 'int' );
$crypto->attach( 'EC_POINT_get_affine_coordinates' => [ 'opaque', 'opaque', 'opaque', 'opaque', 'opaque' ] => 'int' );
$crypto->attach( 'EC_POINT_point2hex' => [ 'opaque', 'opaque', 'int', 'opaque' ] => 'string' );
$crypto->attach( 'EVP_PKEY_get1_EC_KEY' => ['opaque'] => 'opaque' );

$ffi->attach( 'hexdump' => [ 'string', 'string', 'int' ] => 'void' );
$ffi->attach( 'slurp' => [ 'string', 'opaque*' ] => 'size_t' );
$ffi->attach( 'point2hex' => [ 'string', 'opaque', 'int' ] => 'string' );
$ffi->attach( 'hex2point' => [ 'string', 'string' ] => 'opaque' );
$ffi->attach( 'hex2bn' => ['string'] => 'opaque' );
$ffi->attach( 'bin2hex' => [ 'string', 'size_t' ] => 'string' );
$ffi->attach( 'get_pkey_bn_param' => [ 'opaque', 'string' ] => 'opaque' );
$ffi->attach( '_get_pkey_octet_string_param' => [ 'opaque', 'string', 'opaque*' ] => 'size_t' );
$ffi->attach( 'get_pkey_utf8_string_param' => [ 'opaque', 'string' ] => 'string' );
$ffi->attach( 'export_rsa_pubkey' => ['opaque'] => 'opaque' );
$ffi->attach( '_rsa_oaep_encrypt' => [ 'string', 'opaque', 'string', 'size_t', 'opaque*' ] => 'size_t' );
$ffi->attach( '_rsa_oaep_decrypt' => [ 'string', 'opaque', 'string', 'size_t', 'opaque*' ] => 'size_t' );
$ffi->attach( 'read_key' => ['opaque'] => 'string' );
$ffi->attach( 'read_key_from_der' => ['string'] => 'opaque' );
$ffi->attach( 'read_pubkey_from_der' => ['string'] => 'opaque' );
$ffi->attach( 'read_key_from_pem' => ['string'] => 'opaque' );
$ffi->attach( 'read_pubkey_from_pem' => ['string'] => 'opaque' );
$ffi->attach( 'read_pubkey' => ['opaque'] => 'string' );
$ffi->attach( 'read_ec_pubkey' => [ 'opaque', 'int' ] => 'string' );
$ffi->attach( '_bn_mod_sqrt' => [ 'opaque', 'opaque' ] => 'opaque' );
$ffi->attach( '_aes_cmac' => [ 'string', 'string', 'size_t', 'string', 'size_t', 'size_t*' ] => 'opaque' );
$ffi->attach( '_pkcs12_key_gen' => [ 'string', 'size_t', 'string', 'size_t', 'uint', 'uint', 'string', 'size_t*' ] => 'opaque' );
$ffi->attach( '_pkcs5_pbkdf2_hmac' => [ 'string', 'size_t', 'string', 'size_t', 'uint', 'string', 'size_t*' ] => 'opaque' );
$ffi->attach( '_hmac' => [ 'string', 'string', 'size_t', 'string', 'size_t', 'opaque*' ] => 'int' );
$ffi->attach( '_hkdf' => [ 'int', 'string', 'string', 'size_t', 'string', 'size_t', 'string', 'size_t', 'opaque*', 'size_t' ] => 'int' );
$ffi->attach( '_ecdh' => [ 'opaque', 'opaque', 'size_t*' ] => 'opaque' );
$ffi->attach( 'mul_ec_point' => [ 'string', 'opaque', 'opaque', 'opaque' ] => 'opaque' );
$ffi->attach( 'gen_ec_point' => [ 'string', 'opaque', 'opaque', 'int' ] => 'opaque' );
$ffi->attach( 'gen_ec_key' => [ 'string', 'string' ] => 'opaque' );
$ffi->attach( 'gen_ec_pubkey' => [ 'string', 'string' ] => 'opaque' );
$ffi->attach( 'export_ec_pubkey' => ['opaque'] => 'opaque' );
$ffi->attach( 'write_key_to_der' => [ 'string', 'opaque' ] => 'string' );
$ffi->attach( 'write_key_to_pem' => [ 'string', 'opaque' ] => 'string' );
$ffi->attach( 'write_pubkey_to_der' => [ 'string', 'opaque' ] => 'string' );
$ffi->attach( 'write_pubkey_to_pem' => [ 'string', 'opaque' ] => 'string' );
$ffi->attach( '_ecdsa_sign' => [ 'opaque', 'string', 'string', 'int', 'opaque*' ] => 'int' );
$ffi->attach( '_ecdsa_verify' => [ 'opaque', 'string', 'string', 'int', 'string', 'int' ] => 'int' );
$ffi->attach( '_symmetric_cipher' => [ 'string', 'string', 'int', 'string', 'string', 'int', 'opaque*', 'int' ] => 'int' );
$ffi->attach( '_aead_encrypt' => [ 'string', 'string', 'int', 'string', 'int', 'string', 'string', 'int', 'opaque*', 'opaque*', 'int' ] => 'int' );
$ffi->attach( '_aead_decrypt' => [ 'string', 'string', 'int', 'string', 'int', 'string', 'int', 'string', 'string', 'int', 'opaque*' ] => 'int' );
$ffi->attach( 'print_pkey_gettable_params' => ['opaque'] => 'void' );
$ffi->attach( 'sgn0_m_eq_1' => ['opaque'] => 'int' );
$ffi->attach( 'clear_cofactor' => [ 'opaque', 'opaque', 'opaque', 'opaque' ] => 'int' );
$ffi->attach( 'CMOV' => [ 'opaque', 'opaque', 'int' ] => 'opaque' );
$ffi->attach( 'calc_c1_c2_for_sswu' => [ ( ('opaque') x 7 ) ] => 'int' );
$ffi->attach( 'map_to_curve_sswu_straight_line' => [ ( ('opaque') x 10 ) ] => 'int' );
$ffi->attach( 'map_to_curve_sswu_not_straight_line' => [ ( ('opaque') x 8 ) ] => 'int' );

# sub OBJ_nid2sn { _OBJ_nid2sn(@_) }
# sub OBJ_sn2nid { _OBJ_sn2nid(@_) }
# sub EVP_get_digestbyname { _obj( _EVP_get_digestbyname(@_), 'Crypt::OpenSSL::EC::EVP_MD' ) }
# sub EVP_MD_get_block_size { _EVP_MD_get_block_size( _ptr( $_[0] ) ) }
# sub EVP_MD_get_size { _EVP_MD_get_size( _ptr( $_[0] ) ) }
# sub BN_bn2hex { _BN_bn2hex( _ptr( $_[0] ) ) }
# sub EC_GROUP_get0_order { _obj( _EC_GROUP_get0_order( _ptr( $_[0] ) ), 'Crypt::OpenSSL::Bignum' ) }
# sub EC_GROUP_get_curve { _EC_GROUP_get_curve( map { _ptr($_) } @_ ) }
# sub EC_POINT_new { _obj( _EC_POINT_new( _ptr( $_[0] ) ), 'Crypt::OpenSSL::EC::EC_POINT' ) }
# sub EC_POINT_invert { _EC_POINT_invert( map { _ptr($_) } @_ ) }
# sub EC_POINT_add { _EC_POINT_add( map { _ptr($_) } @_ ) }
# sub EC_POINT_set_affine_coordinates { _EC_POINT_set_affine_coordinates( map { _ptr($_) } @_ ) }
# sub EC_POINT_get_affine_coordinates { _EC_POINT_get_affine_coordinates( map { _ptr($_) } @_ ) }
# sub EC_POINT_point2hex { _EC_POINT_point2hex( _ptr( $_[0] ), _ptr( $_[1] ), $_[2], _ptr( $_[3] ) ) }
# sub EVP_PKEY_get1_EC_KEY { _obj( _EVP_PKEY_get1_EC_KEY( _ptr( $_[0] ) ), 'Crypt::OpenSSL::EC::EC_KEY' ) }

# sub hexdump { _hexdump( $_[0] // '', $_[1] // '', $_[2] ) }
# sub slurp { _slurp(@_) }
# sub point2hex { _point2hex( $_[0], _ptr( $_[1] ), $_[2] ) }
# sub hex2point { _obj( _hex2point(@_), 'Crypt::OpenSSL::EC::EC_POINT' ) }
# sub hex2bn { _obj( _hex2bn(@_), 'Crypt::OpenSSL::Bignum' ) }
# sub bin2hex { _bin2hex( $_[0] // '', length( $_[0] // '' ) ) }
# sub get_pkey_bn_param { _obj( _get_pkey_bn_param( _ptr( $_[0] ), $_[1] ), 'Crypt::OpenSSL::Bignum' ) }
# sub get_pkey_utf8_string_param { _get_pkey_utf8_string_param( _ptr( $_[0] ), $_[1] ) }
# sub export_rsa_pubkey { _obj( _export_rsa_pubkey( _ptr( $_[0] ) ), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub read_key { _read_key( _ptr( $_[0] ) ) }
# sub read_key_from_der { _obj( _read_key_from_der(@_), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub read_pubkey_from_der { _obj( _read_pubkey_from_der(@_), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub read_key_from_pem { _obj( _read_key_from_pem(@_), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub read_pubkey_from_pem { _obj( _read_pubkey_from_pem(@_), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub read_pubkey { _read_pubkey( _ptr( $_[0] ) ) }
# sub read_ec_pubkey { _read_ec_pubkey( _ptr( $_[0] ), $_[1] ) }

sub bn_mod_sqrt { _obj( _bn_mod_sqrt( _ptr( $_[0] ), _ptr( $_[1] ) ), 'Crypt::OpenSSL::Bignum' ) }

# sub mul_ec_point { _obj( _mul_ec_point( $_[0], _ptr( $_[1] ), _ptr( $_[2] ), _ptr( $_[3] ) ), 'Crypt::OpenSSL::EC::EC_POINT' ) }
# sub gen_ec_point { _obj( _gen_ec_point( $_[0], _ptr( $_[1] ), _ptr( $_[2] ), $_[3] ), 'Crypt::OpenSSL::EC::EC_POINT' ) }
# sub gen_ec_key { _obj( _gen_ec_key( $_[0], $_[1] // '' ), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub gen_ec_pubkey { _obj( _gen_ec_pubkey(@_), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub export_ec_pubkey { _obj( _export_ec_pubkey( _ptr( $_[0] ) ), 'Crypt::OpenSSL::EC::EVP_PKEY' ) }
# sub write_key_to_der { _write_key_to_der( $_[0], _ptr( $_[1] ) ) }
# sub write_key_to_pem { _write_key_to_pem( $_[0], _ptr( $_[1] ) ) }
# sub write_pubkey_to_der { _write_pubkey_to_der( $_[0], _ptr( $_[1] ) ) }
# sub write_pubkey_to_pem { _write_pubkey_to_pem( $_[0], _ptr( $_[1] ) ) }
# sub print_pkey_gettable_params { _print_pkey_gettable_params( _ptr( $_[0] ) ) }
# sub sgn0_m_eq_1 { _sgn0_m_eq_1( _ptr( $_[0] ) ) }
# sub clear_cofactor { _clear_cofactor( map { _ptr($_) } @_ ) }
# sub CMOV { _obj( _CMOV( _ptr( $_[0] ), _ptr( $_[1] ), $_[2] ), 'Crypt::OpenSSL::Bignum' ) }
# sub calc_c1_c2_for_sswu { _calc_c1_c2_for_sswu( map { _ptr($_) } @_ ) }
# sub map_to_curve_sswu_straight_line { _map_to_curve_sswu_straight_line( map { _ptr($_) } @_ ) }
# sub map_to_curve_sswu_not_straight_line { _map_to_curve_sswu_not_straight_line( map { _ptr($_) } @_ ) }

 sub ecdh {
     my $len = 0;
     my $ptr = _ecdh( _ptr( $_[0] ), _ptr( $_[1] ), \$len );
     return _bytes_from_ptr( $ptr, $len );
 }

sub hkdf_main {
    my ( $mode, $digest_name, $ikm, $salt, $info, $okm_len ) = @_;
    $ikm  //= '';
    $salt //= '';
    $info //= '';
    my $ptr;
    my $len = _hkdf( $mode, $digest_name, $ikm, length($ikm), $salt, length($salt), $info, length($info), \$ptr, $okm_len );
    return _bytes_from_ptr( $ptr, $len );
}

sub hmac {
    my ( $digest_name, $key, $msg ) = @_;
    $key //= '';
    $msg //= '';
    my $ptr;
    my $len = _hmac( $digest_name, $key, length($key), $msg, length($msg), \$ptr );
    return _bytes_from_ptr( $ptr, $len );
}

sub aes_cmac {
    my ( $cipher_name, $key, $msg ) = @_;
    $key //= '';
    $msg //= '';
    my $len = 0;
    my $ptr = _aes_cmac( $cipher_name, $key, length($key), $msg, length($msg), \$len );
    return _bytes_from_ptr( $ptr, $len );
}

sub pkcs12_key_gen {
    my ( $password, $salt, $id, $iteration, $digest_name ) = @_;
    $password //= '';
    $salt     //= '';
    my $len = 0;
    my $ptr = _pkcs12_key_gen( $password, length($password), $salt, length($salt), $id, $iteration, $digest_name, \$len );
    return _bytes_from_ptr( $ptr, $len );
}

sub pkcs5_pbkdf2_hmac {
    my ( $password, $salt, $iteration, $digest_name ) = @_;
    $password //= '';
    $salt     //= '';
    my $len = 0;
    my $ptr = _pkcs5_pbkdf2_hmac( $password, length($password), $salt, length($salt), $iteration, $digest_name, \$len );
    return _bytes_from_ptr( $ptr, $len );
}

sub digest_array {
    my ( $digest_name, $arr ) = @_;
    my $digest = EVP_get_digestbyname($digest_name);
    my $ctx    = EVP_MD_CTX_new();
    EVP_DigestInit_ex2( $ctx, $digest, undef );
    for my $msg ( @{$arr} ) {
        $msg //= '';
        EVP_DigestUpdate( $ctx, $msg, length($msg) );
    }
    my $out_len = EVP_MD_get_size($digest);
    my $out     = "\0" x $out_len;
    my $got     = $out_len;
    EVP_DigestFinal_ex( $ctx, scalar_to_pointer($out), \$got );
    EVP_MD_CTX_free($ctx);
    return substr( $out, 0, $got );
}

sub ecdsa_sign {
    my ( $priv_key, $sig_name, $msg ) = @_;
    $msg //= '';
    my $ptr;
    my $len = _ecdsa_sign( _ptr($priv_key), $sig_name, $msg, length($msg), \$ptr );
    return _bytes_from_ptr( $ptr, $len );
}

sub ecdsa_verify {
    my ( $pub_key, $sig_name, $msg, $sig ) = @_;
    $msg //= '';
    $sig //= '';
    return _ecdsa_verify( _ptr($pub_key), $sig_name, $msg, length($msg), $sig, length($sig) );
}

sub symmetric_encrypt {
    my ( $cipher_name, $plaintext, $key, $iv ) = @_;
    $plaintext //= '';
    $key       //= '';
    $iv        //= '';
    my $ptr;
    my $len = _symmetric_cipher( $cipher_name, $plaintext, length($plaintext), $key, $iv, length($iv), \$ptr, 1 );
    return _bytes_from_ptr( $ptr, $len );
}

sub symmetric_decrypt {
    my ( $cipher_name, $ciphertext, $key, $iv ) = @_;
    $ciphertext //= '';
    $key        //= '';
    $iv         //= '';
    my $ptr;
    my $len = _symmetric_cipher( $cipher_name, $ciphertext, length($ciphertext), $key, $iv, length($iv), \$ptr, 0 );
    return _bytes_from_ptr( $ptr, $len );
}

sub aead_encrypt {
    my ( $cipher_name, $plaintext, $aad, $key, $iv, $tag_len ) = @_;
    $plaintext //= '';
    $aad       //= '';
    $key       //= '';
    $iv        //= '';
    my ( $ciphertext, $tag );
    my $ciphertext_len = _aead_encrypt( $cipher_name, $plaintext, length($plaintext), $aad, length($aad), $key, $iv, length($iv), \$ciphertext, \$tag, $tag_len );
    return [ _bytes_from_ptr( $ciphertext, $ciphertext_len ), _bytes_from_ptr( $tag, $tag_len ) ];
}

sub aead_decrypt {
    my ( $cipher_name, $ciphertext, $aad, $tag, $key, $iv ) = @_;
    $ciphertext //= '';
    $aad        //= '';
    $tag        //= '';
    $key        //= '';
    $iv         //= '';
    my $ptr;
    my $len = _aead_decrypt( $cipher_name, $ciphertext, length($ciphertext), $aad, length($aad), $tag, length($tag), $key, $iv, length($iv), \$ptr );
    return $len > 0 ? _bytes_from_ptr( $ptr, $len ) : undef;
}

sub get_pkey_octet_string_param {
    my ( $pkey, $param_name ) = @_;
    my $ptr;
    my $len = _get_pkey_octet_string_param( _ptr($pkey), $param_name, \$ptr );
    return _bytes_from_ptr( $ptr, $len );
}

sub rsa_oaep_encrypt {
    my ( $digest_name, $pub, $plaintext ) = @_;
    $plaintext //= '';
    my $ptr;
    my $len = _rsa_oaep_encrypt( $digest_name, _ptr($pub), $plaintext, length($plaintext), \$ptr );
    return _bytes_from_ptr( $ptr, $len );
}

sub rsa_oaep_decrypt {
    my ( $digest_name, $priv, $ciphertext ) = @_;
    $ciphertext //= '';
    my $ptr;
    my $len = _rsa_oaep_decrypt( $digest_name, _ptr($priv), $ciphertext, length($ciphertext), \$ptr );
    return _bytes_from_ptr( $ptr, $len );
}

sub digest {
    my ($digest_name, @arr) = @_;
    return digest_array($digest_name, \@arr);
}

sub hkdf {
# define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND  0
# define EVP_KDF_HKDF_MODE_EXTRACT_ONLY        1
# define EVP_KDF_HKDF_MODE_EXPAND_ONLY         2
    my ($digest_name, $k, $salt, $info, $len) = @_;
    return hkdf_main(0, $digest_name, $k, $salt, $info, $len);
}

sub hkdf_extract {
    my ($digest_name, $k, $salt, $info, $len) = @_;
    return hkdf_main(1, $digest_name, $k, $salt, $info, $len);
}

sub hkdf_expand {
    my ($digest_name, $k, $salt, $info, $len) = @_;
    return hkdf_main(2, $digest_name, $k, $salt, $info, $len);
}



sub sn_point2hex {
    my ($group_name, $point, $point_compress_t) = @_;
    $point_compress_t //= 4;

    my $ec_params_r = get_ec_params($group_name);
    my $point_hex = Crypt::OpenSSL::EC::EC_POINT::point2hex($ec_params_r->{group}, $point, $point_compress_t, $ec_params_r->{ctx});
    return $point_hex;
}


#sub aead_encrypt_split {
    #my ($res, $tag_len) = @_;
    #my $ciphertext = substr $res, 0, length($res) - $tag_len;
    #my $tag = substr $res, length($res) - $tag_len, $tag_len;
    #return ($ciphertext, $tag);
#}

sub random_bn {
    my ($Nn) = @_; 
    my $range_hex = join("", ('ff') x $Nn);
    my $range = Crypt::OpenSSL::Bignum->new_from_hex($range_hex);

    my $random_bn = Crypt::OpenSSL::Bignum->rand_range($range);
    return $random_bn;
}

sub i2osp {
    my ($len, $L) = @_;  

    my $s = pack "C*", $len;
    $s = unpack("H*", $s);

    my $s_len = length($s);
    my $tmp_l = $L*2;
    if($tmp_l > $s_len){
        my $pad_len = $tmp_l - $s_len;
        substr $s, 0, 0, ('0') x $pad_len;
    }   

    $s = pack("H*", $s);

    return $s; 
}

sub generate_ec_key {
    my ( $group_name, $priv_hex ) = @_;

    ### generate_ec_key

    my $priv_pkey = gen_ec_key($group_name, $priv_hex || '');
    $priv_hex = read_key($priv_pkey);
    my $priv_bn  = Crypt::OpenSSL::Bignum->new_from_hex($priv_hex);
   
    ### $priv_hex

    my $pub_pkey = export_ec_pubkey($priv_pkey);

    ### $pub_pkey
    
    ### read_pubkey: read_pubkey($pub_pkey)

    my $pub_hex = read_ec_pubkey($pub_pkey, 1);

    ### $pub_hex

    my $pub_bin  = pack( "H*", $pub_hex );

    my $pub_point =hex2point($group_name, $pub_hex);

    return {
        name => $group_name, 
        priv_pkey => $priv_pkey, 
        #priv_key => $priv_key, 
        priv_bn => $priv_bn,
        pub_pkey => $pub_pkey, 
        pub_point => $pub_point, 
        pub_hex => $pub_hex, 
        pub_bin => $pub_bin,
    };

} ## end sub generate_ec_key

sub get_ec_params {
    my ( $group_name ) = @_;

    my $nid   = OBJ_sn2nid( $group_name );
    my $group = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name( $nid );
    my $ctx   = Crypt::OpenSSL::Bignum::CTX->new();


    my $p = Crypt::OpenSSL::Bignum->new();
    my $a = Crypt::OpenSSL::Bignum->new();
    my $b = Crypt::OpenSSL::Bignum->new();
    EC_GROUP_get_curve( $group, $p, $a, $b, $ctx );

    my $degree = Crypt::OpenSSL::EC::EC_GROUP::get_degree($group);

    my $order = Crypt::OpenSSL::Bignum->new();
    Crypt::OpenSSL::EC::EC_GROUP::get_order($group, $order, $ctx);

    my $cofactor = Crypt::OpenSSL::Bignum->new();
    Crypt::OpenSSL::EC::EC_GROUP::get_cofactor($group, $cofactor, $ctx);

    return {
        nid => $nid,
        name => $group_name,
        group =>$group,
        p => $p, a=> $a, b=>$b, degree => $degree, order=> $order, cofactor=>$cofactor,
        ctx=> $ctx,
    };
}

# Hash2Curve

our %H2C_CNF = (
  'prime256v1' => {
      k => 0x80,
      m => 1,
      'sswu' => {
          z                 => '-10',
          calc_c1_c2_func   => \&calc_c1_c2_for_sswu,
          map_to_curve_func => \&map_to_curve_sswu_straight_line,
      },
  },
);

sub sn2kv {
my ($group_name, $param_name) = @_;
return $H2C_CNF{$group_name}{$param_name};
}


sub get_hash2curve_params {
    my ( $group_name, $type ) = @_;

    my $ec_params_r = get_ec_params($group_name);
    
    $ec_params_r->{$_} = $H2C_CNF{$group_name}{$_} for keys(%{$H2C_CNF{$group_name}});

    if($type eq 'sswu'){
        my $z = Crypt::OpenSSL::Bignum->new_from_decimal( $H2C_CNF{$group_name}{$type}{z} );
        my $c1 = Crypt::OpenSSL::Bignum->new();
        my $c2 = Crypt::OpenSSL::Bignum->new();
        $H2C_CNF{$group_name}{$type}{calc_c1_c2_func}->( $c1, $c2, 
            @{$ec_params_r}{qw/p a b/}, 
            $z, 
            $ec_params_r->{ctx}, 
        );

        @{$ec_params_r}{qw/c1 c2 z/} = ($c1, $c2, $z);

    }

    $ec_params_r;
} ## end sub get_hash2curve_params

sub hash_to_curve {
  my ( $msg, $DST, $group_name, $type, $hash_name, $expand_message_func, $clear_cofactor_flag ) = @_;

  my $h2c_r = get_hash2curve_params( $group_name, $type );
  #my ( $group, $c1, $c2, $p, $a, $b, $z, $ctx ) = @$params_ref;

  my $count = 2;
  #my ( $k, $m ) = sn2k_m( $group_name );
  my @res = hash_to_field( $msg, $count, $DST, $h2c_r->{p}, $h2c_r->{m}, $h2c_r->{k}, $hash_name, $expand_message_func );

  my $u0 = $res[0][0];
  my $Q0 = map_to_curve( $h2c_r, $group_name, $type, $u0, $clear_cofactor_flag );

  my $u1 = $res[1][0];
  my $Q1 = map_to_curve( $h2c_r, $group_name, $type, $u1, $clear_cofactor_flag );

  my $Q = Crypt::OpenSSL::EC::EC_POINT::new( $h2c_r->{group} );
  Crypt::OpenSSL::EC::EC_POINT::add( $h2c_r->{group}, $Q, $Q0, $Q1, $h2c_r->{ctx} );

  return $Q unless ( $clear_cofactor_flag );

  my $P = Crypt::OpenSSL::EC::EC_POINT::new( $h2c_r->{group} );
  clear_cofactor( $h2c_r->{group}, $P, $Q, $h2c_r->{ctx} );

  return wantarray ? ($P, $h2c_r) : $P;
} ## end sub hash_to_curve

sub encode_to_curve {
  my ( $msg, $DST, $group_name, $type, $hash_name, $expand_message_func, $clear_cofactor_flag ) = @_;

  my $h2c_r = get_hash2curve_params( $group_name, $type );
  #my ( $group, $c1, $c2, $p, $a, $b, $z, $ctx ) = @$params_ref;

  my $count = 1;
  #my ( $k, $m ) = sn2k_m( $group_name );
  #my @res = hash_to_field( $msg, $count, $DST, $p, $m, $k, $hash_name, $expand_message_func );
  my @res = hash_to_field( $msg, $count, $DST, $h2c_r->{p}, $h2c_r->{m}, $h2c_r->{k}, $hash_name, $expand_message_func );

  my $u = $res[0][0];
  my $P = map_to_curve( $h2c_r, $group_name, $type, $u, $clear_cofactor_flag );
  return wantarray ? ($P, $h2c_r) : $P;
}

sub map_to_curve {
  my ( $params_ref, $group_name, $type, $u, $clear_cofactor_flag ) = @_;

  #my ( $group, $c1, $c2, $p, $a, $b, $z, $ctx ) = @$params_ref;

  my $x = Crypt::OpenSSL::Bignum->new();
  my $y = Crypt::OpenSSL::Bignum->new();
  $H2C_CNF{$group_name}{$type}{map_to_curve_func}->( 
      @{$params_ref}{qw/c1 c2 p a b z/}, 
      $u, $x, $y, $params_ref->{ctx} );

  ### $u 
  my $Q = gen_ec_point($group_name, $x, $y, $clear_cofactor_flag);

  ### $Q

  return $Q;
} ## end sub map_to_curve



#sub CMOV {
#my ($a, $b, $c) = @_;
#return $b if($c);
#return $a;
#}

sub hash_to_field {
  my ( $msg, $count, $DST, $p, $m, $k, $hash_name, $expand_message_func ) = @_;

  my $ctx = Crypt::OpenSSL::Bignum::CTX->new();

  my $L = $p->num_bits;
  $L = ceil(($L + $k)/8);
  ### $L

  my $len_in_bytes  = $count * $m * $L;
  ### len_in_bytes: $len_in_bytes
  my $uniform_bytes = $expand_message_func->( $msg, $DST, $len_in_bytes, $hash_name );
  ### uniform_bytes: unpack("H*", $uniform_bytes)

  my @res;
  for my $i ( 0 .. $count - 1 ) {
    my @u;
    for my $j ( 0 .. $m - 1 ) {
      my $elm_offset = $L * ( $j + $i * $m );
      my $tv         = substr( $uniform_bytes, $elm_offset, $L );

      my $tv_bn =  Crypt::OpenSSL::Bignum->new_from_bin( $tv );
      my $reminder = $tv_bn->mod($p, $ctx);
      ### reminder: $reminder->to_hex()
      ### reminder: $reminder->to_decimal()
      
      push @u, $reminder;
    }
    push @res, \@u;
  }
  return @res;
} ## end sub hash_to_field

sub expand_message_xmd {
  my ( $msg, $DST, $len_in_bytes, $hash_name ) = @_;

  #my $h_r = Crypt::OpenSSL::EVP::MD->new( $hash_name );
  my $h_r = EVP_get_digestbyname( $hash_name );

  my $hash_size = EVP_MD_get_size( $h_r );
  #my $ell = ceil( $len_in_bytes / $h_r->size() );
  #my $ell = ceil( $len_in_bytes / $hash_size );
  my $ell = ceil( $len_in_bytes / $hash_size );
  return if ( $ell > 255 );

  ### len_in_bytes: $len_in_bytes
  ### md get size : EVP_MD_get_size( $h_r )
  ### ell: $ell

  my $DST_len     = length( $DST );
  my $DST_len_hex = pack( "C*", $DST_len );
  my $DST_prime   = $DST . $DST_len_hex;
  ### DST: unpack("H*", $DST)
  ### $DST_len
  ### DST_len_hex: unpack("H*", $DST_len_hex)
  ### DST_prime: unpack("H*", $DST_prime)
  
  my $rn    = EVP_MD_get_block_size( $h_r ) * 2;
  my $Z_pad = pack( "H$rn", '00' );

  my $l_i_b_str = pack( "S>", $len_in_bytes );

  my $zero = pack( "H*", '00' );

  my $msg_prime = $Z_pad . $msg . $l_i_b_str . $zero . $DST_prime;
  ### msg_prime: unpack("H*", $msg_prime)
  
  my $len       = pack( "C*", 1 );
  my $b0        = digest( $hash_name, $msg_prime );


  my $b1 = digest( $hash_name, $b0 . $len . $DST_prime );

  ### b0: unpack("H*", $b0)
  ### b1: unpack("H*", $b1)

  #my $b0  = $h_r->digest( $msg_prime );
  #my $b1  = $h_r->digest( $b0 . $len . $DST_prime );

  my $b_prev        = $b1;
  my $uniform_bytes = $b1;
  for my $i ( 2 .. $ell ) {
    my $tmp = ( $b0 ^ $b_prev ) . pack( "C*", $i ) . $DST_prime;
    my $bi  = digest( $hash_name, $tmp );

    ### bi: unpack("H*", $bi)

    $uniform_bytes .= $bi;
    $b_prev = $bi;
  }

  ### uniform_bytes: unpack("H*", $uniform_bytes)
  my $res = substr( $uniform_bytes, 0, $len_in_bytes );
  ### res: unpack("H*", $res)

  return $res;
} ## end sub expand_message_xmd

1;
__END__
