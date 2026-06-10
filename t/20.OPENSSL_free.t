#!/usr/bin/perl
use utf8;
use Test::More;
use Crypt::OpenSSL::BaseFunc;

ok( __PACKAGE__->can('OPENSSL_free'), 'OPENSSL_free is exported' );
ok( __PACKAGE__->can('OBJ_nid2sn'), 'OBJ_nid2sn is exported' );
ok( __PACKAGE__->can('OBJ_sn2nid'), 'OBJ_sn2nid is exported' );
ok( __PACKAGE__->can('slurp'), 'slurp is exported' );
ok( __PACKAGE__->can('bin2hex'), 'bin2hex is exported' );

open my $pm_fh, '<', 'BaseFunc.pm' or die "BaseFunc.pm: $!";
my $pm = do { local $/; <$pm_fh> };

unlike( $pm, qr/\$ffi->attach\(\s*\[/, 'bundled FFI attach calls do not rename functions' );
unlike( $pm, qr/\$crypto->attach\(\s*\[\s*OBJ_nid2sn\s*=>\s*'_OBJ_nid2sn'\s*\]/, 'OBJ_nid2sn attach does not rename function' );

done_testing();
