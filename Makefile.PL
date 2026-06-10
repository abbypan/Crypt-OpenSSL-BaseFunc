use strict;
use warnings;

use ExtUtils::MakeMaker;
use FFI::Build::MM;
#use Config;
use Crypt::OpenSSL::Guess;

# This is similar to what Crypt::OpenSSL::EC, Crypt::OpenSSL::RSA does.

my $openssl_local_lib = qq[ -L/usr/local/openssl/lib64 -L/usr/local/openssl/lib -L/usr/local/lib64 -L/usr/local/lib ];
my $openssl_local_inc = qq[ -I/usr/local/openssl/include -I/usr/local/include ];

my $fbmm = FFI::Build::MM->new(
    cflags => $openssl_local_inc . openssl_inc_paths() . ' -DOPENSSL_NO_KRB5',
    libs   => $openssl_local_lib . openssl_lib_paths() . ' -lssl -lcrypto',
);

WriteMakefile(
    $fbmm->mm_args(
    NAME              => 'Crypt::OpenSSL::BaseFunc',
    AUTHOR             => 'Pan Lanlan <abbypan@gmail.com>',
    VERSION_FROM      => 'BaseFunc.pm',
    ABSTRACT  => 'Crypt Base Functions, using the OpenSSL libraries', 
    'LICENSE'  => 'Mozilla_2_0', 
    'DISTNAME'         => 'Crypt-OpenSSL-BaseFunc',
    CONFIGURE_REQUIRES => {
        'Crypt::OpenSSL::Guess' => 0.12,
        'ExtUtils::MakeMaker'   => 0,
        'FFI::Build::MM'        => 1.00,
    },
    BUILD_REQUIRES => {
        'FFI::Build::MM' => 1.00,
    },
    PREREQ_PM         => { 
        'Carp' => 0.01,
        'Crypt::OpenSSL::Bignum' => 0.09,
        'Crypt::OpenSSL::EC' => 1.31,
        'FFI::CheckLib' => 0.28,
        'FFI::Platypus' => 1.00,
        'Crypt::OpenSSL::Guess' => 0.12,
        'Math::BigInt' => 1.999815,
        'Test' => 0.01,
        'Test::More' => 0.01,
        'bignum' => 0.52, 
    }, 
    EXE_FILES => [ 'bin/ec_conv.pl' ], 
    'MIN_PERL_VERSION' => 5.006,

    'dist'  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    'clean' => { FILES    => 'Crypt-OpenSSL-BaseFunc-*' },

    (
        $ExtUtils::MakeMaker::VERSION >= 6.46
        ? (
            'META_MERGE' => {
                recommends => {
                    'Crypt::OpenSSL::Bignum' => 0.09,
                },
                configure_requires => {
                    'Crypt::OpenSSL::Guess' => 0.12,
                    'FFI::Build::MM' => 1.00,
                },
                build_requires => {
                    'Test' => 0,    # For testing
                    'Test::More' => 0.01,
                    'Carp' => 0.01,
                    'Crypt::OpenSSL::Bignum' => 0.09,
                    'Crypt::OpenSSL::EC' => 1.31,
                    'Crypt::OpenSSL::Guess' => 0.12,
                    'FFI::Build::MM' => 1.00,
                    'FFI::CheckLib' => 0.28,
                    'FFI::Platypus' => 1.00,
                    'bignum' => 0.52, 
                },
                resources => {
                    'license'    => 'http://dev.perl.org/licenses/',
                    'homepage'   => 'http://github.com/abbypan/Crypt-OpenSSL-BaseFunc',
                    'bugtracker' => 'https://github.com/abbypan/Crypt-OpenSSL-BaseFunc/issues',
                    'repository' => 'http://github.com/abbypan/Crypt-OpenSSL-BaseFunc',
                }
            }
        )
        : ()
    ),
    ),
);

sub MY::postamble {
    $fbmm->mm_postamble;
}
