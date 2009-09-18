#!/usr/bin/perl
use strict;
use warnings;
use feature ':5.10';

package Crypt::;
use Moose;

use overload
    '""' => \&crypt,
    'eq' => \&crypt,
    'nomethod' => \&crypt;

has 'password' => (
    is => 'rw',
    trigger => \&_crypt,
    required => 1,
    clearer => 'forget_password',
);

has 'crypted' => (
    is => 'rw',
);

has 'salt'=> (
    is => 'rw',
    lazy_build => 1,
    builder => '_invent_salt',
);

# from libc6 crypt/crypt-entry.c
my %magic_strings = (
    md5 => '$1$',
    sha256 => '$5$',
    sha512 => '$6$',
);
has 'digest' => (
    is => 'rw',
    default => sub { "sha256" },
);

sub check {
    my $self = shift;
    my $plaintext = shift;
    
    CORE::crypt($plaintext, $self) eq "$self";
}

sub crypt {
    my $self = shift;
    wantarray ? ($self->crypted, $self->salt) : $self->crypted;
}

sub _crypt {
    my $self = shift;
    
    my $digest = $self->digest;
    my $magic_string = $magic_strings{$digest}
        || die "no such digest algorithm: $digest";
    my $salt = $magic_string.$self->salt;
    my $password = $self->password;
    my $crypted = CORE::crypt($password, $salt);
    
    $self->crypted($crypted);
    $self->forget_password();
    $crypted;
}

sub _invent_salt {
    my $self = shift;
    my $salt = "SteveSteveSteve";
    $self->salt($salt);
}

sub BUILDARGS {
    my $class = shift;
    my %args;
    $args{password} = shift;
    $args{salt} = shift if @_;
    $args{digest} = shift if @_;
    \%args
}

package main;

use Test::More;

{
    diag "hash something";
    my $text = "crypticatest";
    my $c = Crypticate->new($text);
    ok(!$c->password, "password vanishes");
    
    my $salt = $c->salt;
    ok($salt, "salt appears");
    like($salt, qr{.{8}}, "salt looks good");
    
    my $hash = $c->crypted;
    ok($hash, "hash appears");
    like($hash, qr{^\$5\$$salt\$...}, "hash looks good");
    
    ok($c->check($text), "validates original text");
    ok(!$c->check("$text and stuff"), "invalidates other text");
}

{
    diag "supplied salt";
    my $text = "crypticatest";
    my $salt = "saltstring";
    my $c = Crypticate->new($text, $salt);
    is($c->salt, $salt, "salt attribute correct");
    like($c->crypted, qr{^\$5\$$salt\$...}, "crypted salt correct");
    my $crypted = $c->crypted;
    is("$c", $crypted, "crypted overloaded");
    
    diag "supply another password";
    my $moretext = "something else";
    $c->password($moretext);
    isnt($c, $crypted, "password re-hashed");
    is($c->salt, $salt, "salt stays the same");
    ok(!$c->password, "password vanishes");
    ok($c->check($moretext), "password validates");
    ok(!$c->check($text), "old password invalidates");
}

done_testing();










