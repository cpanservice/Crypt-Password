#!/usr/bin/perl
use strict;
use warnings;

package Crypt::Password;
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

our @valid_salt = ( "a".."z", "A".."Z", "0".."9", qw(/ \ ! @ # % ^) );

sub _invent_salt {
    my $self = shift;
    my $salt = join "", map { $valid_salt[rand(@valid_salt)] } 1..8;
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










