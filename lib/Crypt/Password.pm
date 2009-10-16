package Crypt::Password;
use Moose;

our $VERSION = "0.04";

# TODO write export crypt_password($plain) and check_password($plain, $hashed)

use overload
    '""' => \&crypt,
    'eq' => \&crypt,
    'nomethod' => \&crypt;

has 'password' => (
    is => 'rw',
    trigger => sub { shift->_crypt() },
    required => 1,
    clearer => 'forget_password',
);

has 'crypted' => (
    is => 'rw',
    predicate => 'is_crypted',
);

has 'salt'=> (
    is => 'ro',
    lazy_build => 1,
    builder => '_invent_salt',
);

# from libc6 crypt/crypt-entry.c
my %magic_strings = (
    md5 => '$1$',
    sha256 => '$5$',
    sha512 => '$6$',
);
# TODO could be figured out from pre-crypted text like salt is
has 'digest' => (
    is => 'ro',
    default => sub { "sha256" },
);

sub check {
    my $self = shift;
    my $plaintext = shift;
    
    CORE::crypt($plaintext, $self) eq "$self";
}

sub string_is_crypted {
    $_[1] && $_[1] =~ m{^\$\d+\$.*\$.+$};
}

sub crypt {
    my $self = shift;
    $self->crypted;
}

sub _crypt {
    my ($self, $password) = @_;
    
    my $digest = $self->digest;
    my $magic_string = $magic_strings{$digest}
        || die "no such digest algorithm: $digest";
    my $salt = $magic_string.$self->salt;
    
    return CORE::crypt($password, $salt);
}

around '_crypt' => sub {
    my ($orig, $self) = @_;
    
    my $crypted;
    my $password = $self->password;
    if ($self->string_is_crypted($password)) {
        $crypted = $password;
    }
    else {
        $crypted = $self->$orig($password);
    }
    $self->crypted($crypted);
    $self->forget_password();
    $crypted;
};

our @valid_salt = ( "a".."z", "A".."Z", "0".."9", qw(/ \ ! @ % ^), "#" );

sub _invent_salt {
    join "", map { $valid_salt[rand(@valid_salt)] } 1..8;
}

around '_invent_salt' => sub {
    my ($orig, $self) = @_;
    
    my $salt;
    if ($self->is_crypted) {
        $salt = (split /\$/, $self->crypted)[2];
    }
    else {
        $salt = $self->$orig();
    }
    return $salt
};

sub BUILDARGS {
    my $class = shift;
    my %args;
    for ("password", "salt", "digest") {
        $args{$_} = shift if @_;
        delete $args{$_} unless defined $args{$_};
    }
    \%args
}

1;

__END__

=head1 NAME

Crypt::Password - Unix-style, Variously Hashed Passwords

=head1 SYNOPSIS

 use Crypt::Password;
 
 # sha256, generated salt:
 my $hashed = Crypt::Password->new("password");
 
 # the above $hashed might look like:
 # $5$%RK2BU%L$aFZd1/4Gpko/sJZ8Oh.ZHg9UvxCjkH1YYoLZI6tw7K8
 # the format goes $digest$salt$hash
 
 say $hashed->check("password") ? "correct" : "wrong";
 
 # sha256, supplied salt:
 my $hashed = Crypt::Password->new("password", "salt");
 
 # md5, no salt:
 my $hashed = Crypt::Password->new("password", "", "md5");

=head1 DESCRIPTION

This is just a wrapper for perl's crypt(), which can do everything you would
probably want to do to store a password, but this is supposed to provide the
various uses easier.

Given a string it defaults to using sha256 and generates a salt for you.  The
salt can be supplied as the second argument to the constructor, or avoided by
passing an empty string. The digest algorithm can be supplied as the third
argument to the constructor.

=head1 KNOWN ISSUES

Doesn't seem to work on Darwin.

=head1 SUPPORT, SOURCE

If you have a problem, submit a test case via a fork of the github repo.

 http://github.com/st3vil/crypt-password

=head1 AUTHOR AND LICENCE

Code by Steve Craig, L<steve@catalyst.net.nz>, idea by Sam Vilain,
L<sam.vilain@catalyst.net.nz>.  Development commissioned by NZ
Registry Services.

Copyright 2009, NZ Registry Services.  This module is licensed under
the Artistic License v2.0, which permits relicensing under other Free
Software licenses.

=head1 SEE ALSO

L<Digest::SHA>, L<Authen::Passphrase>, L<Crypt::SaltedHash>

=cut

