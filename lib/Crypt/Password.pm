package Crypt::Password;
use Moose;

# TODO documentation
# TODO maybe export a nice tidy factory

use overload
    '""' => \&crypt,
    'eq' => \&crypt,
    'nomethod' => \&crypt;

has 'password' => (
    is => 'rw',
    trigger => sub { shift->_crypt() }, # needs around modifier
    required => 1,
    clearer => 'forget_password',
);

has 'crypted' => (
    is => 'rw',
    predicate => 'is_crypted',
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
# TODO could be figured out from pre-crypted text like salt is
has 'digest' => (
    is => 'rw',
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

1
