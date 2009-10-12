#!/usr/bin/perl
use strict;
use warnings;
use Test::More;

use FindBin '$Bin';
use lib "$Bin/../lib";
use_ok "Crypt::Password";

{
    # hash something
    my $text = "crypticatest";
    my $c = Crypt::Password->new($text);
    ok(!$c->password, "password vanishes");
    
    my $salt = $c->salt;
    ok($salt, "salt appears");
    like($salt, qr{^.{8}$}, "salt looks good");
    
    my $hash = $c->crypted;
    ok($hash, "hash appears");
    my $beginning = '$5$'.$salt.'$';
    like($hash, qr{^\Q$beginning\E\S{20,}$}, "hash looks good");
    
    ok($c->check($text), "validates original text");
    ok(!$c->check("$text and stuff"), "invalidates other text");
}

for my $digest (undef, "md5", "sha256", "sha512") {
    # supplied salt
    my $text = "Thiruvaaimozhi";
    my $salt = "saltstring";
    my $expected_crypted = 
        !defined($digest) || $digest eq "sha256" ?
            '$5$saltstring$rQ06cRdm6VM1iT1AJX2WVoanGxfD2ZhQyHE3HikNs51'
        : $digest eq "md5" ?
            '$1$saltstri$dTa7uW4.I4xwD1OFLWer7/'
        : $digest eq "sha512" ?
            '$6$saltstring$IYc0k2/8BA5f7yx6oiZCTQhxpWpY.clHT9zQ/chgMUKQImVFolKbwnUHQZUwGMQuH4zMkC1SaNYqf9GG2SGzf/'
        : die "no such digest: $digest";
    
    my $c = Crypt::Password->new($text, $salt, $digest);
    ok(ref $c, "gave Crypt::Password a salt string and ".($digest||"no")." digest algorithm");
    
    is($c->salt, $salt, "salt attribute correct");
    is($c->crypted, $expected_crypted, "crypted output correct");
    my $crypted = $c->crypted;
    is("$c", $crypted, 'overloaded: ""');
    is($c."blah", $crypted."blah", "overloaded: .");
    ok($c eq $crypted, "overloaded: eq");
    
    # supply another password
    my $moretext = "something else";
    $c->password($moretext);
    isnt($c, $crypted, "password re-hashed");
    is($c->salt, $salt, "salt stays the same");
    ok(!$c->password, "password vanishes");
    ok($c->check($moretext), "password validates");
    ok(!$c->check($text), "old password invalidates");
}

{
    # already crypted
    my $password = '$5$saltstring$rQ06cRdm6VM1iT1AJX2WVoanGxfD2ZhQyHE3HikNs51';
    my $c = Crypt::Password->new($password);
    ok(ref $c, "gave Crypt::Password an already encrypted password");
    is($c->crypted, $password, "crypted-ness maintained");
    is($c->salt, "saltstring", "extracted the correct salt");
    ok($c->check("Thiruvaaimozhi"), "validates original string");
}

done_testing();

