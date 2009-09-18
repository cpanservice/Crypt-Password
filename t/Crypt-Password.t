#!/usr/bin/perl
use strict;
use warnings;
use Test::More;

use_ok Crypt::Password;

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

