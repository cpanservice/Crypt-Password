#!/usr/bin/perl
use strict;
use warnings;
use Test::More 'no_plan';

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

    diag("first test crypted to $c");
    
    ok($c->check($text), "validates original text");
    ok(!$c->check("$text and stuff"), "invalidates other text");
}

my $results = {
    '11' => {
	'sha512' => '$6$SoThEnIaDdE$nnfhAn48thZOO5AcmBTPnZjXD1gNjUbjnpBpYq/4gAoUjTZw.cLeD0G0oi3lZS/CBRIldoc17EYUCaeq16T/V/',
	'sha256' => '$5$SoThEnIaDdE$PJERMX0fCmjfaOUTKDGSbDlK3E59ey2NgFHB815YMs3',
	'undef' => '$5$SoThEnIaDdE$PJERMX0fCmjfaOUTKDGSbDlK3E59ey2NgFHB815YMs3',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '7' => {
	'sha512' => '$6$SoThEnI$u1xvfHYyvFA1G0Qd/BRm04IZfN7IFddvLLe9st/vsLEfPbGAHDNRXOecW9zz8ZzwLKFMVrZeRt/9UtdkNJ0LL1',
	'sha256' => '$5$SoThEnI$XPHK/f/CI49YK8b9Ojil1qkcUL8AnhIocZLDIPYL0f7',
	'undef' => '$5$SoThEnI$XPHK/f/CI49YK8b9Ojil1qkcUL8AnhIocZLDIPYL0f7',
	'md5' => '$1$SoThEnI$Fe9Yeo7LZ9FGhWtfgpshG/'
    },
    '2' => {
	'sha512' => '$6$So$jht1ZnncpqpP49mXMZatSSXmxy6ny7Q9Fo3o1cqJW5MfJR2yRLDebTkqmE7pFFTk0fcWet/7TQ8SL8W4w41p..',
	'sha256' => '$5$So$YYgGHls93H5wrbGZ5d2/lN6yvnp3yLJBsx.PDJcWdjB',
	'undef' => '$5$So$YYgGHls93H5wrbGZ5d2/lN6yvnp3yLJBsx.PDJcWdjB',
	'md5' => '$1$So$tgw.rCZ0DRJhCDxZ7LV4O/'
    },
    '1' => {
	'sha512' => '$6$S$8ZK8K9ZA1Km.U7baZfd.lExs.Rqia4pB5iK6Ti2XrZlrZLPEqDv1z6.mAOmC3eIiBkJ25eefYskBrTVQLzEyT/',
	'sha256' => '$5$S$81tCtQfDWs0peD7RQV2pSPhee2PrN2Iag3dCNAvMji7',
	'undef' => '$5$S$81tCtQfDWs0peD7RQV2pSPhee2PrN2Iag3dCNAvMji7',
	'md5' => '$1$S$dDzDEq5m.FZkWDwWdKpbL.'
    },
    '16' => {
	'sha512' => '$6$SoThEnIaDdEdMoRe$Ap8GxsTS7g2ubled/7uPK0YSU3.2IqekUH/VdAxZQ/kp1f9GZmQI3uaEkxty1xvGaNZLcpd4mXOGAR4L3ScI8/',
	'sha256' => '$5$SoThEnIaDdEdMoRe$FqBL07gEbeEqY9e0oVWKp9CRIdrVeIx5XTgRu/GShS2',
	'undef' => '$5$SoThEnIaDdEdMoRe$FqBL07gEbeEqY9e0oVWKp9CRIdrVeIx5XTgRu/GShS2',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '13' => {
	'sha512' => '$6$SoThEnIaDdEdM$gRiueAcz0yfmPqdovL3bV6izFAST7FNA83UW5DZZOqYTfPc/sAp/ZRwb.rS5YAF3Ew1q5oEPwX2pE9Rm5r8Gx/',
	'sha256' => '$5$SoThEnIaDdEdM$ulJ6yRafLTW43/xV2nFA8.Ca1WnKf4IXCS9tzhbbDj/',
	'undef' => '$5$SoThEnIaDdEdM$ulJ6yRafLTW43/xV2nFA8.Ca1WnKf4IXCS9tzhbbDj/',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '6' => {
	'sha512' => '$6$SoThEn$s3LnKJgLwufR5IRoejNEtmkg5D5IjWD6g/UFpoDKARoChHP8Iaagrw43wXQbN/5qPJM/gVWMFcV98TF/.JWms1',
	'sha256' => '$5$SoThEn$vHIDfZjlUFo5hcQVZxnsF4rA/jXVCVl0GVLwibFbyM5',
	'undef' => '$5$SoThEn$vHIDfZjlUFo5hcQVZxnsF4rA/jXVCVl0GVLwibFbyM5',
	'md5' => '$1$SoThEn$qRykMfGNHlT1vkBUwYKKs/'
    },
    '3' => {
	'sha512' => '$6$SoT$EU.zZP.0sUbBD.nGjMc2HkumULg/XplxIUTNH3KGpJOu6BKKB32Ey8OQBpAVDh0u3ss3JE.gBcgIONBdgfu9Q.',
	'sha256' => '$5$SoT$fqmLDMGZHiEu8wKkiDZSRLnCiw.gDX4KtXlfxMrVKe0',
	'undef' => '$5$SoT$fqmLDMGZHiEu8wKkiDZSRLnCiw.gDX4KtXlfxMrVKe0',
	'md5' => '$1$SoT$hMmo4PqyVEkDXlwyY.b4e/'
    },
    '9' => {
	'sha512' => '$6$SoThEnIaD$PFZOlRWChqSRNyyT0yU9gnfFydyAsRpBcThp2Qz6RvLRu/vHxLRyKqqZS3Um3GsRHUCL5egLJwd8a3TcwCvf20',
	'sha256' => '$5$SoThEnIaD$S0Ri2jXd6GjpcykYbH7IqRTmw4PTEPtu.ayYVFnSIh5',
	'undef' => '$5$SoThEnIaD$S0Ri2jXd6GjpcykYbH7IqRTmw4PTEPtu.ayYVFnSIh5',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '12' => {
	'sha512' => '$6$SoThEnIaDdEd$9BQJpQDoIHw43XdUQauIldTx/LrjfzVfcSzaoWSmCFtcEuRKOsO1g5E..bAfcWchJzjWA5unp6t3sfNiHkzv41',
	'sha256' => '$5$SoThEnIaDdEd$XtWFrT81bnozZL3rupiSqz.2v1u6Clrf/GXnK17BT23',
	'undef' => '$5$SoThEnIaDdEd$XtWFrT81bnozZL3rupiSqz.2v1u6Clrf/GXnK17BT23',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '14' => {
	'sha512' => '$6$SoThEnIaDdEdMo$yMrMXb6usJFSigvtL1w1MQdKoQc1mCuu/YM0bFOLFMjvRaXHQLegYtnFqQXcDwJCXgiV97nsWMkORPRvq8khk1',
	'sha256' => '$5$SoThEnIaDdEdMo$KbF3Br12/KJja/KivZtWoz3JusV83/fdECxXwLWybL6',
	'undef' => '$5$SoThEnIaDdEdMo$KbF3Br12/KJja/KivZtWoz3JusV83/fdECxXwLWybL6',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '15' => {
	'sha512' => '$6$SoThEnIaDdEdMoR$KWTNGq6Iq9Igz0VCiiEP8E5cn2XD3tpx8.oq2sy741kKqzzGJAbhmrfKxAaWBxdVUD.Y.NFRqnRASGvU2fUT8.',
	'sha256' => '$5$SoThEnIaDdEdMoR$a.E.gvbzZy5ME8V8GgJ1a4fCf7K1Zu8a33MkQiiQym8',
	'undef' => '$5$SoThEnIaDdEdMoR$a.E.gvbzZy5ME8V8GgJ1a4fCf7K1Zu8a33MkQiiQym8',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '8' => {
	'sha512' => '$6$SoThEnIa$aUrs.NqWPv8kGT4cknn68DCubwDLyVOzlQ5pMtzOWIFqZqVzwGz8xr7H7fEveBQ.s/tVqfT5wl/CAXNxSM6A60',
	'sha256' => '$5$SoThEnIa$fWh70Vw1PZxmrh3Eo3EC.VJ3gZyC4Nx/2kSbxx4Eyv2',
	'undef' => '$5$SoThEnIa$fWh70Vw1PZxmrh3Eo3EC.VJ3gZyC4Nx/2kSbxx4Eyv2',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '4' => {
	'sha512' => '$6$SoTh$BjE8AF6A6ONpF62Og8kFvEuhXAsluybeROgbsBNaZgX07gG90bVPc.LmQ5RgANTgJY5uBr3kCKIEY.wpx8Uki1',
	'sha256' => '$5$SoTh$4wJAQGQCSlkQBsbkQ.4iQQ6WPUEWFV4ZgNJst3tBq4D',
	'undef' => '$5$SoTh$4wJAQGQCSlkQBsbkQ.4iQQ6WPUEWFV4ZgNJst3tBq4D',
	'md5' => '$1$SoTh$PctPs/6pDcF8C4BKuGDtp.'
    },
    '10' => {
	'sha512' => '$6$SoThEnIaDd$OJo4.Bz0DVb3GHEyqdgnm9rQZXdvfvS6drKs/p0RWtuz3sWUKKyghF5qwnuGT/JfZA2fBpKKzFLkIhhHU9dXQ0',
	'sha256' => '$5$SoThEnIaDd$U2.gW7ZqwMahoe69eaDdrP5UTaU3sMJOQDauxhyYuV4',
	'undef' => '$5$SoThEnIaDd$U2.gW7ZqwMahoe69eaDdrP5UTaU3sMJOQDauxhyYuV4',
	'md5' => '$1$SoThEnIa$vMKw0oxQz4Aj//K5f4FJP.'
    },
    '5' => {
	'sha512' => '$6$SoThE$m7xja4oFN4xt.pC4ORxWc0j8UUXHbInkkJcCwc5HxREyk8vjnpvirI.bf0Fci2kJl2ycdDU7NG6Dflm39ll7H.',
	'sha256' => '$5$SoThE$5KMjZFyMptL8jSRSBC7KqdNsfpJVnajcOa6T4oWY81.',
	'undef' => '$5$SoThE$5KMjZFyMptL8jSRSBC7KqdNsfpJVnajcOa6T4oWY81.',
	'md5' => '$1$SoThE$AnIgPlxcLU3EarXoamJqd1'
    }
};

for my $saltlength (1..16) {
    for my $digest (undef, "md5", "sha256", "sha512") {
	# supplied salt
	my $text = "Thiruvaaimozhi";
	my $salt = substr("SoThEnIaDdEdMoReTeStVeRbOsItY", 0, $saltlength);
	my $expected_crypted = $results->{$saltlength}->{$digest||'undef'};

	diag("Crypting '$text' via ".($digest||"unspecified digest")." with salt '$salt' ($saltlength byte salt)");

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

