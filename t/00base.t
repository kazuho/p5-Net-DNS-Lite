use strict;
use warnings;

use Test::More;

BEGIN {
    use_ok('Net::DNS::Lite');
};

is(Net::DNS::Lite::parse_ipv6('2408:10:2761:9f00:3ae0:8eff:fe10:6f94'), pack('C*', 0x24, 0x08, 0x00, 0x10, 0x27, 0x61, 0x9f, 0x00, 0x3a, 0xe0, 0x8e, 0xff, 0xfe, 0x10, 0x6f, 0x94), 'parse_ipv6 test (wo ::)');

my $r = Net::DNS::Lite->new(
    server => [ qw(8.8.4.4 8.8.8.8) ], # google public dns
    search => [ qw(google.com) ],
);

my @r = $r->resolve("google.com", "a");
ok scalar(@r), "lookup google.com";
for my $ip (map { $_->[4] } @r) {
    like $ip, qr/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/;
}

@r = $r->resolve("www", "a");
ok scalar(@r), "lookup www (search = google.com)";
for my $ip (map { $_->[4] } @r) {
    like $ip, qr/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/;
}

@r = $r->resolve("foo.nonexistent.", "a");
ok ! @r, "lookup foo.nonexistent.";

done_testing;
