use strict;
use warnings;

use Test::More;

BEGIN {
    use_ok('Net::DNS::Lite');
};

my $r = Net::DNS::Lite->new(
    server => [ qw(4.4.4.4 8.8.8.8) ],
    search => [ qw(google.com) ],
);

my @r = $r->resolve("google.com", "a");
ok @r;
for my $ip (map { $_->[3] } @r) {
    like $ip, qr/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/;
}

@r = $r->resolve("www", "a");
ok @r;
for my $ip (map { $_->[3] } @r) {
    like $ip, qr/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/;
}

done_testing;
