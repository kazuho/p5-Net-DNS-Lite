use strict;
use warnings;

use Test::More;

BEGIN {
    use_ok('Net::DNS::Lite');
};

my $r = Net::DNS::Lite->new(
    server => [ qw(8.8.4.4 8.8.8.8) ], # google public dns
    search => [ qw(google.com) ],
);

my @r = $r->resolve("google.com", "a");
ok scalar(@r), "lookup google.com";
for my $ip (map { $_->[3] } @r) {
    like $ip, qr/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/;
}

@r = $r->resolve("www", "a");
ok scalar(@r), "lookup www (search = google.com)";
for my $ip (map { $_->[3] } @r) {
    like $ip, qr/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/;
}

@r = $r->resolve("foo.nonexistent.", "a");
ok ! @r, "lookup foo.nonexistent.";

done_testing;
