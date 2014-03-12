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

my @r = $r->resolve("google.com", "mx");
ok scalar(@r), "lookup google.com mx";
for my $mx (@r) {
    is scalar @$mx, 6, "mx response size";
    is $mx->[0], "google.com";
    is $mx->[1], "mx";
    like $mx->[4], qr/\A[0-9]+\z/, "priority int";
}

done_testing;
