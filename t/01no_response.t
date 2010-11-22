use strict;
use warnings;

use List::Util qw(sum);
use Net::DNS::Lite;
use Test::More;
use Time::HiRes qw(time);

my $r = Net::DNS::Lite->new(
    server => [ qw(google.com) ], # google.com just drops UDP 53 (no response)
);

$Net::DNS::Lite::TIMEOUT = 1000;

my $start_at = time;
my @r = $r->resolve("google.com", "a");
my $elapsed = time - $start_at;
ok ! @r, 'no response from server';
my $expected_time = sum @{$r->{timeout}};
ok(
    $expected_time - 0.5 <= $elapsed && $elapsed <= $expected_time + 0.5,
    "elapsed: $elapsed",
);

done_testing;
