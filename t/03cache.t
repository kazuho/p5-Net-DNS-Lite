use strict;
use warnings;

use Socket qw();
use Test::More;
use Test::Requires qw(Cache::LRU);

BEGIN {
    use_ok('Net::DNS::Lite');
};

my $cache = $Net::DNS::Lite::CACHE = Cache::LRU->new(
    size => 1024,
);

ok Net::DNS::Lite::inet_aton('example.com');
my $value = $cache->get('in a example.com');
ok $value;
$value->[1] = time + 10000;
splice @{$value->[0]{an}}, 1;
$value->[0]{an}[0][4] = "127.0.0.1";
is Net::DNS::Lite::inet_aton('example.com'), Socket::inet_aton('127.0.0.1');

done_testing;
