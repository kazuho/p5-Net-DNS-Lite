use strict;
use warnings;

use List::Util qw(sum);
use Net::DNS::Lite qw(inet_aton);
use Test::More;
use Time::HiRes qw(time);

if (! -e '/etc/resolv.conf') {
    plan skip_all => 'no /etc/resolv.conf';
}

my $ip = inet_aton("google.com");
ok scalar($ip), "lookup google.com";
is length($ip), 4;

$ip = inet_aton("foo.nonexistent.");
ok ! defined $ip, "lookup foo.nonexistent.";

$Net::DNS::Lite::TIMEOUT = 3;

my $start_at = time;
$ip = inet_aton("harepe.co.");
my $elapsed = time - $start_at;
ok ! defined $ip, 'no response from server';
ok 2.5 <= $elapsed && $elapsed <= 3.5, "elapsed: $elapsed";

done_testing;
