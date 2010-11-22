use strict;
use warnings;

use Benchmark qw(:all);
use Net::DNS::Lite qw();
use Socket qw();

my $fqdn = 'google.com.';

cmpthese(-1, {
    'Socket' => sub {
        Socket::inet_aton($fqdn);
    },
    'Net::DNS::Lite' => sub {
        Net::DNS::Lite::inet_aton($fqdn);
    },
});
