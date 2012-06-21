use strict;
use warnings;
use Net::DNS::Lite;
use Test::More;

my $r = Net::DNS::Lite->new();

{
    $r->parse_resolv_conf(<<EOF);
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
    is_deeply $r->{server}, [qw/8.8.8.8 8.8.4.4/];
    is_deeply $r->{timeout}, [2,5,5];
}

{
    $r->parse_resolv_conf(<<EOF);
options rotate timeout:1
nameserver 8.8.8.8
EOF
    is_deeply $r->{timeout}, [1,1];
}

{
    $r->parse_resolv_conf(<<EOF);
options rotate attempts:3
nameserver 8.8.8.8
EOF
    is_deeply $r->{timeout}, [5,5,5];
}

{
    $r->parse_resolv_conf(<<EOF);
options rotate timeout:2 attempts:3
nameserver 8.8.8.8
EOF
    is_deeply $r->{timeout}, [2,2,2];
}

done_testing();


