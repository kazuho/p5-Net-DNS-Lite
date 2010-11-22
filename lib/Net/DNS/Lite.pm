package Net::DNS::Lite;

use 5.008_001;

use strict;
use warnings;

use Carp ();
use Exporter qw(import);
use List::MoreUtils qw(uniq);
use Socket qw(AF_INET SOCK_DGRAM inet_ntoa sockaddr_in unpack_sockaddr_in);
use Time::HiRes qw(time);

our $VERSION = '0.02';

our @EXPORT = qw();
our @EXPORT_OK = qw(inet_aton);
our %EXPORT_TAGS = (
    'all' => [ @EXPORT_OK ],
);

sub DOMAIN_PORT () { 53 }

our %opcode_id = (
   query  => 0,
   iquery => 1,
   status => 2,
   notify => 4,
   update => 5,
   map +($_ => $_), 3, 6..15
);

our %opcode_str = reverse %opcode_id;

our %rcode_id = (
   noerror  =>  0,
   formerr  =>  1,
   servfail =>  2,
   nxdomain =>  3,
   notimp   =>  4,
   refused  =>  5,
   yxdomain =>  6, # Name Exists when it should not     [RFC 2136]
   yxrrset  =>  7, # RR Set Exists when it should not   [RFC 2136]
   nxrrset  =>  8, # RR Set that should exist does not  [RFC 2136]
   notauth  =>  9, # Server Not Authoritative for zone  [RFC 2136]
   notzone  => 10, # Name not contained in zone         [RFC 2136]
# EDNS0  16    BADVERS   Bad OPT Version                    [RFC 2671]
# EDNS0  16    BADSIG    TSIG Signature Failure             [RFC 2845]
# EDNS0  17    BADKEY    Key not recognized                 [RFC 2845]
# EDNS0  18    BADTIME   Signature out of time window       [RFC 2845]
# EDNS0  19    BADMODE   Bad TKEY Mode                      [RFC 2930]
# EDNS0  20    BADNAME   Duplicate key name                 [RFC 2930]
# EDNS0  21    BADALG    Algorithm not supported            [RFC 2930]
   map +($_ => $_), 11..15
);

our %rcode_str = reverse %rcode_id;

our %type_id = (
   a     =>   1,
   ns    =>   2,
   md    =>   3,
   mf    =>   4,
   cname =>   5,
   soa   =>   6,
   mb    =>   7,
   mg    =>   8,
   mr    =>   9,
   null  =>  10,
   wks   =>  11,
   ptr   =>  12,
   hinfo =>  13,
   minfo =>  14,
   mx    =>  15,
   txt   =>  16,
   aaaa  =>  28,
   srv   =>  33,
   naptr =>  35, # rfc2915
   dname =>  39, # rfc2672
   opt   =>  41,
   spf   =>  99,
   tkey  => 249,
   tsig  => 250,
   ixfr  => 251,
   axfr  => 252,
   mailb => 253,
   "*"   => 255,
);

our %type_str = reverse %type_id;

our %class_id = (
   in   =>   1,
   ch   =>   3,
   hs   =>   4,
   none => 254,
   "*"  => 255,
);

our %class_str = reverse %class_id;

our $TIMEOUT = 10;

sub new {
    my ($class, %arg) = @_;

    my $self = bless {
        server          => [],
        timeout         => [2, 5, 5],
        search          => [],
        ndots           => 1,
        reuse           => 300,
        %arg,
        reuse_q         => [],
        reuse_h         => +{},
    }, $class;

    $self->_open_socket();

    if (@{$self->{server}} == 0) {
        if (-e '/etc/resolv.conf') {
            $self->_parse_resolv_conf_file('/etc/resolv.conf');
        } else {
            Carp::croak "server was not specified and there is no /etc/resolv.conf";
        }
    }

    $self->_compile;

    $self
}

sub _open_socket {
    my $self = shift;

    my $got_socket = 0;
    socket($self->{sock_v4}, AF_INET, SOCK_DGRAM, 0)
        and $got_socket++;
    # if (AF_INET6) {
    #     socket($self->{sock_v6}, AF_INET6, SOCK_DGRAM, 0)
    #         and $got_socket++;
    # }

    $got_socket
        or Carp::croak "unable to create either an IPv4 or an IPv6 socket";

    $self->{reuse_q} = [];
    $self->{reuse_h} = +{};
}

sub _compile {
    my $self = shift;

    $self->{search} = [ grep { length($_) } uniq @{$self->{search}} ];

    $self->{server} = [
        map {
            Socket::inet_aton($_) or Carp::croak "invalid server address: $_"
        } grep { length($_) } uniq @{$self->{server}},
    ];

    my @retry;

    for my $timeout (@{$self->{timeout}}) {
        for my $server (@{$self->{server}}) {
            push @retry, [ $server, $timeout ];
        }
    }

    $self->{retry} = \@retry;
}

sub resolve {
    my ($self, $qname, $qtype, %opt) = @_;

    my @search = $qname =~ s/\.$//
       ? ""
       : $opt{search}
           ? @{ $opt{search} }
           : ($qname =~ y/.//) >= $self->{ndots}
               ? ("", @{ $self->{search} })
               : (@{ $self->{search} }, "");

    my $class = $opt{class} || "in";

    my %atype = $opt{accept}
        ? map { +($_ => 1) } @{$opt{accept}}
        : ($qtype => 1);

    # use some big value as default so that all servers and retries will be
    # performed before total_timeout
    my $timeout_at = time + (defined $opt{timeout} ? $opt{timeout} : $TIMEOUT);

    # advance in searchlist
    my ($do_search, $do_req);

    $do_search = sub {
        @search
            or (undef $do_search), (undef $do_req), return ();

        (my $name = lc "$qname." . shift @search) =~ s/\.$//;
        my $depth = 10;

        # advance in cname-chain
        $do_req = sub {
            my $res = $self->request(
                +{
                    rd => 1,
                    qd => [[$name, $qtype, $class]],
                },
                $timeout_at,
            ) or return $do_search->();

            my $cname;

            while (1) {
                # results found?
                my @rr = grep {
                    $name eq lc $_->[0] && ($atype{"*"} || $atype{$_->[1]})
                } @{$res->{an}};

                (undef $do_search), (undef $do_req), return @rr
                    if @rr;

                # see if there is a cname we can follow
                @rr = grep {
                    $name eq lc $_->[0] && $_->[1] eq "cname"
                } @{$res->{an}};

                if (@rr) {
                    $depth--
                        or return $do_search->(); # cname chain too long

                    $cname = 1;
                    $name = lc $rr[0][3];

                } elsif ($cname) {
                    # follow the cname
                    return $do_req->();

                } else {
                    # no, not found anything
                    return $do_search->();
                }
            }
        };

        $do_req->();
    };

    $do_search->();
}

sub request {
    my ($self, $req, $total_timeout_at) = @_;

    $req->{id} = $self->_new_id();

    my $req_pkt = dns_pack($req);

    for (my $retry = 0; $retry < @{$self->{retry}}; $retry++) {
        my ($server, $server_timeout) = @{$self->{retry}->[$retry]};

        my $now = time;
        my $server_timeout_at = $now + $server_timeout;
        $server_timeout_at = $total_timeout_at
            if $total_timeout_at < $server_timeout_at;

        # send request
        send(
            $self->{sock_v4}, $req_pkt, 0,
            scalar sockaddr_in(DOMAIN_PORT, $server),
        ) or do {
            warn "failed to send packet to @{[inet_ntoa($server)]}:$!";
            next;
        };

        # wait for the response (or the timeout)
        my $res;
        for (; ; undef($res), $now = time) {
            my $select_timeout = $server_timeout_at - $now;
            if ($select_timeout <= 0) {
                goto FAIL if $total_timeout_at <= $now;
                last;
            }
            last if $select_timeout <= 0;
            my $rfd = '';
            vec($rfd, fileno($self->{sock_v4}), 1) = 1;
            my $nfound = select(
                $rfd, my $wfd = '', my $efd = '', $select_timeout);
            next unless $nfound > 0;
            my $from = recv($self->{sock_v4}, my $res_pkt, 1024, 0)
                or next;
            my ($from_port, $from_addr) = unpack_sockaddr_in($from);
            if (! ($from_port == DOMAIN_PORT
                       && grep { $from_addr eq $_ } @{$self->{server}})) {
                next;
            }
            $res = dns_unpack($res_pkt)
                or next;
            if ($res->{id} == $req->{id}) {
                $self->_register_unusable_id($req->{id})
                    if $retry != 0;
                return $res;
            }
        }
    }

 FAIL:
    $self->_register_unusable_id($req->{id});
    return;
}

sub _new_id {
    my $self = shift;
    my $id;

    my $now = time;

    if (@{$self->{reuse_q}} >= 30000) {
        $self->_open_socket();
    } else {
        delete $self->{reuse_h}{(shift @{$self->{reuse_q}})->[1]}
            while @{$self->{reuse_q}} && $self->{reuse_q}[0][0] <= $now;
    }

    while (1) {
        $id = int rand(65536);
        last if not defined $self->{reuse_h}{$id};
    }

    $id;
}

sub _register_unusable_id {
    my ($self, $id) = @_;

    push @{$self->{reuse_q}}, [ time + $self->{reuse}, $id ];
    $self->{reuse_h}{$id} = 1;
}

sub parse_resolv_conf {
    my ($self, $resolvconf) = @_;

    $self->{server} = [];
    $self->{search} = [];

    my $attempts;

    for (split /\n/, $resolvconf) {
        s/\s*[;#].*$//; # not quite legal, but many people insist

        if (/^\s*nameserver\s+(\S+)\s*$/i) {
            my $ip = $1;
            if (my $ipn = parse_address($ip)) {
                push @{ $self->{server} }, $ip;
            } else {
                warn "nameserver $ip invalid and ignored\n";
            }
        } elsif (/^\s*domain\s+(\S*)\s*$/i) {
            $self->{search} = [$1];
        } elsif (/^\s*search\s+(.*?)\s*$/i) {
            $self->{search} = [split /\s+/, $1];
        } elsif (/^\s*sortlist\s+(.*?)\s*$/i) {
            # ignored, NYI
        } elsif (/^\s*options\s+(.*?)\s*$/i) {
            for (split /\s+/, $1) {
                if (/^timeout:(\d+)$/) {
                    $self->{timeout} = [$1];
                } elsif (/^attempts:(\d+)$/) {
                    $attempts = $1;
                } elsif (/^ndots:(\d+)$/) {
                    $self->{ndots} = $1;
                } else {
                    # debug, rotate, no-check-names, inet6
                }
            }
        }
    }
}

sub _parse_resolv_conf_file {
    my ($self, $resolv_conf) = @_;

    open my $fh, '<', $resolv_conf
        or Carp::croak "could not open file: $resolv_conf: $!";

    $self->parse_resolv_conf(do { local $/; join '', <$fh> });
}

sub _enc_name($) {
    pack "(C/a*)*", (split /\./, shift), ""
}

sub _enc_qd() {
    no warnings;
    (_enc_name $_->[0]) . pack "nn",
        ($_->[1] > 0 ? $_->[1] : $type_id {$_->[1]}),
        ($_->[2] > 0 ? $_->[2] : $class_id{$_->[2] || "in"})
}

sub _enc_rr() {
    die "encoding of resource records is not supported";
}

sub dns_pack {
    no warnings;
    my ($req) = @_;

    pack "nn nnnn a* a* a* a*",
        $req->{id},

        ! !$req->{qr}   * 0x8000
        + $opcode_id{$req->{op}} * 0x0800
        + ! !$req->{aa} * 0x0400
        + ! !$req->{tc} * 0x0200
        + ! !$req->{rd} * 0x0100
        + ! !$req->{ra} * 0x0080
        + ! !$req->{ad} * 0x0020
        + ! !$req->{cd} * 0x0010
        + $rcode_id{$req->{rc}} * 0x0001,

        scalar @{ $req->{qd} || [] },
        scalar @{ $req->{an} || [] },
        scalar @{ $req->{ns} || [] },
        scalar @{ $req->{ar} || [] },

        (join "", map _enc_qd, @{ $req->{qd} || [] }),
        (join "", map _enc_rr, @{ $req->{an} || [] }),
        (join "", map _enc_rr, @{ $req->{ns} || [] }),
        (join "", map _enc_rr, @{ $req->{ar} || [] })
}

our $ofs;
our $pkt;

# bitches
sub _dec_name {
   my @res;
   my $redir;
   my $ptr = $ofs;
   my $cnt;

   while () {
      return undef if ++$cnt >= 256; # to avoid DoS attacks

      my $len = ord substr $pkt, $ptr++, 1;

      if ($len >= 0xc0) {
         $ptr++;
         $ofs = $ptr if $ptr > $ofs;
         $ptr = (unpack "n", substr $pkt, $ptr - 2, 2) & 0x3fff;
      } elsif ($len) {
         push @res, substr $pkt, $ptr, $len;
         $ptr += $len;
      } else {
         $ofs = $ptr if $ptr > $ofs;
         return join ".", @res;
      }
   }
}

sub _dec_qd {
   my $qname = _dec_name;
   my ($qt, $qc) = unpack "nn", substr $pkt, $ofs; $ofs += 4;
   [$qname, $type_str{$qt} || $qt, $class_str{$qc} || $qc]
}

our %dec_rr = (
     1 => sub { join ".", unpack "C4", $_ }, # a     2 => sub { local $ofs = $ofs - length; _dec_name }, # ns
     5 => sub { local $ofs = $ofs - length; _dec_name }, # cname
     6 => sub { 
             local $ofs = $ofs - length;             my $mname = _dec_name;
             my $rname = _dec_name;
             ($mname, $rname, unpack "NNNNN", substr $pkt, $ofs)
          }, # soa    11 => sub { ((join ".", unpack "C4", $_), unpack "C a*", substr $_, 4) }, # wks
    12 => sub { local $ofs = $ofs - length; _dec_name }, # ptr
    13 => sub { unpack "C/a* C/a*", $_ }, # hinfo    15 => sub { local $ofs = $ofs + 2 - length; ((unpack "n", $_), _dec_name) },
 # mx
    16 => sub { unpack "(C/a*)*", $_ }, # txt
    28 => sub { AnyEvent::Socket::format_ipv6 ($_) }, # aaaa
    33 => sub { local $ofs = $ofs + 6 - length; ((unpack "nnn", $_), _dec_name) }, # srv
    35 => sub { # naptr
       # requires perl 5.10, sorry
       my ($order, $preference, $flags, $service, $regexp, $offset) = unpack "nn C/a* C/a* C/a* .", $_;
       local $ofs = $ofs + $offset - length;
       ($order, $preference, $flags, $service, $regexp, _dec_name)
    },
    39 => sub { local $ofs = $ofs - length; _dec_name }, # dname
    99 => sub { unpack "(C/a*)*", $_ }, # spf
);

sub _dec_rr {
   my $name = _dec_name;

   my ($rt, $rc, $ttl, $rdlen) = unpack "nn N n", substr $pkt, $ofs; $ofs += 10;
   local $_ = substr $pkt, $ofs, $rdlen; $ofs += $rdlen;

   [
      $name,
      $type_str{$rt}  || $rt,
      $class_str{$rc} || $rc,
      ($dec_rr{$rt} || sub { $_ })->(),
   ]
}

sub dns_unpack {
   local $pkt = shift;
   my ($id, $flags, $qd, $an, $ns, $ar)
      = unpack "nn nnnn A*", $pkt;

   local $ofs = 6 * 2;

   {
      id => $id,
      qr => ! ! ($flags & 0x8000),
      aa => ! ! ($flags & 0x0400),
      tc => ! ! ($flags & 0x0200),
      rd => ! ! ($flags & 0x0100),
      ra => ! ! ($flags & 0x0080),
      ad => ! ! ($flags & 0x0020),
      cd => ! ! ($flags & 0x0010),
      op => $opcode_str{($flags & 0x001e) >> 11},
      rc => $rcode_str{($flags & 0x000f)},

      qd => [map _dec_qd, 1 .. $qd],
      an => [map _dec_rr, 1 .. $an],
      ns => [map _dec_rr, 1 .. $ns],
      ar => [map _dec_rr, 1 .. $ar],
   }
}

sub parse_address {
    my $text = shift;
    if (my $addr = parse_ipv6($text)) {
        $addr =~ s/^\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff//;
        return $addr;
    } else {
        return parse_ipv4($text);
    }
}

sub parse_ipv4 {
    $_[0] =~ /^      (?: 0x[0-9a-fA-F]+ | 0[0-7]* | [1-9][0-9]* )
              (?:\. (?: 0x[0-9a-fA-F]+ | 0[0-7]* | [1-9][0-9]* ) ){0,3}$/x
                  or return undef;

    @_ = map /^0/ ? oct : $_, split /\./, $_[0];

    # check leading parts against range
    return undef if grep $_ >= 256, @_[0 .. @_ - 2];

    # check trailing part against range
    return undef if $_[-1] >= 2 ** (8 * (4 - $#_));

    pack "N", (pop)
        + ($_[0] << 24)
        + ($_[1] << 16)
        + ($_[2] <<  8);
}

sub parse_ipv6 {
    # quick test to avoid longer processing
    my $n = $_[0] =~ y/://;
    return undef if $n < 2 || $n > 8;

    my ($h, $t) = split /::/, $_[0], 2;

    unless (defined $t) {
        ($h, $t) = (undef, $h);
    }

    my @h = split /:/, $h;
    my @t = split /:/, $t;

    # check for ipv4 tail
    if (@t && $t[-1]=~ /\./) {
        return undef if $n > 6;

        my $ipn = parse_ipv4(pop @t)
            or return undef;

        push @t, map +(sprintf "%x", $_), unpack "nn", $ipn;
    }

    # no :: then we need to have exactly 8 components
    return undef unless @h + @t == 8 || $_[0] =~ /::/;

    # now check all parts for validity
    return undef if grep !/^[0-9a-fA-F]{1,4}$/, @h, @t;

    # now pad...
    push @h, 0 while @h + @t < 8;

    # and done
    pack "n*", map hex, @h, @t
}

our $resolver;

sub RESOLVER() {
    $resolver ||= Net::DNS::Lite->new;
}

sub inet_aton {
    my $name = shift;
    if (my $address = parse_address($name)) {
        return $address;
    }
    my @rr = RESOLVER->resolve(
        $name, 'a',
        (@_ ? (timeout => $_[0]) : ()),
    );
    for my $rec (@rr) {
        my $address = parse_ipv4($rec->[3]);
        return $address if defined $address;
    }
    return undef;
}

1;
__END__

=head1 NAME

Net::DNS::Lite - a pure-perl DNS resolver with support for timeout

=head1 SYNOPSIS

    use Net::DNS::Lite qw(inet_aton);

    # drop-in replacement for Socket::inet_aton
    $Net::DNS::Lite::TIMEOUT = 5; # global timeout variable
    my $addr = inet_aton("www.google.com");

    # or per-query timeout
    my $addr = inet_aton("www.google.com", $timeout_in_seconds);

=head1 DESCRIPTION

This module provides a replacement function for L<Socket::inet_aton>, with support for timeouts.

=head1 AUTHOR

Kazuho Oku

The module is based on the excellent L<AnyEvent::DNS> by mlehmann.

=head1 LICENSE

       This program is free software; you can redistribute it and/or modify it
       under the same terms as Perl itself.

       See <http://www.perl.com/perl/misc/Artistic.html>

=cut
