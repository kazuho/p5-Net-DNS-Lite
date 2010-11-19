package Net::DNS::Lite;

use strict;
use warnings;

use Carp ();
use List::MoreUtils qw(uniq);
use Socket qw(AF_INET SOCK_DGRAM inet_aton inet_ntoa sockaddr_in
              unpack_sockaddr_in);

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

sub new {
    my ($class, %arg) = @_;

    Carp::croak "missing mandatory parameter: 'server'"
        unless $arg{server};

    my $self = bless {
        server          => [],
        timeout         => [2, 5, 5],
        search          => [],
        ndots           => 1,
        reuse           => 300,
        %arg,
        reuse_q         => [],
    }, $class;

    my $got_socket = 0;
    socket($self->{sock_v4}, AF_INET, SOCK_DGRAM, 0)
        and $got_socket++;
    # if (AF_INET6) {
    #     socket($self->{sock_v6}, AF_INET6, SOCK_DGRAM, 0)
    #         and $got_socket++;
    # }

    $got_socket
        or Carp::croak "unable to create either an IPv4 or an IPv6 socket";

    $self->_compile;

    $self
}

sub _compile {
    my $self = shift;

    my %search;
    $self->{search} = [ grep { length($_) } uniq @{$self->{search}} ];
    $self->{server} = [ grep { length($_) } uniq @{$self->{server}} ];

    my @retry;

    for my $timeout (@{$self->{timeout}}) {
        for my $server (@{$self->{server}}) {
            my $iaddr = inet_aton($server)
                or Carp::croak "invalid server address: $server : $!";
            push @retry, [ scalar sockaddr_in(DOMAIN_PORT, $iaddr), $timeout ];
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

    # advance in searchlist
    my ($do_search, $do_req);

    $do_search = sub {
        @search
            or (undef $do_search), (undef $do_req), return ();

        (my $name = lc "$qname." . shift @search) =~ s/\.$//;
        my $depth = 10;

        # advance in cname-chain
        $do_req = sub {
            my $res = $self->request({
                rd => 1,
                qd => [[$name, $qtype, $class]],
            }) or return $do_search->();

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
    my ($self, $req) = @_;

    $req->{id} ||= $$;
    my $req_pkt = dns_pack($req);

    my $now = time;
    
    for (my $retry = 0; $retry < @{$self->{retry}}; $retry++) {
        my ($server, $timeout) = @{$self->{retry}->[$retry]};

        my $timeout_at = $now + $timeout;

        # send request
        send($self->{sock_v4}, $req_pkt, 0, $server);

        # wait for the response (or the timeout)
        my $res;
        for (; ; undef($res), $now = time) {
            my $select_timeout = $timeout_at - $now;
            last if $select_timeout <= 0;
            my $rfd = '';
            vec($rfd, fileno($self->{sock_v4}), 1) = 1;
            my $nfound = select(
                $rfd, my $wfd = '', my $efd = '', $select_timeout);
            next unless $nfound > 0;
            my $from = recv($self->{sock_v4}, my $res_pkt, 1024, 0)
                or next;
            my ($from_port, $from_addr) = unpack_sockaddr_in($from);
            $from_addr = inet_ntoa($from_addr);
            if (! ($from_port == DOMAIN_PORT
                       && grep { $from_addr eq $_ } @{$self->{server}})) {
                next;
            }
            $res = dns_unpack($res_pkt)
                or next;
            if ($res->{id} == $req->{id}) {
                return $res;
            }
        }
    }

    return;
}

sub _enc_name($) {
    pack "(C/a*)*", (split /\./, shift), ""
}

if ($] < 5.008) {
    # special slower 5.6 version
    *_enc_name = sub ($) {
        join "", map +(pack "C/a*", $_), (split /\./, shift), ""
    };
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

1;
