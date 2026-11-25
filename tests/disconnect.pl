#!/usr/bin/env perl
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::UNIX;
use POSIX qw(setsid);
use Socket qw(SOCK_STREAM);
use Time::HiRes qw(time sleep);

# No camera, web server, root access, or non-core Perl modules are required.
my $binary = abs_path(shift @ARGV // die "Usage: $0 /path/to/fcgiwrap\n");
die "Binary is not executable\n" unless -x $binary;
my $dir = tempdir('fcgiwrap-disconnect-XXXXXX', TMPDIR => 1, CLEANUP => 1);
$| = 1;

sub fixture {
    my ($name, $source) = @_;
    open(my $f, '>', "$dir/$name") or die $!;
    print $f "#!$^X\n", $source;
    close($f) or die $!;
    chmod(0755, "$dir/$name") or die $!;
}

fixture('silent.cgi', <<'CGI');
use strict;
use warnings;
$| = 1;
open(my $f, '>', $ENV{DISCONNECT_TEST_PIDFILE}) or die $!;
print $f "$$\n";
close($f);
if (($ENV{QUERY_STRING} // '') eq 'headers=1') {
    # Exceed libfcgi's output buffer before becoming silent.
    print "Content-Type: text/plain\r\n\r\nREADY\n", 'x' x 16384;
}
sleep 60;
CGI

fixture('quick.cgi', <<'CGI');
print "Content-Type: text/plain\r\n\r\nWORKER_REUSED\n";
CGI

sub record {
    my ($type, $body) = @_;
    return pack('CCnnCC', 1, $type, 1, length($body), 0, 0) . $body;
}

sub encoded_length {
    my $length = shift;
    return $length < 128 ? pack('C', $length) : pack('N', $length | 0x80000000);
}

sub request {
    my ($socket, $script, $query, $pidfile) = @_;
    my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $socket) or die $!;
    my %params = (
        SCRIPT_FILENAME => "$dir/$script",
        REQUEST_METHOD => 'GET',
        QUERY_STRING => $query,
        CONTENT_LENGTH => '0',
        DISCONNECT_TEST_PIDFILE => $pidfile,
    );
    my $params = join('', map {
        encoded_length(length($_)) . encoded_length(length($params{$_})) . $_ . $params{$_}
    } sort keys %params);
    my $data = record(1, pack('nCxxxxx', 1, 0)) . record(4, $params)
        . record(4, '') . record(5, '');
    my $offset = 0;
    while ($offset < length($data)) {
        my $written = syswrite($s, $data, length($data) - $offset, $offset);
        die "write failed: $!" unless $written;
        $offset += $written;
    }
    return $s;
}

sub read_until {
    my ($s, $seconds, $needle) = @_;
    my $end = time + $seconds;
    my $select = IO::Select->new($s);
    my $reply = '';
    while (time < $end) {
        next unless $select->can_read($end - time);
        my $n = sysread($s, my $buffer, 65536);
        last unless $n;
        $reply .= $buffer;
        last if index($reply, $needle) >= 0;
    }
    return $reply;
}

my @tests = (
    ['silent-before-headers', 0, 0],
    ['silent-after-headers', 1, 0],
    ['retain-connected-idle', 1, 2],
    map { ["repeat-$_", 0, 0] } 1..8,
);

for my $test (@tests) {
    my ($name, $headers, $hold) = @$test;
    my $socket = "$dir/socket";
    my $pidfile = "$dir/cgi.pid";
    unlink($socket);
    unlink($pidfile);
    my $server = fork();
    die "fork failed: $!" unless defined($server);
    if (!$server) {
        setsid() >= 0 or die "setsid failed: $!";
        exec($binary, '-c', '1', '-s', "unix:$socket");
        die "exec failed: $!";
    }
    my $ok = eval {
        for (1..100) { last if -S $socket; sleep(0.02); }
        die "No server socket\n" unless -S $socket;
        my $s = request($socket, 'silent.cgi', $headers ? 'headers=1' : '', $pidfile);
        for (1..100) { last if -s $pidfile; sleep(0.02); }
        open(my $f, '<', $pidfile) or die "No CGI PID\n";
        chomp(my $cgi = <$f>);
        close($f);
        die "Invalid CGI PID\n" unless $cgi =~ /^\d+$/ && $cgi > 1;
        if ($headers) {
            die "No initial CGI output\n" unless read_until($s, 2, 'READY') =~ /READY/;
        }
        if ($hold) {
            sleep($hold);
            die "Connected idle CGI terminated\n" unless kill(0, $cgi);
        }
        close($s);
        my $start = time;
        while (time - $start < 3 && kill(0, $cgi)) { sleep(0.02); }
        die "CGI remains alive after disconnect\n" if kill(0, $cgi);
        my $next = request($socket, 'quick.cgi', '', $pidfile);
        my $reply = read_until($next, 2, 'WORKER_REUSED');
        close($next);
        die "Worker did not accept the next request\n" unless $reply =~ /WORKER_REUSED/;
        printf "PASS %s: child exited and worker reused (%.3fs)\n", $name, time - $start;
        1;
    };
    my $error = $@;
    # The isolated instance and all its CGI fixtures have their own session.
    kill('TERM', -$server);
    sleep(0.1);
    kill('KILL', -$server);
    waitpid($server, 0);
    die "FAIL $name: $error" unless $ok;
}
print "All disconnect regression tests passed.\n";
