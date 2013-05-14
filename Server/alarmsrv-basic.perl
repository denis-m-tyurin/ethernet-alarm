#!/usr/bin/perl -w
# vim: set sw=4 ts=4 si et:
# Copyright GPL, author Guido Socher
#
use strict;
use vars qw($opt_a $opt_c $opt_l  $opt_s $opt_h);
use Getopt::Std;
use IO::Socket;
$|=1;
sub help();
sub today();
sub logmsg($$);
&getopts("ha:c:l:s:")||die "ERROR: No such option. -h for help\n";
my($sock, $msg, $today);
#
help() if ($opt_h);
# ---- sending client
if ($opt_a && $opt_s){
    $sock = IO::Socket::INET->new(Proto => 'udp', PeerAddr => "$opt_a", PeerPort => 1200)|| die "socket: $@";
    $msg="a=t:$opt_s";
    print "sending $msg to $opt_a\n";
    $sock->send($msg."\n");
    exit 0;
}
# ---- alarm server
if ($opt_c && $opt_s && $opt_l){
    my $listenport = 5151;
    $sock = IO::Socket::INET->new(LocalPort => $listenport, Proto => 'udp')|| die "socket: $@";
    $today=today();
    logmsg($opt_l,"OK $today, waiting for UDP messages on port $listenport\n");
    while ($sock->recv($msg, 1024)) {
        my($port, $ipaddr) = sockaddr_in($sock->peername);
        my $peer = inet_ntoa($ipaddr);
        chomp($msg);
        $today=today();
        logmsg($opt_l,"OK $today, $peer said: $msg\n");
        if ($msg=~/a=t:$opt_s, n=(.+)/o){
            my $name=$1;
            logmsg($opt_l,"OK $today, test alarm, running $opt_c testalarm \"$name\"\n");
            print `$opt_c testalarm \"$name\" 2>&1`;
            next;
        }
        if ($msg=~/a=\d:$opt_s, n=(.+)/o){
            my $name=$1;
            logmsg($opt_l,"OK $today, alarm, running $opt_c alarm \"$name\"\n");
            print  `$opt_c alarm \"$name\" 2>&1`;
            next;
        } else {
        	print $msg;
        }
    } 
    die "recv: $!";
}
help();
#
sub logmsg($$){
    my $lf=shift;
    my $txt=shift;
    open(LF,">>$lf")|| die "ERROR: can not write to $lf\n";
    print LF $txt;
    print $txt;
    close LF;
}
sub today(){
    my @ltime = localtime;
    #return a date in yyyy-mm-dd format
    sprintf("%04d-%02d-%02d %02d:%02d:%02d",1900 + $ltime[5],$ltime[4] + 1,$ltime[3],$ltime[2],$ltime[1],$ltime[0])
}
sub help(){
print "alarmsrv -- ethernet alarm system server
Start the server: 
alarmsrv -l log.txt -c alarm_command_script -s sharedsec

The alarm_command_script is a shell script that will be executed
if any of the ethernet board raises an alarm.
The sharedsecret is a password like string. It has to be the same
on this alarmsrv and all the ethernet boards. 

Example: 
  ./alarmsrv  -l log.txt -c ./alarm_command_script  -s sharedsec

Test the system:
alarmsrv -a ip -s sharedsec
This sends a message to the ethernet board with IP ip and asks
it to raise a test alarm.

Example: 
  ./alarmsrv  -a 10.0.0.29  -s sharedsec
";
exit 0;
}
__END__ 
