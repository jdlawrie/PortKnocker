#!/usr/bin/perl
#
# PortKnocker.pl
#
# Author: James Lawrie
#
# Description: Portknocking helps to prevent bruteforcing by allowing a particular port to
# be opened to a given IP address only once a particular 'knock sequence' has been sent to
# a range of other ports. In the example in this code, TCP port 21 is closed to all hosts 
# unless they first attempt to connect to TCP ports 2000, 2001 and 2002, in that order.
# This script is a very basic implementation of a port knock daemon, which listens for the
# knocks (using iptables logging) and handles iptables accepts/rejects as necessary. It uses
# forking for each knock sequence check, which in some ways was a bad idea but I wanted to see
# if I could get it working.
# The code is heavily reliant on Linux, and has been tested on Fedora Core 12 and 13, although
# it should run on any derivative of RHEL5 or later. It needs IPTables and IPC::Shareable. 

use strict;
use warnings;

# Decided to try to use forks for this, so needed shareable variables 
use IPC::Shareable;
use POSIX ":sys_wait_h"; 

use constant CHAIN      => 'PortKnocker';
use constant COMMENT    => 'PortKnocker ';
use constant MAX_FORKS  => 10;

# The following aren't constants as most likely to be
# configurable if that option is provided.
my $port_number   = 21;                   # The port number to allow access to
my $protocol      = 'tcp';
my @knock_ports   = (2000..2010);         # The range of ports to log
my @sequence      = (2000, 2001, 2002);   # The knock sequence
my $log_file      = "/var/log/messages";  # where the IPTables logging will go
my $log_prefix    = 'PortKnocker ';       # To make parsing easier
my %pids;   # List of the current forks
my %hosts;  # keeps track of progress through the knock sequence

my %options = (  # Honestly I'm not really sure what these options do. 
    create    => 1,
    exclusive => 0,
    mode      => 0644,
    destroy   => 1,
);

tie %hosts, 'IPC::Shareable', 'data', \%options; # allow the hosts hash to be used between forks.

# Firstly setup IPTables logging (removing it if it already exists)
# First version of the code doesn't leave existing rules
&init_iptables();

# 'Daemon' section of the code - listens for changes in the logfile
# and forks a process to deal with it. Will need to be killed with
# (at least) SIGINT so needs handler to restore IPTables.
$SIG{'INT'}  = \&interrupted;
$SIG{'CHLD'} = \&fork_end;

open my $log, "tail -n0 -f $log_file |" or die('Unable to open logfile: $!');
while (<$log>) {
    next unless /$log_prefix/;
    while (keys(%pids) >= MAX_FORKS) {
        warn('Too many forks, sleeping');        
        sleep(1);
    }
    my $pid = fork(); # Unnecessary really, but could be required if a lot of logs
    if ($pid) {
        $pids{$pid}++;
    }
    else {
        &check_entry($_); # compare the 'knock' against the sequence.
    }
}

sub fork_end {
    my $pid; # once a fork ends, remove it from the fork hash.
    while(($pid = waitpid(-1, &WNOHANG)) > 1) {
        print "Finished with $pid\n";
        delete($pids{$pid});
    }
}

sub interrupted {
    die if $pids{$$}; # I don't want all forks trying to delete the IPTables rules. 
    if(keys %pids) { 
        sleep(1); # want to make sure pids close first, give them a second to do so willingly
        foreach my $pid (keys %pids) {
            kill 9, $pid;
        }
    }
    &delete_chain(CHAIN); # remove any IPTables modifications we made 
    die("Interrupted, quitting...\n");
}

sub delete_chain {
    my $chain = shift or return;
    # To delete a chain you firstly have to delete all references to it.
    # This has to be done manually, I don't think IPTables has an option
    # for it.
    open my $iptables_in, "/sbin/iptables-save |" or die("Unable to get IPTables rules: $!");
    # Have to store them all and then restore otherwise run the risk of overwriting the rules
    # before we've read them all.
    my @rules = <$iptables_in>;
    close $iptables_in;
    open my $iptables_out, "| iptables-restore";
    foreach my $rule (@rules) {
        if ($rule !~ /-j $chain/) { print $iptables_out $rule or die("Unable to add rules to IPTables: $!"); }
    }
    close $iptables_out;
    # Now just need to delete the chain, which should be simpler.
    system("iptables -F $chain 2&>/dev/null"); # Delete all rules from the chain
    system("iptables -X $chain 2&>/dev/null"); # No need to analyse return code as expected to fail sometimes
} 

sub init_iptables {
    # First remove the chain if it exists
    my ($chain, $comment) = (CHAIN, COMMENT); # unnecessary but allows for interpolation so more readable.
    &delete_chain($chain);
    # Then add it again
    system("iptables -N $chain") and die("Unable to create chain");
    system("iptables -A INPUT -p $protocol -m multiport " .
                    "--dports ".join(',', @knock_ports)." -j $chain -m comment --comment $comment")
           and die ("Unable to add IPTables rule");
    system("iptables -A $chain -j LOG --log-prefix '$comment '") and die("Unable to add IPTables Logging");
    system("iptables -A $chain -p $protocol --dport $port_number -j REJECT") and die("Unable to IPTables rule");
}

sub allow_access {
    my ($host, $port) = @_;
    print "Allowing access from $host to $port\n";
    system("iptables -I " . CHAIN . " -p $protocol --source $host --dport $port -j ACCEPT")
        and die("Unable to add rule allowing host: [$host] access to port: [$port]");
}

sub check_entry {
    # Check a knock against the knock sequence.
    my ($source, $port);
    if (/\sSRC=([\d\.]+)\s.*DPT=(\d+)\s/) {
        ($source, $port) = ($1, $2);
    }
    else {
        warn("Didn't match source or port");
        return;
    }
    # host must progress through each knock before being allowed access
    my $progress = $hosts{$source} || 0;
    if ($port != $sequence[$progress]) {
        # Knock was incorrect
        $hosts{$source} = 0;
    }
    else {
        $hosts{$source}++;
        if ($hosts{$source} == @sequence) {
            &allow_access($source, $port_number);
        }
    }
    exit;
}