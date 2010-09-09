#!/usr/bin/perl
#
# PortKnocker.pl - A simple port knocking daemon
# Version 0.15 Copyright (C) 2010 James Lawrie
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Changelog since last version:
# - Moved back from File::Tail to "tail -f $file |" as File::Tail only allows
#   reads every second (uses sleep(integer) inside the code and 0 seems to default
#   to 1)
# - Added in IPTables rule to allow established connections
# - Now allows a list of "already trusted" IP addresses to be passed as arguments.
#
# Description
# Portknocking helps to prevent bruteforcing by allowing a particular internal port to
# be opened for a given external IP address only after a particular 'knock sequence' has been
# sent to a range of other ports. In the example in this code, TCP port 22 is closed to all hosts 
# unless they first attempt to connect to TCP ports 2000, 2001 and 2002, in that order.
#
# This script is a very basic implementation of a port knock daemon, which listens for the
# knocks (using iptables logging) and handles iptables accepts/rejects as necessary. It uses
# forking for each knock sequence check, which in some ways was a bad idea and is unlikely to
# be necessary.
# 
# Usage
# Either set it as executable and run it, or pass it as an argument to your perl interpreter.
# I'd advise running it in a screen as a background process. To stop it, simply send it a
# SIGTERM and it should revert all firewall rules.
#
# Requirements
# - Linux RedHat 5 derivative or later
# - IPTables (tested on v1.4.5)
# - IPC::Shareable (perl-IPC-Shareable on Fedora 13)
#
# Disclaimer
# I cannot take any responsibility for your use of this script. If you want to use it, do so at
# your own risk - don't come complaining to me if you lock yourself out of SSH or rely on this
# alone for security and fall victim to a replay attack.
#
# To do
# - Replace IPTables system calls with a module. I couldn't get IPTables::IPv4 to install, any
#   other suggestions are welcome.
# - Replace system call for tail with Perl. File::Tail was not an option.
#
# Suggestions/Complaints/Feedback welcome to james [at] shitsandgiggl.es
#

use strict;
use warnings;

# Decided to try to use forks for this, so needed shareable variables 
use IPC::Shareable;
use File::Tail;
use POSIX ":sys_wait_h";

use constant CHAIN      => 'PortKnocker';
use constant COMMENT    => 'PortKnocker ';
use constant MAX_FORKS  => 10;

# The following aren't constants as most likely to be
# configurable if that option is provided.
my $port_number   = 22;                   # The port number to allow access to
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

# Allow some safe hosts/IPs to be passed as arguments.
foreach (@ARGV) {
    &allow_access($_, $port_number);
}

# 'Daemon' section of the code - listens for changes in the logfile
# and forks a process to deal with it. Will need to be killed with
# (at least) SIGINT so needs handler to restore IPTables.
$SIG{'INT'}  = \&interrupted;
$SIG{'CHLD'} = \&fork_end;

open my $log, "tail -f -n0 $log_file |";

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
    system("iptables -F $chain"); # Delete all rules from the chain
    system("iptables -X $chain"); # No need to analyse return code as expected to fail sometimes
} 

sub init_iptables {
    # First remove the chain if it exists
    my ($chain, $comment) = (CHAIN, COMMENT); # unnecessary but allows for interpolation so more readable.
    &delete_chain($chain);
    # Then add it again
    system("iptables -N $chain") and die("Unable to create chain");
    system("iptables -I INPUT -p $protocol -m multiport " .
                    "--dports $port_number,".join(',', @knock_ports)." -j $chain -m comment --comment $comment")
           and die ("Unable to add IPTables rule");
    system("iptables -A $chain -m state --state RELATED,ESTABLISHED -j ACCEPT") and die ("Unable to add IPTables rule");
    system("iptables -A $chain -p $protocol --dport $port_number -j REJECT") and die("Unable to add IPTables rule");
    system("iptables -A $chain -j LOG --log-prefix '$comment '") and die("Unable to add IPTables Logging");
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
