#!/usr/bin/perl

use strict;
use warnings;

use POSIX ":sys_wait_h";  

use constant CHAIN      => 'PortKnocker';
use constant COMMENT    => 'PortKnocker ';
use constant MAX_FORKS  => 10;

# The following aren't constants as most likely to be
# configurable if that option is provided.
my $port          = 21;
my @knock_ports   = (2000..2010);
my @sequence      = (2000, 2001, 2002);
my $protocol      = 'tcp';
my $log_file      = "/var/log/messages";
my $log_prefix    = 'PortKnocker ';
my %pids;
my %hosts;

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
    	  check_entry($_);
    }
}

sub fork_end {
    my $pid;
    while(($pid = waitpid(-1, &WNOHANG)) > 1) {
        print "Finished with $pid\n";
        delete($pids{$pid});
    }
}

sub interrupted {
   die if $pids{$$};
   if(keys %pids) { 
      sleep(1); # want to make sure pids close first, give them a second to do so willingly
      foreach my $pid (keys %pids) {
          kill 9, $pid;
      }
   }
   &ipt_delete_chain(CHAIN);
   die("Interrupted, quitting...\n");
}

sub ipt_delete_chain {
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
   	if ($rule !~ /-j $chain/) { print $iptables_out $rule or die("Unable to add rules to IPTables"); }
   }
   close $iptables_out;
   # Now just need to delete the chain, which should be simpler.
   system("iptables -F $chain"); # Delete all rules from the chain
   system("iptables -X $chain"); # No need to analyse return code as expected to fail sometimes.
}

sub init_iptables {
    # First remove the chain if it exists
    my ($chain, $comment) = (CHAIN, COMMENT); # unnecessary but allows for interpolation so more readable.
    &ipt_delete_chain($chain);
	 # Then add it again
	 system("iptables -N $chain") and die("Unable to create chain");
	 system("iptables -A INPUT -p $protocol -m multiport " .
                    "--dports ".join(',', @knock_ports)." -j $chain -m comment --comment $comment")
           and die ("Unable to add IPTables rule");
    system("iptables -A $chain -j LOG --log-prefix '$comment '") and die("Unable to add IPTables Logging");
    system("iptables -A $chain -p $protocol --dport $port -j REJECT") and die("Unable to IPTables rule");
}

sub allow_access {
    my ($host, $port) = @_;
    print "Allowing access from $host to $port\n";
    system("iptables -I " . CHAIN . " -p $protocol --source $host --dport $port -j ACCEPT")
    	or die("Unable to add rule allowing host: [$host] access to port: [$port]- $!");
}

sub check_entry {
    my ($source, $port);
    if (/\sSRC=([\d\.]+)\s.*DPT=(\d+)\s/) {
        ($source, $port) = ($1, $2);
    }
    else {
        warn("Didn't match source or port");
        print "$_\n";
        return;
    }
    my $progress = $hosts{$source} || 0; # host must progress through each knock before being allowed access.
    print "Progress for $source is $progress\n";
    if ($port != $sequence[$progress]) {
        print "Dropping to 0\n";
        $hosts{$source} = 0;
    }
    else {
        print "Increasing by 1\n";
        $hosts{$source}++;
        print "Now $hosts{$source}\n";
        print join "\n", (keys %hosts);
        if ($hosts{$source} == @sequence) {
            allow_access($source, $port);
        }
    }
    exit;
} 
