#!/usr/bin/perl -w
# 
# FiOpt: Firewall Optmisor
#
# Creator: Craig Wilson
# Contact: CraigAWilson at Gmail.com
# Homepage: caWilson.co.uk
#
#

# Assess comand line arguments
# Format: [Rule Syntax] [input type] [input]
#   Syntaxs
#   -a     ACLs
#   -i     IpTables
#   -g     Generic Syntax
#
#   Input Types
#   -f     File
#   -r     single rule
#
if ( $ARGV[1] ne "")
{ 
 if ($ARGV[0] eq "-i")
 { 
  if ($ARGV[1] eq "-r")
  { &iptables_single; }
  elsif ($ARGV[1] eq "-f")
  { print "Linux IpTables Rule File\n"; }
  else
  { &help }
 }
 elsif ($ARGV[0] eq "-a")
 { 
  if ($ARGV[1] eq "-r")
  { print "Cisco ACLs Single Rule\n"; }

  elsif ($ARGV[1] eq "-f")
  { print "Cisco ACLs Rule File\n"; }
  else 
  { &help }
 }
 else
 { &help; }
}
else
{ &help; } #if no arguemtns do direct to printing help




# Subroutine: Help
#
# Purpose: Print out help in the event of incorrect or missing command line arguments
#
# Variables used: N/A
#
sub help
{
 print <<ENDHELP;
 FiOpt: Firewall Optimiser
 Arguments

 Format: FiOpt.pl [Rule Syntax] [input type] [input]

 Syntaxs
 -a 	ACLs
 -i	IpTables
 -g	Generic Syntax

 Input Types
 -f	File
 -r	single rule

ENDHELP
}

sub iptables_single
{
 print "Linux Iptables Single Rule\n";
}
