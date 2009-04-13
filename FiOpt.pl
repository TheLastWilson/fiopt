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
if ($ARGV[1] ne "")
{ 
 if ($ARGV[0] eq "-i")
 { 
  if ($ARGV[1] eq "-r")
  { 
   if ($ARGV[2])
   { &iptables_single($ARGV[2]); }
   else
   { &help; }
  }
  elsif ($ARGV[1] eq "-f")
  { print "Linux IpTables Rule File\n"; }
  else
  { &help; }
 }
 elsif ($ARGV[0] eq "-a")
 { 
  if ($ARGV[1] eq "-r")
  { print "Cisco ACLs Single Rule\n"; }

  elsif ($ARGV[1] eq "-f")
  { print "Cisco ACLs Rule File\n"; }
  else 
  { &help; }
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
 -r	Single Rule (followed by the rule surrounded in either " or ')
        Single rules must be an Apple rule with -A

ENDHELP
}

sub iptables_single
{
 local (@rule, $append, $dPort, $dIP, $sIP, $sPort, $jump);
 print "Insert Single IPtables Rule\n$_[0] \n";
 @rule = split(' ',$_[0]);
 
 $append = 0; # set append to 0. 0 = no apppend flag, 1 = append flag
 foreach $element(@rule) 
 {
  if ($element eq '-A')
  {
   $append = 1; # 1 = append flag detected
  }
 }
 
 # if append flag was detected (1) then disect rule for entry into database
 if ($append = 1)
 {
  print "Append rule: true";
 }
 else
 {
  print "Error: single rule entry must contain Append flag (-A)";
 }
}










