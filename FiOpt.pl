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
 if ($ARGV[0] eq "-i") # -i IPTables
 { 
  if ($ARGV[1] eq "-r") # -r = single rule
  { 
   if ($ARGV[2]) # send to single rule subroutine if rule (next argument) is not null
   { &iptables_single($ARGV[2]); } # send to single rule subroutine
   else
   { &help; } # issue help to command line frm subroutine
  }
  elsif ($ARGV[1] eq "-f" && $ARGV[2]) # -f = rule file, send to single routine subroutine if file name (next argument) is not null
  { &iptables_file($ARGV[2]); } #
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
 local (@rule, $append);
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
 if ($append == 1)
 {
   &iptable(@rule);
 }
 else
 {
    print "Fatal Error: Append Flag(-A) required for single rule\n"; 
 }

}
  
 
sub iptables_file
{
 open(RULES, $_[0]) or die "$_[0] cannot be opened";
 @rules = <RULES>;

 foreach $line(@rules)
 {
  @rule = split(" ",$line);
  &iptable(@rule)
 }
}


 
sub iptable
{
 # loop though elements in @rule, start at 1 to avoid iptables command, no $i++ to allow if statements to easily skip elements 

 @rule = @_;


jump: for ($i = 1; $i < scalar(@rule); $i++)
 {
  if ($rule[$i] eq "-P")
  {
   $i++;
   print "Policy for $rule[$i]: ";
   $i++;
   print "$rule[$i]\n";
  }
  elsif ($rule[$i] eq "-A")
  {
   $i++;
#   print "Table: $rule[$i]\n";
  }
  elsif ($rule[$i] eq "-p")
  {
   $i++;
   if ($rule[$i]=~m/(TCP|UDP|ICMP|ALL)$/i )
   { 
#    print "Protocol: $rule[$i]\n"; 
   }
   else
   { print "Fatal Error: Protocol entry not understood ($rule[$i])\n @rule\n"; last jump; }
  }
  elsif ($rule[$i] eq "--src")
  {
   $i++;
   @address = split("/",$rule[$i]);
   if ($address[0]=~m/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi )
   {
#    print "Source IP Address: $address[0]\n";
   }
   else
   { print "Fatal Error: Source IP Address not valid ($address[0])\n @rule\n"; }
   
   if($address[1])
   {
    if ($address[1] <= 32)
    { 
   #  print "Source Network Mask: $address[1]\n"; 
    }
    else
    { print "Fatal Error: Source Subnet mask not valid ($address[1])\n @rule\n"; }
   }
  }
  elsif ($rule[$i] eq "--dst")
  {
   $i++;
   @address = split("/",$rule[$i]);
   if ($address[0]=~m/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi )
   {
#     print "Destination IP Address: $address[0]\n";
   }
   else
   { print "Fatal Error: Destination IP Address not valid ($address[0])\n @rule\n"; }

   if($address[1])
   {
    if ($address[1] <= 32)
    { 
#     print "Destination Network Mask: $address[1]\n"; 
    }
    else
    { print "Fatal Error: Destination Subnet mask not valid ($address[1])\n @rule\n"; }
   }
  }
  elsif ($rule[$i] eq "-j")
  {
   $i++;
   if ($rule[$i]=~m/(DROP|ACCEPT)$/i)
   {
#    print "Action: $rule[$i]\n";
   }
   else
   { 
    print "Fatal Error: Action not understood for -j ($rule[$i])\n @rule\n";
    last jump; 
   }
  }
  elsif ($rule[$i] eq "--dport")
  {
   $i++;
   if ( $rule[$i] >= 0 && $rule[$i] <= 65535)
   {
#    print "Destination Port: $rule[$i]\n";
   }
   else
   {
    print "Fatal Error: Destination Port not between 0 - 65535 ($rule[$i])\n @rule\n";
    last jump;
   }
  }
  elsif ($rule[$i] eq "--sport")
  {
   $i++;
   if ($rule[$i] >= 0 && $rule[$i] <= 65535)
   { 
#    print "Source Port: $rule[$i]\n";
   }
   else
   {
    print "Fatal Error: Source Port not between 0 - 65535 ($rule[$i])\n @rule\n";
    last jump;
   }
  }
  else
  {
   print "Fatal Error: Element Not Understood ($rule[$i])\n @rule\n";
   last jump;
  }
 } #end for loop



} #end sub











