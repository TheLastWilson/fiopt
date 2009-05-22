#!/usr/bin/perl -w
#use strict
# 
# FiOpt: Firewall Optmisor
#
# Creator: Craig Wilson
# Contact: CraigAWilson at Gmail.com
# Homepage: caWilson.co.uk
#


# Define global variables holding firewall rules
our $die;	#global flag to kill loop

our @P;		#Protcol
our @SIP;	#Source IP address
our @SM;	#Source subnet Mask
our @SP;	#Source Port
our @DIP;	#Destination IP address
our @DM;	#Destination subnet Mask
our @DP;	#Destination Port
our @Action;

our @ruleset = (@SIP, @P, @SM, @SP, @DIP, @DM, @DP, @Action);


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


#' print out rule set with - inbetween 
for ($i=0; $i<=$#{$ruleset[0]};$i++)
{
 for ($j=0; $j<=$#ruleset; $j++)
 {
  if($ruleset[$j][$i])
  { print $ruleset[$j][$i],"-"; }
 }
 print "\n";
}

#print $array[2][0];




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


# Subroutine: iptables_single
#
# Purpose: deal with the arugments input for adding a single rule to the ruleset
#
# Currently depcriated
sub iptables_single
{
# my @rule;
# my $append;
# print "Insert Single IPtables Rule\n$_[0] \n";
# @rule = split(' ',$_[0]);
# 
# $append = 0; # set append to 0. 0 = no apppend flag, 1 = append flag
# my $element;
# foreach $element(@rule) 
# {
#  if ($element eq '-A')
#  {
#   $append = 1; # 1 = append flag detected
#  }
# }
# 
# # if append flag was detected (1) then disect rule for entry into database
# if ($append == 1)
# {
#   &iptable(@rule);
# }
# else
# {
#    print "Fatal Error: Append Flag(-A) required for single rule\n"; 
# }

print "Needs updating";
}
  
# Subroutine: iptables_file
#
# Purpose: deal with the arguments input from a rule file and send each rule individually to the parser
#
# Variables passed into: 
# 			File name
# Variables Returned: 
#		 	N/A
# Variables generated:  
#		 	@rules - iptable file split into lines
#		 	$line - which line (array element of @rules) the foreach look is on
#		 	$j - which line number we are on during the foreach loop
#		 	@rule - the individual rule in $line split into array elements
# Variables passed to another subroutine
# 	iptable: 	$j
# 			\@rule 
sub iptables_file
{
 open(RULES, $_[0]) or die "$_[0] cannot be opened";
 my @rules = <RULES>;

 my $line;
 my $j = 0; #variable to hold array size so as the value gets the correct location in the array to store the info
 my @rule;

 $die = 0;
 foreach $line(@rules) # cycle though rules
 {
  if ($die==0)
  {
   @rule = split(" ",$line); # split each rule into elements
   &iptable($j, \@rule); # pass the line number + rule array reference to the iptable subroutine
   $j++; # incriment the line/rule number
  }
 }
}


# Subroutine: iptable
#
# Purpose: loop though elements of @rule 
# notes: start loop counter at 1 allows loop to automatically skip iptables command.
#
# Variables Passed into:
# 			$j - rule number
# 			\@rule - reference for @rule array
# Variables Returned:	
# 			N/A
# Variables Generated
# 			$ruleref - temp variable to hold the reference for @rule array. needed?
# 			$i - for loop counter
# 			@address - temp array to hold the split up ipaddress and subnet mask fino
# 			@rule - element created with reference, passed from last routine.
# Variables returned:	
# 			N/A
sub iptable
{

 my $j = $_[0]; #variable to hold array size so as the value gets the correct location in the array to store the info
 my $ruleref = $_[1];  
 my @rule = @$ruleref;
 my $i; #for loop counter for cycling though RULE ELEMENTS
 my @address; #temp array for splitting IP address and subnet mask

 print $die;
for ($i = 1; $i < scalar(@rule); $i++)
 {
  if ($rule[$i] eq "-P") # default policy 
  {
   $i++;
   print "Policy for $rule[$i]: ";
   $i++;
   print "$rule[$i]\n";
  }
  elsif ($rule[$i] eq "-A") # rule table
  {
   $i++;
#   print "Table: $rule[$i]\n";
  }
  elsif ($rule[$i] eq "-p") # protocol
  {
   $i++;
   if ($rule[$i]=~m/(TCP|UDP|ICMP|ALL)$/i )
   { 
#    print "Protocol: $rule[$i]\n";
     $ruleset[0][$j] = $rule[$i];
   }
   else
   { print "Fatal Error: Protocol entry not understood ($rule[$i])\n @rule\n"; $die = 1;}
  }
  elsif ($rule[$i] eq "--src") # source ip address
  {
   $i++;
   @address = split("/",$rule[$i]);
   if ($address[0]=~m/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi )
   {
#    print "Source IP Address: $address[0]\n";
     $ruleset[1][$j]=$address[0];
   }
   else
   { print "Fatal Error: Source IP Address not valid ($address[0])\n @rule\n"; }
   
   if($address[1])
   {
    if ($address[1] <= 32)
    { 
#     print "Source Network Mask: $address[1]\n"; 
      $ruleset[2][$j]=$address[1];
    }
    else
    { print "Fatal Error: Source Subnet mask not valid ($address[1])\n @rule\n"; }
   }
  }
  elsif ($rule[$i] eq "--dst") # destination address
  {
   $i++;
   @address = split("/",$rule[$i]);
   if ($address[0]=~m/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi )
   {
#     print "Destination IP Address: $address[0]\n";
      $ruleset[4][$j]=$address[0];
   }
   else
   { print "Fatal Error: Destination IP Address not valid ($address[0])\n @rule\n"; }

   if($address[1])
   {
    if ($address[1] <= 32)
    { 
#     print "Destination Network Mask: $address[1]\n"; 
      $ruleset[5][$j]=$address[1];     
    }
    else
    { print "Fatal Error: Destination Subnet mask not valid ($address[1])\n @rule\n"; }
   }
  }
  elsif ($rule[$i] eq "-j") #action
  {
   $i++;
   if ($rule[$i]=~m/(DROP|ACCEPT)$/i)
   {
#    print "Action: $rule[$i]\n";
    $ruleset[7][$j]=$rule[$i];
   }
   else
   { 
    print "Fatal Error: Action not understood for -j ($rule[$i])\n @rule\n";
     
   }
  }
  elsif ($rule[$i] eq "--dport") #destination port
  {
   $i++;
   if ( $rule[$i] >= 0 && $rule[$i] <= 65535)
   {
#    print "Destination Port: $rule[$i]\n";
    $ruleset[6][$j]=$rule[$i];    
   }
   else
   {
    print "Fatal Error: Destination Port not between 0 - 65535 ($rule[$i])\n @rule\n";
    
   }
  }
  elsif ($rule[$i] eq "--sport") #sourcef
  {
   $i++;
   if ($rule[$i] >= 0 && $rule[$i] <= 65535)
   { 
#    print "Source Port: $rule[$i]\n";
     $ruleset[3][$j]=$rule[$i];
   }
   else
   {
    print "Fatal Error: Source Port not between 0 - 65535 ($rule[$i])\n @rule\n";
   
   }
  }
  else # else means an element not programed for therefore fatal error.
  {
   print "Fatal Error: Element Not Understood ($rule[$i])\n @rule\n";
  
  }
 } #end for loop

} #end sub

