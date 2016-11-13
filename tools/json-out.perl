#!/usr/bin/perl -w
use Net::LDAP;

use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 
use JSON;

my %hash=();
my %hash2=();

# Problem Umlaut?

$hash{USER}{mike}{sophomorixName}="Jürgen";
$hash{USER}{mike}{sophomorixBirthdate}="01.01.1970";

$hash2{computer}{j1010p01}{mac}="94:DE:80:B1:5B:2E";
$hash2{computer}{j1010p01}{type}="netz";



my $utf8_encoded_json_text = encode_json \%hash;
my $utf8_encoded_json_text2 = encode_json \%hash2;

print "\n";
print "Here ist the first json object:\n";
print "$utf8_encoded_json_text\n";
print "\n";
print "Here ist the first json object:\n";
print "$utf8_encoded_json_text2\n";
print "Script end\n";
print "\n";
