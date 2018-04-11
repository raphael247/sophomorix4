#!/usr/bin/perl -w
# This perl module is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linusmuster.net


package Sophomorix::SophomorixConfig;
require Exporter;
use Digest::SHA;
use MIME::Base64;


@ISA = qw(Exporter);

@EXPORT_OK = qw( );
@EXPORT = qw( 
              );



# Reading configuration file
#my $conf="/etc/linuxmuster/sophomorix/sophomorix.conf";
#if (not -e $conf){
#    print "ERROR: $conf not found!\n";
#    exit;
#}
#
#{ package Conf ; do "$conf" 
#  || die "ERROR: sophomorix.conf could not be processed (syntax error?)\n" 
#}
# Use this variables with $Conf::Variablenname (without 'my' in sophomorix.conf)
$Conf::lang="de";
my $conf="/etc/linuxmuster/sophomorix/sophomorix.conf";
if (not -e $conf){
    print "\nERROR: $conf not found!\n\n";
    exit 88;
}


# Reading developer configuration file
my $develconf="/usr/share/sophomorix/devel/sophomorix-devel.conf";
if (not -e $develconf){
    print "ERROR: $develconf not found!\n";
    exit 88;
}

# Einlesen der Konfigurationsdatei für Entwickler
{ package DevelConf ; do "$develconf"
  || die "Error: sophomorix-devel.conf could not be processed (syntax error?)\n" 
}




######################################################################
# make sure files exist
######################################################################

if (not -e $DevelConf::log_command){
    open(LOG,">>$DevelConf::log_command");
    print LOG "##### $DevelConf::log_command created by SophomorixConfig.pm\n";
    close(LOG)
}









# ENDE DER DATEI
# Wert wahr=1 zurückgeben
1;
