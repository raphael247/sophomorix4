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

# Exit if developer config file is nonexisting
my $develconf="/usr/share/sophomorix/devel/sophomorix-devel.conf";
if (not -e $develconf){
    print "ERROR: $develconf not found!\n";
    exit 88;
}

# Reading developer config file
{ package DevelConf ; do "$develconf"
  || die "Error: sophomorix-devel.conf could not be processed (syntax error?)\n" 
}

######################################################################
# create command.log 
######################################################################
if (not -e $DevelConf::log_command){
    open(LOG,">>$DevelConf::log_command");
    print LOG "##### $DevelConf::log_command created by SophomorixConfig.pm\n";
    close(LOG)
}

# END OF FILRE
# Return 1 (TRUE)
1;
