#!/usr/bin/perl -w
# This perl module SophomorixBase is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linuxmuster.net

package Sophomorix::SophomorixBase;
require Exporter;
#use File::Basename;
#use Time::Local;
#use Time::localtime;
#use Quota;
#use Sys::Filesystem ();
use Time::Local;
use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 


@ISA = qw(Exporter);

@EXPORT_OK = qw( 
               );
@EXPORT = qw(
            print_line
            print_title
            NTACL_set_file
            remove_from_list
            time_stamp_AD
            time_stamp_file
            ymdhms_to_epoch
            unlock_sophomorix
            lock_sophomorix
            log_script_start
            log_script_end
            log_script_exit
            backup_amku_file
            get_passwd_charlist
            get_plain_password
            check_options
            config_sophomorix_read
            filelist_fetch
            dir_listing
            dns_query_ip
            remove_whitespace
            json_dump
            get_homedirectory
            get_sharedirectory
            get_group_basename
            recode_utf8_to_ascii
            );




# formatted printout
######################################################################

sub print_line {
   print "========================================",
         "========================================\n";
}


sub print_title {
   my ($a) = @_;
   if($Conf::log_level>=2){
   print  "\n#########################################", 
                            "#######################################\n";
   printf " # %-70s # ",$a;
   print  "\n########################################",
                            "########################################\n";
   } else {
         printf "#### %-69s####\n",$a;
   }
}


# json stuff
######################################################################

sub json_dump {
      my ($arg_ref) = @_;
      my $jsoninfo = $arg_ref->{jsoninfo};
      my $jsoncomment = $arg_ref->{jsoncomment};
      my $json = $arg_ref->{json};
      my $hash_ref = $arg_ref->{hash_ref};
      # json 
      if ($json==0){
          # be quiet
      } elsif ($json==1){
          # pretty output
          $hash_ref->{'JSONINFO'}=$jsoninfo;
          $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
          my $json_obj = JSON->new->allow_nonref;
          my $utf8_pretty_printed = $json_obj->pretty->encode( $hash_ref );
          print "$utf8_pretty_printed";
      } elsif ($json==2){
          # compact output
          $hash_ref->{'JSONINFO'}=$jsoninfo;
          $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
          my $json_obj = JSON->new->allow_nonref;
          my $utf8_json_line   = $json_obj->encode( $hash_ref  );
          print "$utf8_json_line";
      } elsif ($json==3){
          &print_title("DUMP: $jsoncomment");
          print Dumper( $hash_ref );
      }
}


# helper stuff
######################################################################
sub remove_from_list {
    # first argument: comma seperated elements to remove
    # other arguments: list elements
    my $option=shift;
    my @list = @_;
    my @removers=split(/,/,$option);
    my %seen=();
    my @stripped=();
    foreach $item (@removers) { $seen{$item} = 1 }
    foreach $item (@list) {
	if (not exists $seen{$item}){
            push(@stripped, $item);
       }
    }
    return @stripped;
}


sub remove_whitespace {
    my ($string)=@_;
    $string=~s/^\s+//g;# remove leading whitespace
    $string=~s/\s+$//g;# remove trailing whitespace
    return $string;    
}

# time stamps
######################################################################

# use this timestamp for the sophomorix-schema in AD
sub time_stamp_AD {
  # 2016-04-04 21:51:44
  #my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
  #chomp($timestamp);
  # 
  # 20160429115500+0100   (YYYYMMDDHHMM+0x00, x is timezonediff)
  # 20160429115500Z       for GMT/UTC
  # 20160502194807Z
  my $timestamp = `date --utc '+%Y%m%d%H%M%S'`;
  chomp($timestamp);
  $timestamp=$timestamp.".0Z";
  return $timestamp;
}



# use this timestamp for filenames
sub time_stamp_file {
   my $zeit = `date +%Y-%m-%d_%H-%M-%S`;
   chomp($zeit);
   return $zeit;
}



sub ymdhms_to_epoch {
    my ($string)=@_;
    my ($ymdhms,$timezone)=split(/\./,$string);
    #print "YMDHMS: $ymdhms\n";
    my($year,$month,$day,$hour,$minute,$second)=unpack 'A4 A2 A2 A2 A2 A2',$ymdhms;
    #print "$year $month $day $hour $minute $second\n";
    my $epoch=timelocal($second, $minute, $hour, $day , ($month-1), $year);
    #print "epoch of $string is $epoch\n";
    return $epoch;
}



# sophomorix locking
######################################################################
sub unlock_sophomorix{
    &print_title("Removing lock in $DevelConf::lock_file");
    my $timestamp=&time_stamp_file();
    my $unlock_dir=$DevelConf::lock_logdir."/".$timestamp."_unlock";
    # make sure logdir exists
    if (not -e "$DevelConf::lock_logdir"){
        system("mkdir $DevelConf::lock_logdir");
    }

    if (-e $DevelConf::lock_file){
        # create timestamped dir
        if (not -e "$unlock_dir"){
            system("mkdir $unlock_dir");
        }
        
        # save sophomorix.lock
        system("mv $DevelConf::lock_file $unlock_dir");

        # saving last lines of command.log
        $command="tail -n 100  ${DevelConf::log_command} ".
	         "> ${unlock_dir}/command.log.tail";
        if($Conf::log_level>=3){
   	    print "$command\n";
        }
	system("$command");

        print "Created log data in ${unlock_dir}\n";
    } else {
        &print_title("Lock $DevelConf::lock_file did not exist");
    }
}


sub lock_sophomorix {
    my ($type,$pid,@arguments) = @_;
    # $type: lock (lock when not existing)
    # $type, steal when existing
    # $pid: steal only when this pid is in the lock file

    # prepare datastring to write into lockfile
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $lock="lock::${timestamp}::creator::$0";
    foreach my $arg (@arguments){
        if ($arg eq "--skiplock"){
            $skiplock=1;
        }
        if ($arg eq ""){
   	    $lock=$lock." ''";
        } else {
	    $lock=$lock." ".$arg ;
        }
    }
    $lock=$lock."::$$"."::\n";

    if ($type eq "lock"){
        # lock , only when nonexisting
        if (not -e $DevelConf::lock_file){
           &print_title("Creating lock in $DevelConf::lock_file");
           open(LOCK,">$DevelConf::lock_file") || die "Cannot create lock file \n";
           print LOCK "$lock";
           close(LOCK);
        } else {
           print "Cold not create lock file (file exists already!)\n";
           exit;
        }
    } elsif ($type eq "steal"){
        # steal, only when existing with pid $pid
        my ($l_script,$l_pid)=&read_lockfile();
	if (-e $DevelConf::lock_file
           and $l_pid==$pid){
           &print_title("Stealing lock in $DevelConf::lock_file");
           open(LOCK,">$DevelConf::lock_file") || die "Cannot create lock file \n";
           print LOCK "$lock";
           close(LOCK);
           return 1;
       } else {
           print "Coldnt steal lock file (file vanished! or pid changed)\n";
           exit;
       }
    }
}



sub read_lockfile {
    my ($log_locked) = @_;
    open(LOCK,"<$DevelConf::lock_file") || die "Cannot create lock file \n";
    while (<LOCK>) {
        @lock=split(/::/);
    }
    close(LOCK);

    # write to command.log
    if (defined $log_locked){
       open(LOG,">>$DevelConf::log_command");
       print LOG "$log_locked";
       close(LOG);
    }

    my $locking_script=$lock[3];
    my $locking_pid=$lock[4];
    return ($locking_script,$locking_pid);
}



# reading configuration files
######################################################################
sub config_sophomorix_read {
    my ($ldap,$root_dse)=@_;
    my %sophomorix_config=();

    # read available encodings from iconv --list
    my %encodings_set=();
    my $available_encodings = `iconv --list`;  #Backticks return a string.
    my @encodings_arr = split /\s+/, $available_encodings;
    foreach my $coding_orig (@encodings_arr){
        my $coding=$coding_orig;
        $coding=~s/\/\/$//g;# remove trailing whitespace
        #print "<$coding>\n";
        $sophomorix_config{'ENCODINGS'}{$coding}=$coding_orig;
        #$encodings_set{$coding}=$coding_orig;
    }
    #my %encodings_set = map {lc $_ => undef} @encodings_arr;

    # Adding some defaults: ????? better to move the defaults to an external file ?????
    $sophomorix_config{'FILES'}{'USER_FILE'}{'vampire.csv'}{RT_sophomorixType_PRIMARY}=
        "adminclass";
    # default school
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'OU'}=$DevelConf::name_default_school; 
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'CONF_FILE'}=
        $DevelConf::path_conf_sophomorix."/".$DevelConf::name_default_school."/school.conf"; 
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'SCHOOL_NAME'}=
        "School"; 
    #$sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'OU_TOP'}=
    #    "OU=".$DevelConf::name_default_school.",".$root_dse; 
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'OU_TOP'}=
        "OU=".$DevelConf::name_default_school.",".$DevelConf::AD_schools_ou.",".$root_dse; 

    # Adding repdir absolute paths
    opendir REPDIR, $DevelConf::path_conf_devel_repdir or return;
    foreach my $file (readdir REPDIR){
        my $abs_path=$DevelConf::path_conf_devel_repdir."/".$file;
        my $Type;
        if ($file eq "."){next};
        if ($file eq ".."){next};
        $sophomorix_config{'REPDIR_FILES'}{$file}=$abs_path;
    }
    closedir REPDIR;

    # add default school to school list
    push @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} }, $DevelConf::name_default_school; 

    ##################################################
    # sophomorix.conf 
    my $conf_file=$DevelConf::file_conf_sophomorix;
    &print_title("Reading $conf_file");
    open(SOPHOMORIX,"$conf_file") || 
         die "ERROR: $conf_file not found!";
    while (<SOPHOMORIX>){
        $_=~s/\s+$//g;# remove trailing whitespace
        if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
            next;
        }
        chomp();
        if ($_ eq ""){# next on empty line
            next;
        }
        my ($var,$value)=split(/=/);
        $var=&remove_whitespace($var);
        $value=&remove_whitespace($value);
        if ($var eq "SCHOOL"){
            # add default school to school list
            $sophomorix_config{'SCHOOLS'}{$value}{'OU'}="unknown";
            push @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} }, $value; 
            $sophomorix_config{'SCHOOLS'}{$value}{'CONF_FILE'}=
                $DevelConf::path_conf_sophomorix."/".$value."/".$value.".school.conf";
        } elsif ($var eq "LANG"){
            $sophomorix_config{$DevelConf::AD_global_ou}{$var}=$value;
        } elsif ($var eq "USE_QUOTA"){
            $sophomorix_config{$DevelConf::AD_global_ou}{$var}=$value;
        } elsif ($var eq "ADMINS_PRINT"){
            $sophomorix_config{$DevelConf::AD_global_ou}{$var}=$value;
        } else {
            print "$var is not a valid variable\n";
            exit;
        }
    }
    close(SOPHOMORIX);

    ##################################################
    # SCHOOLS   
    #### new code
    # do that once
    my %master=&read_master_ini($DevelConf::path_conf_master_school);
    #### new code


    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        my $conf_school=$sophomorix_config{'SCHOOLS'}{$school}{'CONF_FILE'};
        $sophomorix_config{'SCHOOLS'}{$school}{OU}=$school;
        $sophomorix_config{'SCHOOLS'}{$school}{OU_TOP}=
            "OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;

                 if ($school eq $DevelConf::name_default_school){
                     # default-school
                     $sophomorix_config{'SCHOOLS'}{$school}{SCHOOL}=
                          $DevelConf::name_default_school;
                     $sophomorix_config{'SCHOOLS'}{$school}{PREFIX}="";
                     $sophomorix_config{'SCHOOLS'}{$school}{POSTFIX}="";
                     #$sophomorix_config{'SCHOOLS'}{$school}{OU_TOP}=
                     #    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{OU_TOP};
                 } else {
                     # *school
                     $sophomorix_config{'SCHOOLS'}{$school}{SCHOOL}=$school;
                     $sophomorix_config{'SCHOOLS'}{$school}{PREFIX}=$school."-";
                     $sophomorix_config{'SCHOOLS'}{$school}{POSTFIX}="-".$school;
                     $sophomorix_config{'SCHOOLS'}{$school}{OU_TOP}=
                         $sophomorix_config{'SCHOOLS'}{$school}{OU_TOP};
                 }




        #### new code
        # do that for every school



        #### new code




        ######## ?????????????????????????  ################     replace this with ini import
        &print_title("Reading $conf_school");
        open(SCHOOL,"$conf_school") || 
             die "ERROR: $conf_school not found!\n";
        while (<SCHOOL>){
            $_=~s/\s+$//g;# remove trailing whitespace
            if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
                next;
            }
            chomp();
            if ($_ eq ""){# next on empty line
                next;
            }

            my ($var,$value)=split(/=/);
            $var=&remove_whitespace($var);
            $value=&remove_whitespace($value);

            if ($var eq "SCHOOL_NAME" or
                $var eq "QUOTA_DEFAULT_TEACHER" or
                $var eq "QUOTA_DEFAULT_STUDENT" or
                $var eq "QUOTA_DEFAULT_EXAM" or
                $var eq "MAILQUOTA_DEFAULT_TEACHER" or
                $var eq "MAILQUOTA_DEFAULT_STUDENT" or
                $var eq "MAILQUOTA_DEFAULT_EXAM"
               ){
                $sophomorix_config{'SCHOOLS'}{$school}{$var}=$value;
            } elsif ($var eq "USER_FILE"){
                my ($file,$filter_script,$enc,$enc_force,$sur_chars,$first_chars,
                    $reverse,$rand_pwd,$pwd_length,$toleration_time,$deactivation_time)=split(/::/,$value);
                my $token_file;
                if ($school eq $DevelConf::name_default_school){
                    $token_file=$file;
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{SCHOOL}=
                        $DevelConf::name_default_school;
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{PREFIX}="";
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{POSTFIX}="";
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{OU_TOP}=
                        $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{OU_TOP};
                } else {
                    $token_file=$school.".".$file;
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{SCHOOL}=$school;
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{PREFIX}=$school."-";
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{POSTFIX}="-".$school;
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{OU_TOP}=
                        $sophomorix_config{'SCHOOLS'}{$school}{OU_TOP};
                }

                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$token_file;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{PATH_ABS}=$path_abs;
                my $path_abs_filter=$DevelConf::path_conf_tmp."/".$token_file.".filter";
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{FILTERTARGET}=$path_abs_filter;
                my $path_abs_utf8=$DevelConf::path_conf_tmp."/".$token_file.".filter.utf8";
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{PATH_ABS_UTF8}=$path_abs_utf8;

                # save unchecked filter script for error messages
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{FILTERSCRIPT_CONFIGURED}=$filter_script;

                # save only abs_paths to executable scripts
                if ($filter_script eq "---"){
                   $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{FILTERSCRIPT}=$filter_script;
	        } elsif (-f $filter_script and -x $filter_script and $filter_script=~m/^\//){
                   # configured value is a file and executable
                   $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{FILTERSCRIPT}=$filter_script;
                } else {
                   $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{FILTERSCRIPT}="ERROR_FILTERSCRIPT";
                    print "   * WARNING: $filter_script \n";
                    print "        must be:\n";
                    print "          - an executable file\n";
                    print "          - an absolute path\n";
                }

                if (exists $sophomorix_config{'ENCODINGS'}{$enc} or $enc eq "auto"){
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{ENCODING}=$enc;
	        } else {
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{ENCODING}="ERROR_ENCODING";
                    print "   * WARNING: ENCODING $enc not listed by \"iconv --list\" and not \"auto\"\n";
                }

                if ($enc_force eq "yes" or $enc_force eq "no"){
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{ENCODING_FORCE}=$enc_force;
                } else {
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{ENCODING_FORCE}="ERROR_ENCODING_FORCE";
                    print "   * WARNING: ENCODING_FORCE allows only \"yes\" or \"no\"\n";
                }

                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{SURNAME_CHARS}=$sur_chars;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{FIRSTNAME_CHARS}=$first_chars;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{SURNAME_FIRSTNAME_REVERSE}=$reverse;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{RANDOM_PWD}=$rand_pwd;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{PWD_LENGHT}=$pwd_length;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{TOLERATION_TIME}=$toleration_time;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{DEACTIVATION_TIME}=$deactivation_time;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{OU}=
                    $sophomorix_config{'SCHOOLS'}{$school}{OU};
#                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{OU_TOP_GLOBAL}=
#                    "OU=GLOBAL,".$DevelConf::AD_schools_ou.",".$root_dse;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{OU_TOP_GLOBAL}=
                    "OU=GLOBAL,".$root_dse;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$token_file}{FILETYPE}="users";
            } elsif ($var eq "CLASS_FILE"){
                my ($file,$rest)=split(/::/,$value);
                my $token_file;
                if ($school eq $DevelConf::name_default_school){
                    $token_file=$file;
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{SCHOOL}=
                        $DevelConf::name_default_school;
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{PREFIX}="";
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{POSTFIX}="";
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{OU_TOP}=
                        $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{OU_TOP};
                } else {
                    $token_file=$school.".".$file;
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{SCHOOL}=$school;
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{PREFIX}=$school."-";
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{POSTFIX}="-".$school;
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{OU_TOP}=
                        $sophomorix_config{'SCHOOLS'}{$school}{OU_TOP};
                }
                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$token_file;
                $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{PATH_ABS}=$path_abs;
                $sophomorix_config{'FILES'}{'CLASS_FILE'}{$token_file}{FILETYPE}="classes";
            } elsif ($var eq "DEVICE_FILE"){
                my ($file,$rest)=split(/::/,$value);
                my $token_file;
                if ($school eq $DevelConf::name_default_school){
                    $token_file=$file;
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{SCHOOL}=
                        $DevelConf::name_default_school;
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{PREFIX}="";
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{POSTFIX}="";
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{OU_TOP}=
                        $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{OU_TOP};
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{OU}=
                        $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{OU};
                } else {
                    $token_file=$school.".".$file;
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{SCHOOL}=$school;
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{PREFIX}=$school."-";
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{POSTFIX}="-".$school;
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{OU_TOP}=
                        $sophomorix_config{'SCHOOLS'}{$school}{OU_TOP};
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{OU}=
                        $sophomorix_config{'SCHOOLS'}{$school}{OU};
                }
                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$token_file;
                $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{PATH_ABS}=$path_abs;
                $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$token_file}{FILETYPE}="devices";
            } else {
                print "<$var> is not a valid variable name\n";
                exit;
            }
        }
        close(SCHOOL);
        ######## ?????????????????????????  ################     replace this with ini import






    }
    # GLOBAL
#    $sophomorix_config{$DevelConf::AD_global_ou}{OU_TOP}=
#        "OU=".$DevelConf::AD_global_ou.",".$DevelConf::AD_schools_ou.",".$root_dse;
    $sophomorix_config{$DevelConf::AD_global_ou}{OU_TOP}=
        "OU=".$DevelConf::AD_global_ou.",".$root_dse;
    $sophomorix_config{$DevelConf::AD_global_ou}{SCHOOL}="global";
    $sophomorix_config{$DevelConf::AD_global_ou}{PREFIX}="";
    # SCHOOL
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{OU_TOP}=
        "OU=".$DevelConf::name_default_school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{SCHOOL}=
        $DevelConf::name_default_school;
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{PREFIX}="";

    #print Dumper(%sophomorix_config);
    #exit;
    ##################################################
    # RoleType
    &print_title("Reading $DevelConf::file_conf_roletype");
    open(ROLETYPE,"$DevelConf::file_conf_roletype") || 
         die "ERROR: $DevelConf::file_conf_roletype not found!";
    while (<ROLETYPE>){
        if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
            next;
        }
        chomp();
        my ($user,$primary,$secondary,$tertiary,$quaternary)=split(/\|\|/);
        my ($roletype_file,$sophomorix_field5,$sophomorix_role)=split(/::/,$user);
        my ($sophomorix_type_primary,$group_primary,$ou_sub_primary)=split(/::/,$primary);
        my ($sophomorix_type_secondary,$group_secondary,$ou_sub_secondary)=split(/::/,$secondary);
        my ($sophomorix_type_tertiary,$group_tertiary,$ou_sub_tertiary)=split(/::/,$tertiary);
        my ($sophomorix_type_quaternary,$group_quaternary,$ou_sub_quaternary)=split(/::/,$quaternary);

        $roletype_file=&remove_whitespace($roletype_file);
        $roletype_file=~s/^\*\.//g;# remove leading asterisk and dot
        # user
        $sophomorix_role=&remove_whitespace($sophomorix_role);
        $sophomorix_field5=&remove_whitespace($sophomorix_field5);
        # primary group
        $sophomorix_type_primary=&remove_whitespace($sophomorix_type_primary);
        $group_primary=&remove_whitespace($group_primary);
        $ou_sub_primary=&remove_whitespace($ou_sub_primary);
        # secondary group
        $sophomorix_type_secondary=&remove_whitespace($sophomorix_type_secondary);
        $group_secondary=&remove_whitespace($group_secondary);
        $ou_sub_secondary=&remove_whitespace($ou_sub_secondary);
        # tertiary group
        $sophomorix_type_tertiary=&remove_whitespace($sophomorix_type_tertiary);
        $group_tertiary=&remove_whitespace($group_tertiary);
        $ou_sub_tertiary=&remove_whitespace($ou_sub_tertiary);
        # quaternary group
        $sophomorix_type_quaternary=&remove_whitespace($sophomorix_type_quaternary);
        $group_quaternary=&remove_whitespace($group_quaternary);
        $ou_sub_quaternary=&remove_whitespace($ou_sub_quaternary);

        # create list of sub ou's that are needed to create from sophomorix-RoleType.conf:
        if ($ou_sub_primary ne ""){
            $sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'RT_OU'}{$ou_sub_primary}="from RoleType";
        }
        if ($ou_sub_secondary ne ""){
            $sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'RT_OU'}{$ou_sub_secondary}="from RoleType";
        }
        if ($ou_sub_tertiary ne ""){
            $sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'RT_OU'}{$ou_sub_tertiary}="from RoleType";
        }
        if ($ou_sub_quaternary ne ""){
            $sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'RT_OU'}{$ou_sub_quaternary}="from RoleType";
        } 

        # adding school
	$sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'DEVELCONF_OU'}{$DevelConf::AD_devices_ou}="from DevelConf";
#	$sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'DEVELCONF_OU'}{$DevelConf::AD_examaccount_ou}="from DevelConf";
	$sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'DEVELCONF_OU'}{$DevelConf::AD_project_ou}="from DevelConf";
#	$sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'DEVELCONF_OU'}{$DevelConf::AD_room_ou}="from DevelConf";
	$sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'DEVELCONF_OU'}{$DevelConf::AD_management_ou}="from DevelConf";
	$sophomorix_config{'SUB_OU'}{'SCHOOLS'}{'DEVELCONF_OU'}{$DevelConf::AD_custom_ou}="from DevelConf";
       
        # adding global
#	$sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'DEVELCONF_OU'}{$DevelConf::AD_devices_ou}="from DevelConf";
#	$sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'DEVELCONF_OU'}{$DevelConf::AD_examaccount_ou}="from DevelConf";
#	$sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'DEVELCONF_OU'}{$DevelConf::AD_project_ou}="from DevelConf";
#	$sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'DEVELCONF_OU'}{$DevelConf::AD_room_ou}="from DevelConf";
	$sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'DEVELCONF_OU'}{$DevelConf::AD_management_ou}="from DevelConf";
	$sophomorix_config{'SUB_OU'}{$DevelConf::AD_global_ou}{'DEVELCONF_OU'}{$DevelConf::AD_custom_ou}="from DevelConf";
       


        # remember for the following commented line:
        # experimental warning: foreach my $key (keys $sophomorix_config{'user_file'}) {
        foreach my $key (keys %{$sophomorix_config{'FILES'}{'USER_FILE'}}) {
           if($Conf::log_level>=3){
                print "\n";
                print "* Name in RoleType file: $roletype_file\n";
                print "* Name in schools.conf:  $key\n";
            }
            my $user_file=$key;
            my $token_file="";
            my $type_file="";
            my $extension_file="";

            $apply_key=$key; # apply key has abc.students.csv stripped to students.csv
            my $dots=$apply_key=~tr/\.//;
            if ($dots==2){
                ($token_file,$type_file,$extension_file)=split(/\./,$user_file);
		#print "  * $dots dots in $key ($token_file)\n";
                $group_primary=~s/^\*-//g;
                $group_secondary=~s/^\*-//g;
            } elsif ($dots==1){
                $token_file="";
                ($type_file,$extension_file)=split(/\./,$user_file);
		#print "  * $dots dots in $key\n";
                $group_primary=~s/^\*-//g;
                $group_secondary=~s/^\*-//g;
            } else {
                print "\nERROR: $dots dots in $key\n\n";
                exit;
            }
            my $matchname_of_user_file=$type_file.".".$extension_file;
            if($Conf::log_level>=3){
                print "* Testing if $key (stripped to $matchname_of_user_file) matches $roletype_file (RoleType)\n";
            }
            if ($matchname_of_user_file eq $roletype_file){
                if($Conf::log_level>=3){
                    print "* Match: Inserting data...\n";
                }
                my $ou_file=$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU};

                # user
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_sophomorixRole}=$sophomorix_role;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{FIELD5}=$sophomorix_field5;

                # primary group
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_sophomorixType_PRIMARY}=$sophomorix_type_primary;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_OU_SUB_PRIMARY}=
                    $ou_sub_primary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                if ($group_primary ne "" and not $group_primary eq "multi"){
                    # add with prefix
                    my $group=$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{PREFIX}.$group_primary;
                      $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_GROUP_PRIMARY}=$group;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_LEVEL}{$group}="primary";
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_TYPE}{$group}=$sophomorix_type_primary;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_DESCRIPTION}{$group}="$key -> primary group";
                    if ($group_tertiary ne ""){
                        $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_MEMBER}{$group}=$group_tertiary;
                    }

                    #my $ou_group="OU=".$group.",".$ou_sub_primary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    #my $cn_group="CN=".$group.",".$ou_group;
                    #$sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP}{$group}=
                    #    $ou_sub_primary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    #$sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_OU}{$ou_group}=$group;
                    #$sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_CN}{$cn_group}=$group;

                    my $ou_group=$ou_sub_primary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    my $cn_group="CN=".$group.",".$ou_group;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP}{$group}=
                        $ou_sub_primary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_OU}{$ou_group}=$group;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_CN}{$cn_group}=$group;
                } else {
                    # "" or "multi"
                    #print "GROUP: $group_primary\n";
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_GROUP_PRIMARY}=$group_primary;
                }


                # secondary group
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_sophomorixType_SECONDARY}=$sophomorix_type_secondary;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_OU_SUB_SECONDARY}=
                    $ou_sub_secondary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                if ($group_secondary ne "" and not $group_secondary eq "multi"){
                    # add with prefix
                    my $group=$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{PREFIX}.$group_secondary;
                    # print "GROUP: $group\n";
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_GROUP_SECONDARY}=$group;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_LEVEL}{$group}="secondary";
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_TYPE}{$group}=$sophomorix_type_secondary;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_DESCRIPTION}{$group}="$key -> secondary group";
                    if ($group_tertiary ne ""){
                        $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_MEMBER}{$group}=$group_tertiary;
                    }
                    #my $ou_group="OU=".$group.",".$ou_sub_primary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    #my $cn_group="CN=".$group.",".$ou_group;
                    #$sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP}{$group}=
                    #    $ou_sub_secondary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    #$sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_OU}{$ou_group}=$group;
                    #$sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_CN}{$cn_group}=$group;

                    my $ou_group=$ou_sub_primary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    my $cn_group="CN=".$group.",".$ou_group;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP}{$group}=
                        $ou_sub_secondary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_OU}{$ou_group}=$group;
                    $sophomorix_config{'SCHOOLS'}{$ou_file}{GROUP_CN}{$cn_group}=$group;

                } else {
                    # "" or "multi"
                    #print "GROUP: $group_secondary\n";
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_GROUP_SECONDARY}=$group_secondary;
                }

                # tertiary group
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_sophomorixType_TERTIARY}=$sophomorix_type_tertiary;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_GROUP_TERTIARY}=$group_tertiary;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_OU_SUB_TERTIARY}=
                    $ou_sub_tertiary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP_GLOBAL};
                if ($group_tertiary ne "" and not $group_tertiary eq "multi"){
#		    my $ou_group="OU=".$group_tertiary.",".$ou_sub_tertiary.",".
#                                 $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP_GLOBAL};
#                    my $cn_group="CN=".$group_tertiary.",".$ou_group;
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_LEVEL}{$group_tertiary}="tertiary";
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{$group_tertiary}=$sophomorix_type_tertiary;
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_DESCRIPTION}{$group_tertiary}="$key -> tertiary group";
                    if ($group_quaternary ne ""){
                        $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_MEMBER}{$group_tertiary}=$group_quaternary;
                    }
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP}{$group_tertiary}=
                        $ou_sub_tertiary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP_GLOBAL};

		    my $ou_group=$ou_sub_tertiary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP_GLOBAL};
                    my $cn_group="CN=".$group_tertiary.",".$ou_group;
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_OU}{$ou_group}=$group_tertiary;
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_CN}{$cn_group}=$group_tertiary;
#                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_OU}{$ou_group}=$group_tertiary;
#                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_CN}{$cn_group}=$group_tertiary;
                }

                # quaternary group
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_sophomorixType_QUATERNARY}=$sophomorix_type_quaternary;
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_GROUP_QUATERNARY}=$group_quaternary;
                if ($group_quaternary ne "" and not $group_quaternary eq "multi"){
		    my $ou_group="OU=".$group_quaternary.",".$ou_sub_quaternary.",".
                                 $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP_GLOBAL};
                    my $cn_group="CN=".$group_quaternary.",".$ou_group;
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_LEVEL}{$group_quaternary}="quaternary";
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{$group_quaternary}=$sophomorix_type_quaternary;
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_DESCRIPTION}{$group_quaternary}="$key -> quaternary group";
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP}{$group_quaternary}=
                        $ou_sub_quaternary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP_GLOBAL};
                    $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_OU}{$group_quaternary}=
                      "OU=".$group_quaternary.",".$ou_sub_quaternary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP};
                }
                $sophomorix_config{'FILES'}{'USER_FILE'}{$key}{RT_OU_SUB_QUATERNARY}=
                    $ou_sub_quaternary.",".$sophomorix_config{'FILES'}{'USER_FILE'}{$key}{OU_TOP_GLOBAL};
            } else {
                if($Conf::log_level>=3){
                    print "No match. Nothing to do!\n";
                }
            }
        }
    }

    # Management groups: wifi,internet,admins
    ###############################################
    # GLOBAL
    # OU for Administrators
    $sophomorix_config{$DevelConf::AD_global_ou}{ADMINS}{OU}=
        $DevelConf::AD_management_ou.",".$sophomorix_config{$DevelConf::AD_global_ou}{OU_TOP};

    # my @grouplist=("examaccounts","wifi","internet");
    my @grouplist=("wifi","internet","admins","webfilter","intranet","printing");
    foreach my $group (@grouplist){
        my $sub_ou=$DevelConf::AD_management_ou;
         my $cn_group="CN=global-".$group.",".
            $sub_ou.",".$sophomorix_config{$DevelConf::AD_global_ou}{OU_TOP};
        $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_CN}{$cn_group}="global-".$group;

        $sophomorix_config{$DevelConf::AD_global_ou}{GROUP}{"global-".$group}=
            $sub_ou.",".$sophomorix_config{$DevelConf::AD_global_ou}{OU_TOP};
        $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_LEVEL}{"global-".$group}="none";
        $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_DESCRIPTION}{"global-".$group}="LML GROUP";

        if ($group eq "internet"){
            $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{"global-".$group}="globalinternetaccess";
        } elsif ($group eq "wifi"){
            $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{"global-".$group}="globalwifiaccess";
        } elsif ($group eq "admins"){
            $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{"global-".$group}="globaladmins";
        } elsif ($group eq "webfilter"){
            $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{"global-".$group}="globalwebfilter";
        } elsif ($group eq "intranet"){
            $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{"global-".$group}="globalintranet";
        } elsif ($group eq "printing"){
            $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{"global-".$group}="globalprinting";
        } else {
            $sophomorix_config{$DevelConf::AD_global_ou}{GROUP_TYPE}{"global-".$group}="globalmanagementgroup";
        }
    }

    # SCHOOLS
    foreach my $ou (keys %{$sophomorix_config{'SCHOOLS'}}) {
        # OU for Administrators
        $sophomorix_config{'SCHOOLS'}{$ou}{ADMINS}{OU}=
            $DevelConf::AD_management_ou.",".$sophomorix_config{'SCHOOLS'}{$ou}{OU_TOP};

        # my @grouplist=("examaccounts","wifi","internet");
        my @grouplist=("wifi","internet","admins","webfilter","intranet","printing");
        foreach my $group (@grouplist){
            my $sub_ou=$DevelConf::AD_management_ou;
            my $cn_group="CN=".$sophomorix_config{'SCHOOLS'}{$ou}{PREFIX}.$group.",".
                   $sub_ou.",".$sophomorix_config{'SCHOOLS'}{$ou}{OU_TOP};
            my $group_prefix=$sophomorix_config{'SCHOOLS'}{$ou}{PREFIX}.$group;
            $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_CN}{$cn_group}="$group_prefix";
            $sophomorix_config{'SCHOOLS'}{$ou}{GROUP}{$group_prefix}=
                $sub_ou.",".$sophomorix_config{'SCHOOLS'}{$ou}{OU_TOP};
            $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_LEVEL}{$group_prefix}="none";
            $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_DESCRIPTION}{$group_prefix}="LML $ou $group";
            $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_MEMBER}{$group_prefix}="global-".$group;
            if ($group eq "internet"){
                $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_TYPE}{$group_prefix}="internetaccess";
            } elsif ($group eq "wifi"){
                $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_TYPE}{$group_prefix}="wifiaccess";
            } elsif ($group eq "admins"){
                $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_TYPE}{$group_prefix}="admins";
            } elsif ($group eq "webfilter"){
                $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_TYPE}{$group_prefix}="webfilter";
            } elsif ($group eq "intranet"){
                $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_TYPE}{$group_prefix}="intranetaccess";
            } elsif ($group eq "printing"){
                $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_TYPE}{$group_prefix}="printing";
            } else {
                $sophomorix_config{'SCHOOLS'}{$ou}{GROUP_TYPE}{$group_prefix}="managementgroup";
	    }
        }
    }
    close(ROLETYPE);

    # sorting some lists
    @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} } = sort @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} };

    return %sophomorix_config; 
}
 

sub read_master_ini {
    my ($masterfile)=@_;
    my %master=();
    &print_title("Reading $masterfile");
    
    return %master;
}


sub filelist_fetch {
    # listing existing files of the given FILETYPE
    my ($arg_ref) = @_;
    my $filetype = $arg_ref->{filetype};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $file_key;

    if ($filetype eq "devices"){
	$file_key="DEVICE_FILE";
    } elsif ($filetype eq "classes"){
	$file_key="CLASS_FILE";
    } elsif ($filetype eq "users"){
	$file_key="USER_FILE";
    } else {
        print "ERROR: unknown filetype $filetype\n";
        exit;
    }

    my @filelist=();
    if($Conf::log_level>=2){
        &print_title("Testing the following files for handling:");
    }
    foreach my $file (keys %{$ref_sophomorix_config->{'FILES'}{$file_key}}) {
        my $abs_path=$ref_sophomorix_config->{'FILES'}{$file_key}{$file}{'PATH_ABS'};
        my $filetype_real=$ref_sophomorix_config->{'FILES'}{$file_key}{$file}{'FILETYPE'};
        if (not defined $abs_path){next}; # i.e. vampire.csvFILES
        
        if (-e $abs_path and $filetype_real eq $filetype){
            push @filelist, $abs_path;
            if($Conf::log_level>=2){
                print "  ** $abs_path (existing)\n";
            }
        } else {
            if($Conf::log_level>=2){
                if (not -e $abs_path){
                    print "   - $abs_path (nonexisting)\n";
                } elsif ($filetype_real ne $filetype){
                    print "   + $abs_path (existing but wrong filetype)\n";
                }
            }
        }
    }
    @filelist = sort @filelist;
    return @filelist;
}


sub dir_listing_session_supervisor {
    # directory listing for supervisor of session only

    # fix the path to homedir of supervisors ???????????????????ß

    my ($dir,$name,$role,$supervisor,$session,$ref_sessions)=@_;
    opendir DIR, $dir or return;
    foreach my $file (readdir DIR){
        my $abs_path=$dir."/".$file;
        my $Type;
        if ($file eq "."){next};
        if ($file eq ".."){next};
        if (-d $abs_path){
            $type="d";
        } elsif (-f $abs_path){
            $type="f";
        } else {
            $type="strange";
        }
        $ref_sessions->{'supervisor'}{$supervisor}{'files'}{$name}{$file}{'type'}=$type;
        $ref_sessions->{'id'}{$session}{'supervisor'}{'files'}{$name}{$file}{'type'}=$type;
    }
    closedir DIR;
}


sub quota_listing_session_participant {
    # quota listng for participant only
    my ($participant,$session,$supervisor,$ref_sessions)=@_;
    print "      * fetching quota of participant $participant  --> todo\n";

    # session ids
    $ref_sessions->{'id'}{$session}{'participants'}{$participant}{'quota'}{'/dev/sda1'}{'comment'}="Home";
    $ref_sessions->{'id'}{$session}{'participants'}{$participant}{'quota'}{'/dev/sda1'}{'hardlimit'}="xxx MB";


    # supervisors
    $ref_sessions->{'supervisor'}{$supervisor}{'sophomorixSessions'}{$session}{'participants'}
                   {$participant}{'quota'}{'/dev/sda1'}{'hardlimit'}="xxx MB";
    $ref_sessions->{'supervisor'}{$supervisor}{'sophomorixSessions'}{$session}{'participants'}
                   {$participant}{'quota'}{'/dev/sda1'}{'comment'}="Home";
}




# sophomorix logging to command.log
######################################################################
sub log_script_start {
    my $stolen=0;
    my @arguments = @_;
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $skiplock=0;
    # scripts that are locking the system
    my $log="${timestamp}::start::  $0";
    my $log_locked="${timestamp}::locked:: $0";
    my $count=0;
    foreach my $arg (@arguments){
        $count++;
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        if ($arg eq "--skiplock"){
            $skiplock=1;
        }

        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $arguments[$count]="xxxxxx";
        }

        if ($arg eq ""){
   	    $log=$log." ''";
   	    $log_locked=$log_locked." ''";
        } else {
	    $log=$log." ".$arg ;
	    $log_locked=$log_locked." ".$arg ;
        }
    }

    $log=$log."::$$"."::\n";
    $log_locked=$log_locked."::$$"."::\n";

    open(LOG,">>$DevelConf::log_command");
    print LOG "$log";
    close(LOG);
    my $try_count=0;
    my $max_try_count=5;

    # exit if lockfile exists
    while (-e $DevelConf::lock_file and $skiplock==0){
        my @lock=();
        $try_count++; 
        my ($locking_script,$locking_pid)=&read_lockfile($log_locked);
        if ($try_count==1){
           &print_title("sophomorix locked (${locking_script}, PID: $locking_pid)");
        }
        my $ps_string=`ps --pid $locking_pid | grep $locking_pid`;
        $ps_string=~s/\s//g; 

        if ($ps_string eq ""){
            # locking process nonexisting
	    print "PID $locking_pid not running anymore\n";
	    print "   I'm stealing the lockfile\n";
            $stolen=&lock_sophomorix("steal",$locking_pid,@arguments);
            last;
        } else {
	    print "Process with PID $locking_pid is still running\n";
        }

        if ($try_count==$max_try_count){
            &print_title("try again later ...");
            my $string = &Sophomorix::SophomorixAPI::fetch_error_string(42);
            &print_title($string);
            exit 42;
        } else {
            sleep 1;
        }
    }
    
    if (exists ${DevelConf::lock_scripts}{$0} 
           and $stolen==0
           and $skiplock==0){
	&lock_sophomorix("lock",0,@arguments);
    }
    &print_title("$0 started ...");
    #&nscd_stop();
}



sub log_script_end {
    my @arguments = @_;
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $log="${timestamp}::end  ::  $0";
    my $count=0;
    foreach my $arg (@arguments){
        $count++;
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $arguments[$count]="xxxxxx";
        }
	$log=$log." ".$arg ;
    }
    $log=$log."::"."$$"."::\n";
    open(LOG,">>$DevelConf::log_command");
    print LOG "$log";
    close(LOG);
    # remove lock file
    if (-e $DevelConf::lock_file
         and exists ${DevelConf::lock_scripts}{$0}){
	unlink $DevelConf::lock_file;
        &print_title("Removing lock in $DevelConf::lock_file");    

    }
    #&nscd_start();
    # flush_cache tut nur bei laufendem nscd
    #&nscd_flush_cache();
    &print_title("$0 terminated regularly");
    exit;
}



sub log_script_exit {
    # 1) what to print to the log file/console
    # (unused when return =!0)
    my $message=shift;
    # 2) return 0: normal end, return=1 unexpected end
    # search with this value in errors.lang 
    my $return=shift;
    # 3) unlock (unused)
    my $unlock=shift;
    # 4) skiplock (unused)
    my $skiplock=shift;

    my @arguments = @_;
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $log="${timestamp}::exit ::  $0";

    # get correct message
    if ($return!=0){
        if ($return==1){
            # use message given by option 1)
        } else {
            $message = &Sophomorix::SophomorixAPI::fetch_error_string($return);
        }
    } 

    foreach my $arg (@arguments){
	$log=$log." ".$arg ;
    }
    $log=$log."::"."$$"."::$message\n";
    open(LOG,">>$DevelConf::log_command");
    print LOG "$log";
    close(LOG);
    # remove lock file
    if (-e $DevelConf::lock_file
         and exists ${DevelConf::lock_scripts}{$0}){
        &print_title("Removing lock in $DevelConf::lock_file");
        #&unlock_sophomorix();
        unlink $DevelConf::lock_file;
    }
    if ($message ne ""){
        &print_title("$message");
    }
    #&nscd_start();
    exit $return;
}



# backup stuff before modifying
######################################################################
# option 2: add, move, kill, update
# option 3 before, after
# optopn 4: cp should be correct
#  what is this mv for: &backup_amku_file($zeit,"add","after","mv");
sub backup_amku_file {
    my ($time, $str, $str2) = @_;
    my $input=${DevelConf::path_result}."/sophomorix.".$str;
    my $output=${DevelConf::path_log_user}."/".$time.".sophomorix.".$str."-".$str2;

    # Verarbeitete Datei mit Zeitstempel versehen
    if (-e "${input}"){
        system("cp ${input} ${output}");
        system("chown root:root ${output}");
        system("chmod 600 ${output}");
    }
}



# acl stuff
######################################################################
sub NTACL_set_file {
    my ($arg_ref) = @_;
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $ntacl = $arg_ref->{ntacl};
    my $smbpath = $arg_ref->{smbpath};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
#    my $user = $arg_ref->{user};
#    my $group = $arg_ref->{group};
   
    my $ntacl_abs=$DevelConf::path_conf_devel_ntacl."/".$ntacl.".template";
    if ($ntacl eq "noacl" or $ntacl eq "nontacl"){
        print "   Skipping ACL/NTACL creation for $smbpath\n";
        return;
    } elsif (not -r $ntacl_abs){ # -r: readable
        print "\nERROR: $ntacl_abs not found/readable\n\n";
        exit;
    }
    print "Setting the NTACL:\n";
    my $smbcacls_option="";
    open(NTACL,"<$ntacl_abs");
    my $line_count=0;
    while (<NTACL>) {
        $_=~s/\s+$//g;# remove trailing whitespace
        if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
            next;
        }
        
        my $line=$_;
        $line_count++;
        chomp($line);
        # replacements in line go here

        # create multiple lines? from one line
        if ($line_count==1){
            $smbcacls_option=$line;
        } else {
            $smbcacls_option=$smbcacls_option.",".$line;
        }


    }
    $smbcacls_option="\"".$smbcacls_option."\"";
    my $smbcacls_base_command="smbcacls -U ".$DevelConf::sophomorix_file_admin."%'".
                              $smb_admin_pass."' //$root_dns/$school $smbpath --set ";
    my $smbcacls_command=$smbcacls_base_command.$smbcacls_option;
    print "* $smbcacls_base_command\n";
    print "  $smbcacls_option\n";
    my $smbcacls_return=system("$smbcacls_command");
    if($smbcacls_return==0){
	print "NTACLS set successfully ($smbcacls_return)\n";
    } else {
	print "ERROR setting NTACLS ($smbcacls_return)\n";
    }
    close(NTACL);
}


sub ACL_set_file_obsolete {
    # $path and $aclname are mandatory
    # $workgroup will be later mandatory 
    my ($arg_ref) = @_;
    my $workgroup = $arg_ref->{workgroup};
    my $path = $arg_ref->{path};
    my $aclname = $arg_ref->{aclname};
    #my $role = $arg_ref->{role};
    #my $type = $arg_ref->{type};

    # replacements
    my $school = $arg_ref->{school};
    my $user = $arg_ref->{user};
    my $group = $arg_ref->{group};
 
    my $source="";
    my $tmp="";
    if (not defined $workgroup){
        $workgroup=LINUXMUSTER;
    }

    if (defined $aclname){
        $source=$DevelConf::path_conf_devel_acl."/".$aclname.".acl.template";
        $tmp=$DevelConf::path_conf_tmp."/".$aclname.".acl";
#    } elsif (defined $role){
#        $source=$DevelConf::path_conf_devel_acl."/".$role.".acl.template";
#        $tmp=$DevelConf::path_conf_tmp."/".$role.".acl";
#    } elsif (defined $type){
#        $source=$DevelConf::path_conf_devel_acl."/".$type.".acl.template";
#        $tmp=$DevelConf::path_conf_tmp."/".$type.".acl";
    } else {
        print "";
        &Sophomorix::SophomorixBase::log_script_exit(
            "acl_name, role or type is mandatory when setting ACL's!",1,1,0,@arguments);
    }

    if (not -e $source){
        &Sophomorix::SophomorixBase::log_script_exit(
            "acl template $source not found!",1,1,0,@arguments);
    }

    # replacements
    my $replace="";
    $replace=$replace." -e 's/\@\@WORKGROUP\@\@/${workgroup}/g'"; 
    if (defined $user){
        $replace=$replace." -e 's/\@\@USER\@\@/${user}/g'"; 
    }
    if (defined $group){
        $replace=$replace." -e 's/\@\@GROUP\@\@/${group}/g'"; 
    }
    if (defined $school){
        $replace=$replace." -e 's/\@\@SCHOOL\@\@/${school}-/g'"; 
    }

    # patch the acl into tmp
    $sed_command="sed $replace $source > $tmp";
    print "$sed_command\n";
    system($sed_command);

#    if($Conf::log_level>=2){
        print "\nPatched ACL:\n\n";
        system("cat $tmp");
        print "\n";
#    }

    # apply acl from tmp to path
    $setfacl="setfacl --set-file=".$tmp." ".$path;
    print "$setfacl\n";
    system($setfacl);
}



# password stuff
######################################################################
sub get_passwd_charlist {
   # characters for passwords
   # avoid: 1,i,l,I,L,j
   # avoid: 0,o,O
   # avoid: Capital letters, that can be confused with 
   #        small letters: C,I,J,K,L,O,P,S,U,V,W,X,Y,Z 
   my @zeichen=('a','b','c','d','e','f','g','h','i','j','k',
                'm','n','o','p','q','r','s','t','u','v',
                'w','x','y','z',
                'A','B','D','E','F','G','H','L','M','N','Q','R','T',
                '2','3','4','5','6','7','8','9',
                '!','$','&','(',')','=','?'
                );
   return @zeichen;
}


sub get_plain_password {
    my $role=shift;
    my $file=shift;
    my $random=shift;
    my $length=shift;
    my @password_chars=@_;
    my $password="";
    my $i;
    if ($role eq "teacher") {
        # Teacher
#        if ($Conf::teacher_password_random eq "yes") {
        if ( $random eq "yes") {
	    $password=&create_plain_password($length,@password_chars);
        } else {
            $password=$DevelConf::student_password_default;
	}
    } elsif ($role eq "student") {
        # Student
#        if ($Conf::student_password_random eq "yes") {
        if ($random  eq "yes") {
	    $password=&create_plain_password($length,@password_chars);
        } else {
            $password=$DevelConf::teacher_password_default;
        }
    }
#    } elsif ($role eq "examaccount") {
#        # Exam Account 12 chars to avoid login 
#        $password=&create_plain_password(12,@password_chars);
#    }
    return $password;
}



sub create_plain_password {
    my ($num)=shift;
    my @password_chars=@_;
    my $password="";
    until ($password=~m/[!,\$,&,\(,\),=,?]/ and 
           $password=~m/[a-z]/ and 
           $password=~m/[A-Z]/ and
           $password=~m/[0-9]/
          ){
        $password="";
        for ($i=1;$i<=$num;$i++){
            $password=$password.$password_chars[int (rand $#password_chars)];
        }
	print "Password to test: $password\n";
    }
    print "Password OK: $password\n";
    return $password;
}



# filesystem
######################################################################
sub get_homedirectory {
    my ($root_dns,$school,$group_basename,$user,$role)=@_;
    my $homedirectory;  # as needed to fill the attribute 'homeDirectory (using \\)
    my $unix_home;      # (works only if share is on the same server)
    my $smb_rel_path;   # option for smbclient
    
    my $school_smbshare;
    if ($school eq "global"){
        $school_smbshare=$DevelConf::homedir_global_smb_share;
    } else {
        $school_smbshare=$school;
    }
    my $unc="//".$root_dns."/".$school_smbshare;

    if ($role eq "student"){
        $smb_rel_path="students/".$group_basename."/homes/".$user;
        $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\students\\".$group_basename."\\homes\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/students/".$group_basename."/homes/".$user;
    } elsif ($role eq "teacher"){
        $smb_rel_path="teachers/homes/".$user;
        $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\teachers\\homes\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/teachers/homes/".$user;
    } elsif ($role eq "administrator"){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } else {
        $smb_rel_path="unknown/".$group_basename."/homes/".$user;
        $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\unknown\\".$group_basename."\\homes\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/unknown/".$group_basename."/homes/".$user;
    }
    return ($homedirectory,$unix_home,$unc,$smb_rel_path);
}



sub get_sharedirectory {
    my ($root_dns,$school,$group,$type)=@_;
    my $smb_share; # as needed for perl module 'homeDirectory (using //)
    my $unix_dir; # unix-path (works only if share is on the same server)
    my $smb_rel_path; # option for smbclient

    my $school_smbshare=$school;
    if ($school eq "---"){
        $school=$DevelConf::name_default_school;
        $school_smbshare=$DevelConf::name_default_school;
    } elsif ($school eq "global"){
        $school_smbshare=$DevelConf::homedir_global_smb_share;
    } else {
        $school_smbshare=$school;
    }

    my $unc="//".$root_dns."/".$school_smbshare;

    if ($type eq "project"){
        $smb_rel_path="projects/".$group;
        $smb_share="smb://".$root_dns."/".$school_smbshare."/".$smb_rel_path;
        $unix_dir="/home/schools/".$school."/projects/".$group;
    } elsif  ($type eq "adminclass"){
        my $group_basename=&get_group_basename($group,$school);
        $smb_rel_path="students/".$group_basename;
        $smb_share="smb://".$root_dns."/".$school_smbshare."/".$smb_rel_path;
        $unix_dir="/home/schools/".$school."/students/".$group_basename;
    } else {
        $smb_rel_path="unknown";
        $smb_share="unknown";
        $unix_dir="unknown";
    }

    return ($smb_share,$unix_dir,$unc,$smb_rel_path);
}



sub get_group_basename {
    my ($group,$school)=@_;
    $group=~s/^${school}-//;
    return $group;
}



# others
######################################################################
# error, when options are not given correctly
sub check_options{
   my ($parse_ergebnis) = @_;
   if (not $parse_ergebnis==1){
      my @list = split(/\//,$0);
      my $scriptname = pop @list;
      print "\nYou have made a mistake, when specifying options.\n"; 
      print "See error message above. \n\n";
      print "... $scriptname is terminating.\n\n";
      exit;
   } else {
      if($Conf::log_level>=3){
         print "All options  were recognized.\n";
      }
   }
}

# dns queries
######################################################################

sub dns_query_ip {
    my ($res,$host)=@_;

    my $ip=$host;
    my $reply = $res->search($host);
    if ($reply) {
        foreach my $rr ($reply->answer) {
            next unless $rr->type eq "A";
            return $rr->address;
        }
    } else {
        # no reply: query failed
        return $res->errorstring;
    }
    #return $ip;
}


# encoding, recoding stuff
######################################################################
sub recode_utf8_to_ascii {
    my ($string) = @_;
    # ascii (immer filtern)
    # '
    $string=~s/\x27//g;
    $string=~s/\x60//g;
    # -
    $string=~s/\x2D/-/g;
    $string=~s/\x5F/-/g;

    # utf8
    # -
    $string=~s/\xC2\xAF/-/g;
    # '
    $string=~s/\xC2\xB4//g;

    # iso 8859-1 stuff
    # A
    $string=~s/\xC3\x80/A/g;
    $string=~s/\xC3\x81/A/g;
    $string=~s/\xC3\x82/A/g;
    $string=~s/\xC3\x83/A/g;
    $string=~s/\xC3\x85/A/g;
    # Ae
    $string=~s/\xC3\x84/Ae/g;
    $string=~s/\xC3\x86/Ae/g;
    # C
    $string=~s/\xC3\x87/C/g;
    # E
    $string=~s/\xC3\x88/E/g;
    $string=~s/\xC3\x89/E/g;
    $string=~s/\xC3\x8A/E/g;
    $string=~s/\xC3\x8B/E/g;
    # I
    $string=~s/\xC3\x8C/I/g;
    $string=~s/\xC3\x8D/I/g;
    $string=~s/\xC3\x8E/I/g;
    $string=~s/\xC3\x8F/I/g;
    # D
    $string=~s/\xC3\x90/D/g;
    # I
    $string=~s/\xC3\x91/N/g;
    # O
    $string=~s/\xC3\x92/O/g;
    $string=~s/\xC3\x93/O/g;
    $string=~s/\xC3\x94/O/g;
    $string=~s/\xC3\x95/O/g;
    $string=~s/\xC3\x98/O/g;
    # Oe
    $string=~s/\xC3\x96/Oe/g;
    # X
    $string=~s/\xC3\x97/x/g;
    # U
    $string=~s/\xC3\x99/U/g;
    $string=~s/\xC3\x9A/U/g;
    $string=~s/\xC3\x9B/U/g;
    # Ue
    $string=~s/\xC3\x9C/Ue/g;
    # Y
    $string=~s/\xC3\x9D/Y/g;
    # Th
    $string=~s/\xC3\x9E/Th/g;
    # ss
    $string=~s/\xC3\x9F/ss/g;
    # a
    $string=~s/\xC3\xA0/a/g;
    $string=~s/\xC3\xA1/a/g;
    $string=~s/\xC3\xA2/a/g;
    $string=~s/\xC3\xA3/a/g;
    $string=~s/\xC3\xA5/a/g;
    # ae
    $string=~s/\xC3\xA4/ae/g;
    $string=~s/\xC3\xA6/ae/g;
    # c
    $string=~s/\xC3\xA7/c/g;
    # e
    $string=~s/\xC3\xA8/e/g;
    $string=~s/\xC3\xA9/e/g;
    $string=~s/\xC3\xAA/e/g;
    $string=~s/\xC3\xAB/e/g;
    # i
    $string=~s/\xC3\xAC/i/g;
    $string=~s/\xC3\xAD/i/g;
    $string=~s/\xC3\xAE/i/g;
    $string=~s/\xC3\xAF/i/g;
    # d
    $string=~s/\xC3\xB0/d/g;
    # n
    $string=~s/\xC3\xB1/n/g;
    # o
    $string=~s/\xC3\xB2/o/g;
    $string=~s/\xC3\xB3/o/g;
    $string=~s/\xC3\xB4/o/g;
    $string=~s/\xC3\xB5/o/g;
    # \xC3\xB7 is DIVISION SIGN
    # o
    $string=~s/\xC3\xB8/o/g;
    # oe
    $string=~s/\xC3\xB6/oe/g;
    # u
    $string=~s/\xC3\xB9/u/g;
    $string=~s/\xC3\xBA/u/g;
    $string=~s/\xC3\xBB/u/g;
    # ue
    $string=~s/\xC3\xBC/ue/g;
    # y
    $string=~s/\xC3\xBD/y/g;
    $string=~s/\xC3\xBF/y/g;
    # FE thorn
    $string=~s/\xC3\xBE/th/g;
    # iso 8859-1 stuff end
   
    # \xc4 stuff (U+0100)
    $string=~s/\xC4\x80/A/g;
    $string=~s/\xC4\x81/a/g;
    $string=~s/\xC4\x82/A/g;
    $string=~s/\xC4\x83/a/g;
    $string=~s/\xC4\x84/A/g;
    $string=~s/\xC4\x85/a/g;
    $string=~s/\xC4\x86/C/g;
    $string=~s/\xC4\x87/c/g;
    $string=~s/\xC4\x88/C/g;
    $string=~s/\xC4\x89/c/g;
    $string=~s/\xC4\x8A/C/g;
    $string=~s/\xC4\x8B/c/g;
    $string=~s/\xC4\x8C/C/g;
    $string=~s/\xC4\x8D/c/g;
    $string=~s/\xC4\x8E/D/g;
    $string=~s/\xC4\x8F/d/g;
    $string=~s/\xC4\x90/D/g;
    $string=~s/\xC4\x91/d/g;
    $string=~s/\xC4\x92/E/g;
    $string=~s/\xC4\x93/e/g;
    $string=~s/\xC4\x94/E/g;
    $string=~s/\xC4\x95/e/g;
    $string=~s/\xC4\x96/E/g;
    $string=~s/\xC4\x97/e/g;
    $string=~s/\xC4\x98/E/g;
    $string=~s/\xC4\x99/e/g;
    $string=~s/\xC4\x9A/E/g;
    $string=~s/\xC4\x9B/e/g;
    $string=~s/\xC4\x9C/G/g;
    $string=~s/\xC4\x9D/g/g;
    $string=~s/\xC4\x9E/G/g;
    $string=~s/\xC4\x9F/g/g;
    $string=~s/\xC4\xA0/G/g;
    $string=~s/\xC4\xA1/g/g;
    $string=~s/\xC4\xA2/G/g;
    $string=~s/\xC4\xA3/g/g;
    $string=~s/\xC4\xA4/H/g;
    $string=~s/\xC4\xA5/h/g;
    $string=~s/\xC4\xA6/H/g;
    $string=~s/\xC4\xA7/h/g;
    $string=~s/\xC4\xA8/I/g;
    $string=~s/\xC4\xA9/i/g;
    $string=~s/\xC4\xAA/I/g;
    $string=~s/\xC4\xAB/i/g;
    $string=~s/\xC4\xAC/I/g;
    $string=~s/\xC4\xAD/i/g;
    $string=~s/\xC4\xAE/I/g;
    $string=~s/\xC4\xAF/i/g;
    $string=~s/\xC4\xB0/I/g;
    $string=~s/\xC4\xB1/i/g;
    $string=~s/\xC4\xB2/Ij/g;
    $string=~s/\xC4\xB3/ij/g;
    $string=~s/\xC4\xB4/J/g;
    $string=~s/\xC4\xB5/j/g;
    $string=~s/\xC4\xB6/K/g;
    $string=~s/\xC4\xB7/k/g;
    $string=~s/\xC4\xB8/k/g;
    $string=~s/\xC4\xB9/L/g;
    $string=~s/\xC4\xBA/l/g;
    $string=~s/\xC4\xBB/L/g;
    $string=~s/\xC4\xBC/l/g;
    $string=~s/\xC4\xBD/L/g;
    $string=~s/\xC4\xBE/l/g;
    $string=~s/\xC4\xBF/L/g;

    # \xc5 stuff (U+0140)
    $string=~s/\xC5\x80/l/g;
    $string=~s/\xC5\x81/L/g;
    $string=~s/\xC5\x82/l/g;
    $string=~s/\xC5\x83/N/g;
    $string=~s/\xC5\x84/n/g;
    $string=~s/\xC5\x85/N/g;
    $string=~s/\xC5\x86/n/g;
    $string=~s/\xC5\x87/N/g;
    $string=~s/\xC5\x88/n/g;
    $string=~s/\xC5\x89/n/g;
    $string=~s/\xC5\x8A/N/g;
    $string=~s/\xC5\x8B/n/g;
    $string=~s/\xC5\x8C/O/g;
    $string=~s/\xC5\x8D/o/g;
    $string=~s/\xC5\x8E/O/g;
    $string=~s/\xC5\x8F/o/g;
    $string=~s/\xC5\x90/O/g;
    $string=~s/\xC5\x91/o/g;
    $string=~s/\xC5\x92/Oe/g;
    $string=~s/\xC5\x93/oe/g;
    $string=~s/\xC5\x94/R/g;
    $string=~s/\xC5\x95/r/g;
    $string=~s/\xC5\x96/R/g;
    $string=~s/\xC5\x97/r/g;
    $string=~s/\xC5\x98/R/g;
    $string=~s/\xC5\x99/r/g;
    $string=~s/\xC5\x9A/S/g;
    $string=~s/\xC5\x9B/s/g;
    $string=~s/\xC5\x9C/S/g;
    $string=~s/\xC5\x9D/s/g;
    $string=~s/\xC5\x9E/S/g;
    $string=~s/\xC5\x9F/s/g;
    $string=~s/\xC5\xA0/S/g;
    $string=~s/\xC5\xA1/s/g;
    $string=~s/\xC5\xA2/T/g;
    $string=~s/\xC5\xA3/t/g;
    $string=~s/\xC5\xA4/T/g;
    $string=~s/\xC5\xA5/t/g;
    $string=~s/\xC5\xA6/T/g;
    $string=~s/\xC5\xA7/t/g;
    $string=~s/\xC5\xA8/U/g;
    $string=~s/\xC5\xA9/u/g;
    $string=~s/\xC5\xAA/U/g;
    $string=~s/\xC5\xAB/u/g;
    $string=~s/\xC5\xAC/U/g;
    $string=~s/\xC5\xAD/u/g;
    $string=~s/\xC5\xAE/U/g;
    $string=~s/\xC5\xAF/u/g;
    $string=~s/\xC5\xB0/U/g;
    $string=~s/\xC5\xB1/ue/g;
    $string=~s/\xC5\xB2/U/g;
    $string=~s/\xC5\xB3/u/g;
    $string=~s/\xC5\xB4/W/g;
    $string=~s/\xC5\xB5/w/g;
    $string=~s/\xC5\xB6/Y/g;
    $string=~s/\xC5\xB7/y/g;
    $string=~s/\xC5\xB8/Y/g;
    $string=~s/\xC5\xB9/Z/g;
    $string=~s/\xC5\xBA/z/g;
    $string=~s/\xC5\xBB/Z/g;
    $string=~s/\xC5\xBC/z/g;
    $string=~s/\xC5\xBD/Z/g;
    $string=~s/\xC5\xBE/z/g;
    $string=~s/\xC5\xBF/s/g;
    $string=~s/\xC6\x80/b/g;
    $string=~s/\xC6\x81/B/g;
    $string=~s/\xC6\x82/B/g;
    $string=~s/\xC6\x83/b/g;
    # not a letter
    $string=~s/\xC6\x84/6/g;
    # not a letter
    $string=~s/\xC6\x85/6/g;
    $string=~s/\xC6\x86/O/g;
    $string=~s/\xC6\x87/C/g;
    $string=~s/\xC6\x88/c/g;
    $string=~s/\xC6\x89/D/g;
    $string=~s/\xC6\x8A/D/g;
    $string=~s/\xC6\x8B/D/g;
    $string=~s/\xC6\x8C/d/g;
    $string=~s/\xC6\x8D/d/g;
    $string=~s/\xC6\x8E/E/g;
    # grosses Schwa
    $string=~s/\xC6\x8F/E/g;
    # ?????? continue here
    return $string;
}




# END OF FILE
# Return true=1
1;
