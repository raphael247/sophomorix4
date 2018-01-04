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
use Config::IniFiles;
#use Unicode::GCString;
use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 

# use Net::LDAP::SID;  17.10 18.04

@ISA = qw(Exporter);

@EXPORT_OK = qw( 
               );
@EXPORT = qw(
            print_line
            print_title
            mount_school
            umount_school
            testmount_school
            NTACL_set_file
            remove_from_list
            time_stamp_AD
            time_stamp_file
            ymdhms_to_date
            ymdhms_to_epoch
            unlock_sophomorix
            lock_sophomorix
            log_script_start
            log_script_end
            log_script_exit
            get_login_avoid
            create_test_login
            backup_auk_file
            get_passwd_charlist
            get_plain_password
            create_plain_password
            check_options
            config_sophomorix_read
            result_sophomorix_init
            result_sophomorix_add
            result_sophomorix_add_log
            result_sophomorix_add_summary
            result_sophomorix_check_exit
            result_sophomorix_print
            filelist_fetch
            dir_listing_user
            dns_query_ip
            remove_whitespace
            json_progress_print
            json_dump
            console_print_mail_user
            console_print_quota_user
            console_print_mailquota_user
            get_homedirectory
            get_sharedirectory
            get_group_basename
            recode_utf8_to_ascii
            read_smb_conf
            call_sophomorix_command
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
   print  "\n########################################",
            "########################################\n";
   printf " # %-70s # ",$a;
   print  "\n########################################",
            "########################################\n";
   } else {
         printf "#### %-69s####\n",$a;
   }
}



# mount/umount school
######################################################################
sub mount_school {
    # mountpoint=filesystem directory
    # 
    my ($share,$root_dns,$smb_admin_pass,$ref_sophomorix_config)=@_;
    &print_title("Mounting school $share $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}");
    my $smb_unc;
    my $mountpoint;
    if ($share eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'} or
        $share eq $DevelConf::AD_global_ou or
        $share eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
        # global share (global/GLOBAL/linuxmuster-global will work)
        $smb_unc="//".$root_dns."/".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
        $mountpoint=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'MOUNTPOINT'};
    } else {
        # school share
        $smb_unc="//".$root_dns."/".$share;
        $mountpoint=$ref_sophomorix_config->{'SCHOOLS'}{$share}{'MOUNTPOINT'};
    }
    if ( not defined $mountpoint){
        print "\nERROR: No mountpoint found for $share (Not a school?)\n\n";
        exit;
    }

    # test if it is mounted already
    my $res1=&testmount_school($mountpoint,$smb_unc,$ref_sophomorix_config,0);
    if ($res1 eq "TRUE"){
        print "\n   $smb_unc is mounted already\n\n";
        return;
    }

    # mount
    system ("install -oroot -groot --mode=0755 -d $mountpoint");
    my $user=$DevelConf::sophomorix_AD_admin;
    my $mount_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'MOUNT'}.
                      " -t cifs -o user=".
                      $user.
                      ",pass=\"".
                      $smb_admin_pass.
                      "\",domain=".
                      $ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}.
                      " ".
                      $smb_unc.
                      " ".
                      $mountpoint."/";
    print "COMMAND: $mount_command\n";
    system($mount_command);

    # Test if mount was successful
    my $res2=&testmount_school($mountpoint,$smb_unc,$ref_sophomorix_config,0);
    if ($res2 eq "FALSE"){
        print "\nERROR: $smb_unc not mounted to $mountpoint\n\n";
    }
}



sub testmount_school {
    my ($mountpoint,$smb_unc,$ref_sophomorix_config,$list)=@_;
    # collect data from system
    my %mounts=();
    open(PROCMOUNTS, $ref_sophomorix_config->{'INI'}{'PATHS'}{'PROCMOUNTS'}) or die "Mount File not found";
    while(<PROCMOUNTS>){
        my ($unc,$mpoint,$mtype,$mopts) = split(/ +/, $_);
        if ($mtype eq "cifs"){ # care only about cifs mounts
        $mounts{$unc}{'MPOINT'}=$mpoint;
        $mounts{$unc}{'MTYPE'}=$mtype;
        $mounts{$unc}{'MOPTS'}=$mopts;
        }
    }
    close(PROCMOUNTS);
    #print Dumper(\%mounts);
    if ($list==1){
        ##### list
        my @unc_list=();
        my $line="+------------------------------------------+------------------------------------+\n";
        print "\n";
        print "List of cifs mounts on this server:\n";
        foreach my $unc (keys %mounts) {
            push @unc_list,$unc;
        }
	@unc_list = sort @unc_list;
        print $line;
        print    "| Mountpoint                               | UNC-Path                           |\n";
        print $line;
        foreach my $unc (@unc_list){
            printf "| %-41s| %-35s|\n",$mounts{$unc}{'MPOINT'},$unc;
        }
        print $line;
    } else {
        ##### test
        if (exists $mounts{$smb_unc} and $mounts{$smb_unc}{'MPOINT'} eq $mountpoint){
	    print "OK: UNC-Path $smb_unc  is mounted to $mountpoint as $mounts{$smb_unc}{'MTYPE'}\n";
            return "TRUE";
        } else {
            return "FALSE";
        }
    }
}



sub umount_school {
    my ($share,$root_dns,$ref_sophomorix_config)=@_;
    &print_title("Umounting school $share $DevelConf::AD_global_ou $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}");
    my $mountpoint;
    if ($share eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'} or
        $share eq $DevelConf::AD_global_ou){
        $mountpoint=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'MOUNTPOINT'};
    } else {
        $mountpoint=$ref_sophomorix_config->{'SCHOOLS'}{$share}{'MOUNTPOINT'};
    }
    if (defined $mountpoint){
        my $umount_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'UMOUNT'}." ".$mountpoint;
        print "COMMAND: $umount_command\n";
        my $return=system($umount_command);
    }
}



# mail stuff
######################################################################
sub alias_from_name {
    my ($surname,$firstname,$root_dns,$ref_sophomorix_config)=@_;
    $surname=~tr/A-Z/a-z/; # make lowercase
    $firstname=~tr/A-Z/a-z/; # make lowercase
    my $alias_short=$firstname.".".$surname;
    my $alias_long=$firstname.".".$surname."\@".$root_dns;
    # print "TEST: Alias is $alias\n";
    return ($alias_short,$alias_long);
}



# json stuff
######################################################################
sub json_progress_print {
    my ($arg_ref) = @_;
    my $ref_progress = $arg_ref->{ref_progress};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    if ($json==1){
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_pretty_printed = $json_obj->pretty->encode( $ref_progress );
        if ($ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'} eq "STDERR"){
            print STDERR  "$utf8_pretty_printed";
        } else {
            print STDOUT  "$utf8_pretty_printed";
        }
    } elsif ($json==2){
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_json_line   = $json_obj->encode( $ref_progress );
        if ($ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'} eq "STDERR"){
            print STDERR  "$utf8_json_line\n";
        } else {
            print STDOUT  "$utf8_json_line\n";
        }
           #print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} "$utf8_json_line";
        } elsif ($json==3){
            if ($ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'} eq "STDERR"){
                print STDERR Dumper( $ref_progress );
            } else {
                print STDOUT Dumper( $ref_progress );
            }
       }
}



sub json_dump {
    my ($arg_ref) = @_;
    my $jsoninfo = $arg_ref->{jsoninfo};
    my $jsoncomment = $arg_ref->{jsoncomment};
    my $json = $arg_ref->{json};
    my $log_level = $arg_ref->{log_level};
    my $hash_ref = $arg_ref->{hash_ref};
    my $type = $arg_ref->{type};
    my $object_name = $arg_ref->{object_name};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    # json 
    if ($json==0){
        if ($jsoninfo eq "SESSIONS"){
            &_console_print_sessions($hash_ref,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "ONESESSION"){
            &_console_print_onesession($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "DEVICES"){
            &_console_print_devices($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "ADMINS_V"){
            &_console_print_admins_v($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "USERS_V"){
            &_console_print_users_v($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "USERS_OVERVIEW"){
            &_console_print_users_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "USER"){
            # incl. administrators            
            &_console_print_user_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "PROJECTS_OVERVIEW"){
            &_console_print_projects_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "PROJECT"){
            &_console_print_project_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "CLASSES_OVERVIEW"){
            &_console_print_classes_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "CLASS"){
            &_console_print_class_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "GROUPS_OVERVIEW"){
            &_console_print_groups_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "GROUP"){
            # see MANAGEMENTGROUP
            &_console_print_group_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "MANAGEMENTGROUPS_OVERVIEW"){
            &_console_print_managementgroups_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "MANAGEMENTGROUP"){
            # see GROUP
            &_console_print_group_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "MAIL"){
            &_console_print_mail_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "SHARES"){
            &_console_print_shares($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        } elsif ($jsoninfo eq "UI"){
            &_console_print_ui($hash_ref,$object_name,$log_level,$ref_sophomorix_config)
        }
    } elsif ($json==1){
        # pretty output
        $hash_ref->{'JSONINFO'}=$jsoninfo;
        $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_pretty_printed = $json_obj->pretty->encode( $hash_ref );
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "$utf8_pretty_printed";
    } elsif ($json==2){
        # compact output
        $hash_ref->{'JSONINFO'}=$jsoninfo;
        $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_json_line   = $json_obj->encode( $hash_ref  );
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "$utf8_json_line";
    } elsif ($json==3){
        &print_title("DUMP: $jsoncomment");
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} Dumper( $hash_ref );
    }
}



sub _console_print_sessions {
    my ($ref_sessions,$log_level,$ref_sophomorix_config)=@_;
    print "LogLevel: $log_level\n";
    print "$ref_sessions->{'SESSIONCOUNT'} sessions by Session-Name:\n";
        foreach my $session (@{ $ref_sessions->{'ID_LIST'} }){
            print "  $session   $ref_sessions->{'ID'}{$session}{'SUPERVISOR'}{'sAMAccountName'}   ",
                  "$ref_sessions->{'ID'}{$session}{'sophomorixSessions'}\n";
        }
}



sub _console_print_onesession {
    my ($ref_sessions,$object_name,$log_level,$ref_sophomorix_config)=@_;
    &print_line();
    print "$ref_sessions->{'ID'}{$object_name}{'COMMENT'}  (Session-ID $object_name):\n";
    &print_line();
    my $supervisor=$ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sAMAccountName'};
    my $exammode_string;
    if ($ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sophomorixExamMode'} eq "---"){
        $exammode_string="ExamMode: OFF";
    } else {
        $exammode_string="ExamMode of $supervisor ON by ".$ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sophomorixExamMode'};
    }
    print "Supervisor: $supervisor ",
          " ($ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'givenName'} ",
          "$ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sn'})",
          "  $exammode_string\n";
    print "  $ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'SMBhomeDirectory'}\n";
    foreach my $item (@{ $ref_sessions->{'TRANSFER_DIRS'}{$supervisor}{'TRANSFER_LIST'} }){
        print "      $ref_sessions->{'TRANSFER_DIRS'}{$supervisor}{'TRANSFER'}{$item}{'TYPE'}  $item\n";
    }
    print "$ref_sessions->{'ID'}{$object_name}{'PARTICIPANT_COUNT'} participants:\n";
    &print_line();
    foreach my $participant (@{ $ref_sessions->{'ID'}{$object_name}{'PARTICIPANT_LIST'} }){
        my $exammode_string;
        if ($ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'sophomorixExamMode'} eq "---"){
            $exammode_string="OFF";
        } else {
            $exammode_string="ON by ".$ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'sophomorixExamMode'};
        }
        print "Participant: $participant",
              " ($ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'givenName'} ",
              "$ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'sn'})",
              " ExamMode: $exammode_string\n";
        foreach my $grouptype (@{ $ref_sophomorix_config->{'INI'}{'EXAMMUNTPODE'}{'MANAGEMENTGROUPLIST'} }){
            printf "      %-16s%-20s\n",
                $grouptype.":",
                $ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'group_'.$grouptype};
        }
        print "  $ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'SMBhomeDirectory'}\n";
        foreach my $item (@{ $ref_sessions->{'TRANSFER_DIRS'}{$participant}{'TRANSFER_LIST'} }){
            print "      $ref_sessions->{'TRANSFER_DIRS'}{$participant}{'TRANSFER'}{$item}{'TYPE'}  $item\n";
        }
        print "------------------------------------------------------------\n"
    }
    &print_line();
}



sub _console_print_devices {
    my ($ref_devices,$object_name,$log_level,$ref_sophomorix_config)=@_;
    #if($log_level==1 and $object_name eq ""){
        # one device per line
        &print_line();
        print "DNS Node        | IPv4          | Computer       | Room      | MAC             |\n";
        &print_line();
        foreach my $dns_node ( @{ $ref_devices->{'LISTS'}{'BY_SCHOOL'}{'global'}{'dnsNode'} } ){
            my $computer;
            my $hwc;
            my $adminclass;
            if (exists $ref_devices->{'LOOKUP'}{'sAMAccountName_BY_sophomorixDnsNodename'}{$dns_node}){
                $computer=$ref_devices->{'LOOKUP'}{'sAMAccountName_BY_sophomorixDnsNodename'}{$dns_node};
                $hwc="";
                $adminclass=$ref_devices->{'objectclass'}{'computer'}{'computer'}{$computer}{'sophomorixAdminClass'};
            } else {
                $computer="---";
                $hwc="---";
                $adminclass="---";
            }
            

            printf "|%-15s|%-15s|%-16s|%-11s|%-17s|\n",
                   $dns_node,
                   $ref_devices->{'objectclass'}{'dnsNode'}{'SophomorixdnsNode'}{$dns_node}{'IPv4'},
                   $computer,
                   $adminclass,
                   "not in AD";
            #print "$dns_node\n";
        }
        &print_line();
    #}

}



sub _console_print_classes_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line  ="+--------------------+--+--+--+---+--+-+-+-+-+-+--------------------------------+\n";
    my $line2 ="+-------------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    foreach my $school (@school_list){
        print "\n";
        &print_title("$ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'class'} classes (adminclass, teacherclass) in school $school:");
        if ($ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'class'}==0){
            next;
        }
        print $line;
        print "| Class Name         | t| s| Q| MQ|MM|H|A|L|S|J| Class Description              |\n";
        print $line;
        foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'class'} }){
            my $MQ;
            if ($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailQuota'} eq "---:---:"){
                $MQ=" - "; # unmodified
            } else {
                $MQ=" * "; # modified
            }
            my $Q=0;
            foreach my $quota ( @{ $ref_groups_v->{'GROUPS'}{$group}{'sophomorixQuota'} }){
                my ($share,$value,$comment)=split(/:/,$quota);
		if ($value ne "---" or $comment ne "---"){
                    $Q++;
                }
            }
            printf "| %-19s|%2s|%2s|%2s|%3s|%2s|%1s|%1s|%1s|%1s|%1s| %-31s|\n",
                    $group,
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'teacher'},
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'student'},
                    $Q,
                    $MQ,
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixMaxMembers'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixHidden'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailAlias'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailList'},0,1),
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixStatus'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixJoinable'},0,1),
	            $ref_groups_v->{'GROUPS'}{$group}{'description'};
        }
        print $line;
        my $max_count=$#{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'class'} }+1;
        printf "| %-78s|\n", $max_count." adminclass/teacherclass in ".$school;
        print $line2;

        print "t=teachers  s=students   Q=Quota   MQ=MailQuota  MM=MaxMembers\n";
        print "H=Hidden    A=MailAlias  L=MaiList  S=Status      J=Joinable \n";
    }
}



sub _console_print_groups_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line="+-------------------+--+---+-+-+--+--+--+---------------------------------------+\n";
    my $line2 = "+-------------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    foreach my $school (@school_list){
        print "\n";
        &print_title("$ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'sophomorix-group'} sophomorix-groups in school $school:");
        if ($ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'sophomorix-group'}==0){
            next;
        }
        print $line;
        print "| Group Name        |AQ|AMQ|A|L| m| t| s| Group Description                     |\n";
        print $line;
        foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'sophomorix-group'} }){
            my $AMQ;
            if ($ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddMailQuota'} eq "---:---:"){
                $AMQ=" - "; # unmodified
            } else {
                $AMQ=" * "; # modified
            }
            my $AQ=0;
            foreach my $addquota ( @{ $ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddQuota'} }){
                my ($share,$value,$comment)=split(/:/,$addquota);
		if ($value ne "---" or $comment ne "---"){
                    $AQ++;
                }
            }

            printf "| %-18s|%2s|%3s|%1s|%1s|%2s|%2s|%2s| %-38s|\n",
                $group,
                $AQ,
                $AMQ,
                substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailAlias'},0,1),
                substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailList'},0,1),
                $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'TOTAL'},
                $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'teacher'},
                $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'student'},
	        $ref_groups_v->{'GROUPS'}{$group}{'description'};
        }
        print $line;
        my $max_count=$#{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'sophomorix-group'} }+1;
        printf "| %-78s|\n", $max_count." projects in ".$school;
        print $line2;
        print "AQ=AddQuota  AMQ=AddMailQuota A=MailAlias   L=MaiList\n";
        print " m=member-entries             t=teachers    s=students\n";
    }
}



sub _console_print_managementgroups_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line="+------------------+----+----+----+----------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
 
    foreach my $school (@school_list){
        print "\n";
        &print_title("Managementgroups in school $school:");
        print $line;
        print "| Managementgroup  |  m |  t |  s | Group Description                            |\n";
        print $line;

        # walk through all the list of managementgroup-TYPES (sophomorixType)
        foreach my $grouptype ( @{ $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'} } ){
            # fetch all groups that have this sophomorixType
            foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{$grouptype} }){
                printf "| %-17s|%4s|%4s|%4s| %-45s|\n",
                    $group,
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'TOTAL'},
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'teacher'},
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'student'},
	            $ref_groups_v->{'GROUPS'}{$group}{'description'};
            }
        }
        print $line;
        print "m=member-entries  t=teachers  s=students\n";
    }
}



sub _console_print_projects_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line = "+-----------------------+--+---+--+-+-+-+-+-+-----------------------------------+\n";
    my $line2 = "+-------------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    foreach my $school (@school_list){
        print "\n";
        &print_title("$ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'project'} projects in school $school:");
        if ($ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'project'}==0){
            next;
        }
        print $line;
        print "| Project Name          |AQ|AMQ|MM|H|A|L|S|J| Project Description               |\n";
        print $line;
        foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'project'} }){
            my $AMQ;
            if ($ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddMailQuota'} eq "---:---:"){
                $AMQ=" - "; # unmodified
            } else {
                $AMQ=" * "; # modified
            }
            my $AQ=0;
            foreach my $addquota ( @{ $ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddQuota'} }){
                my ($share,$value,$comment)=split(/:/,$addquota);
		if ($value ne "---" or $comment ne "---"){
                    $AQ++;
                }
            }
            printf "| %-22s|%2s|%3s|%2s|%1s|%1s|%1s|%1s|%1s| %-34s|\n",
                    $group,
                    $AQ,
                    $AMQ,
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixMaxMembers'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixHidden'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailAlias'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailList'},0,1),
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixStatus'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixJoinable'},0,1),
	            $ref_groups_v->{'GROUPS'}{$group}{'description'};
        }
        print $line;
        my $max_count=$#{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'project'} }+1;
        printf "| %-78s|\n", $max_count." projects in ".$school;
        print $line2;
        print "AQ=AddQuota  AMQ=AddMailQuota  J=Joinable  MM=MaxMembers\n";
        print " A=MailAlias   L=MaiList       S=Status     H=Hidden\n";
    }
}



sub _console_print_users_overview {
    my ($ref_users_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    foreach my $school (@school_list){
        print "\n";
        &print_title("$ref_users_v->{'COUNTER'}{$school}{'TOTAL'} users in school $school:");
        if ($ref_users_v->{'COUNTER'}{$school}{'TOTAL'}==0){
            next;
        }
        my $line="+-----------+---+------+------+------+------+------++------+------+-----+\n";
        print $line;
        print "| status    |   | stud | teach| sadm | sbin | comp || gadm | gbin | oth |\n";
        print $line;
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "permanent | P",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'P'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'P'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schooladministrator'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'computer'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globaladministrator'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globalbinduser'},
               $ref_users_v->{'COUNTER'}{'OTHER'};
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "usable    | U",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'U'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'U'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "activated | A",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'A'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'A'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "enabled   | E",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'E'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'E'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "selfactiv.| S",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'S'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'S'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "tolerated | T",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'T'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'T'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "disabled  | D",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'D'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'D'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "locked    | L",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'L'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'L'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "frozen    | F",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'F'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'F'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "removable | R",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'R'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'R'},
            "","","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "killable  | K",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'K'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'K'},
            "","","","","","";
        print $line;
        printf "| %-10s|%2s |%5s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
               "sum: ".$ref_users_v->{'COUNTER'}{$school}{'TOTAL'},
               "",
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'student'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'teacher'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schooladministrator'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'computer'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globaladministrator'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globalbinduser'},
               $ref_users_v->{'COUNTER'}{'OTHER'};
        print $line;
        print "(stud=student,teach=teacher,sadm=schooladministrator,sbin=schoolbinduser,\n";
        print " comp=computer,gadm=globaladministrator,gbin=globalbinduser,oth=other)\n";
    }
    print "\nOther (oth) user objects (objectclass=user):\n";
    foreach my $user ( @{ $ref_users_v->{'LISTS'}{'USER_by_SCHOOL'}{'OTHER'}{'OTHER'} }  ){
        print "   * $user (".$ref_users_v->{'USERS'}{$user}{'DN'}.")\n";
    }
    print "\n";
}



sub _console_print_class_full {
    my ($ref_groups,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="#####################################################################\n";
    my $line= "---------------------------------------------------------------------\n";
    my $line2="+---------------------------------+---------------------------------+\n";
    my $group_count=0;
    if ($ref_groups->{'COUNTER'}{'TOTAL'}==0){
        print "0 classes (adminclass, teacherclass) can be displayed\n";
        return;
    }
    foreach my $group (@{ $ref_groups->{'LISTS'}{'GROUPS'} }){
	$group_count++;
        # calculate max entries for column height
        my $max=1; # display at least one line, even if no members are there
        if ($ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'} > $max){
	    $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'};
        }
        if ($ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'} > $max){
	    $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'};
        }

        ############################################################
        # printout
        ############################################################
        # header
        print $line1;
        print "Class $group_count/$ref_groups->{'COUNTER'}{'TOTAL'}: ",
              "$group in school $ref_groups->{'GROUPS'}{$group}{'sophomorixSchoolname'}\n";
        print "$ref_groups->{'GROUPS'}{$group}{'dn'}\n";
        print $line1;

        # attributes
        printf "%23s: %-40s\n","cn",$ref_groups->{'GROUPS'}{$group}{'cn'};
        printf "%23s: %-40s\n","description",$ref_groups->{'GROUPS'}{$group}{'description'};
        printf "%23s: %-40s\n","gidNumber",$ref_groups->{'GROUPS'}{$group}{'gidNumber'};
        print $line;
        # sophomorix attributes
        printf "%23s: %-40s\n","sophomorixCreationDate",$ref_groups->{'GROUPS'}{$group}{'sophomorixCreationDate'};
        printf "%23s: %-40s\n","sophomorixHidden",$ref_groups->{'GROUPS'}{$group}{'sophomorixHidden'};
        printf "%23s: %-40s\n","sophomorixJoinable",$ref_groups->{'GROUPS'}{$group}{'sophomorixJoinable'};
        printf "%23s: %-40s\n","sophomorixMaxMembers",$ref_groups->{'GROUPS'}{$group}{'sophomorixMaxMembers'};
        printf "%23s: %-40s\n","sophomorixStatus",$ref_groups->{'GROUPS'}{$group}{'sophomorixStatus'};
        printf "%23s: %-40s\n","sophomorixType",$ref_groups->{'GROUPS'}{$group}{'sophomorixType'};
        print $line;
        # sophomorix mail attributes
        printf "%23s: %-40s\n","sophomorixMailQuota",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailQuota'};
        printf "%23s: %-40s\n","mail",$ref_groups->{'GROUPS'}{$group}{'mail'};
        printf "%23s: %-40s\n","sophomorixMailAlias",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailAlias'};
        printf "%23s: %-40s\n","sophomorixMailList",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailList'};
        print $line;
        # sophomorix quota attributes
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixQuota'} } ){
            printf "%23s: %-40s\n","sophomorixQuota",$item;
	}

        # members
        print $line2;
        print "| Admins:                         | Members:                        |\n";
        print $line2;
        for (my $i=0;$i<$max;$i++){
	    # default display values:
            my $admin="";
            my $member="";
            # modify defaults if defined:
            if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i]){
                $admin=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i];
            }
            if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i]){
                $member=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i];
            }
            printf "|%32s |%32s |\n",$admin,$member;
	}
        print $line2;
        # sum up
        printf "| Number of Admins:  %12s | Number of Members: %12s |\n",
            $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'},
            $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'};
        print $line2;

        # optional -v : memberships
        if ($log_level>1){
            print "memberOf:\n";
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'memberOf'} } ){
                print "$item\n";
	    }
            print $line;
            print "member:\n";
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'member'} } ){
                print "$item\n";
	    }
            print $line;
        }

	print "\n";
    }
}



sub _console_print_group_full {
    my ($ref_groups,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="#####################################################################\n";
    my $line= "---------------------------------------------------------------------\n";
    my $line2="+---------------------------------+---------------------------------+\n";
    my $group_count=0;
    if ($ref_groups->{'COUNTER'}{'TOTAL'}==0){
        print "0 sophomorix-groups can be displayed\n";
        return;
    }
    foreach my $group (@{ $ref_groups->{'LISTS'}{'GROUPS'} }){
	$group_count++;

        ############################################################
        # printout
        ############################################################
        # header
        print $line1;
        print "Group $group_count/$ref_groups->{'COUNTER'}{'TOTAL'}: ",
              "$group in school $ref_groups->{'GROUPS'}{$group}{'sophomorixSchoolname'}\n";
        print "$ref_groups->{'GROUPS'}{$group}{'dn'}\n";
        print $line1;

        # attributes
        printf "%23s: %-40s\n","cn",$ref_groups->{'GROUPS'}{$group}{'cn'};
        printf "%23s: %-40s\n","description",$ref_groups->{'GROUPS'}{$group}{'description'};
        printf "%23s: %-40s\n","gidNumber",$ref_groups->{'GROUPS'}{$group}{'gidNumber'};
        print $line;

        # sophomorix attributes
        printf "%23s: %-40s\n","sophomorixCreationDate",$ref_groups->{'GROUPS'}{$group}{'sophomorixCreationDate'};
        printf "%23s: %-40s\n","sophomorixType",$ref_groups->{'GROUPS'}{$group}{'sophomorixType'};
        print $line;

        # sophomorix mail attributes
        printf "%23s: %-40s\n","mail",$ref_groups->{'GROUPS'}{$group}{'mail'};
        printf "%23s: %-40s\n","sophomorixAddMailQuota",$ref_groups->{'GROUPS'}{$group}{'sophomorixAddMailQuota'};
        printf "%23s: %-40s\n","sophomorixMailAlias",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailAlias'};
        printf "%23s: %-40s\n","sophomorixMailList",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailList'};
        print $line;

        # sophomorix quota attributes
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixAddQuota'} } ){
            printf "%23s: %-40s\n","sophomorixAddQuota",$item;
	}

        # memberships
        print $line;
        print "memberOf:\n";
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'memberOf'} } ){
            print "$item\n";
	}
        print $line;
        print "member:\n";
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'member'} } ){
            print "$item\n";
	}
        print $line;
	print "\n";
    }
}



sub _console_print_project_full {
    my ($ref_groups,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="###############################################################################\n";
    my $line= "-------------------------------------------------------------------------------\n";
    my $line2="+----------------+----------------+---------------------+---------------------+\n";
    my $group_count=0;
    if ($ref_groups->{'COUNTER'}{'TOTAL'}==0){
        print "0 projects can be displayed\n";
        return;
    }
    foreach my $group (@{ $ref_groups->{'LISTS'}{'GROUPS'} }){
	$group_count++;
        # calculate max entries for column height
        my $max=1; # display at least one line, even if no members are there
        if ($ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'} > $max){
	    $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'};
        }
        if ($ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'} > $max){
	    $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'};
        }
        if ($ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups_count'} > $max){
	    $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups_count'};
        }
        if ($ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups_count'} > $max){
	    $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups_count'};
        }

        ############################################################
        # printout
        ############################################################
        # header
        print $line1;
        print "Project $group_count/$ref_groups->{'COUNTER'}{'TOTAL'}: ",
              "$group in school $ref_groups->{'GROUPS'}{$group}{'sophomorixSchoolname'}\n";
        print "$ref_groups->{'GROUPS'}{$group}{'dn'}\n";
        print $line1;

        # attributes
        printf "%23s: %-40s\n","cn",$ref_groups->{'GROUPS'}{$group}{'cn'};
        printf "%23s: %-40s\n","description",$ref_groups->{'GROUPS'}{$group}{'description'};
        printf "%23s: %-40s\n","gidNumber",$ref_groups->{'GROUPS'}{$group}{'gidNumber'};
        print $line;
        # sophomorix attributes
        printf "%23s: %-40s\n","sophomorixCreationDate",$ref_groups->{'GROUPS'}{$group}{'sophomorixCreationDate'};
        printf "%23s: %-40s\n","sophomorixHidden",$ref_groups->{'GROUPS'}{$group}{'sophomorixHidden'};
        printf "%23s: %-40s\n","sophomorixJoinable",$ref_groups->{'GROUPS'}{$group}{'sophomorixJoinable'};
        printf "%23s: %-40s\n","sophomorixMaxMembers",$ref_groups->{'GROUPS'}{$group}{'sophomorixMaxMembers'};
        printf "%23s: %-40s\n","sophomorixStatus",$ref_groups->{'GROUPS'}{$group}{'sophomorixStatus'};
        printf "%23s: %-40s\n","sophomorixType",$ref_groups->{'GROUPS'}{$group}{'sophomorixType'};
        print $line;
        # sophomorix mail attributes
        printf "%23s: %-40s\n","mail",$ref_groups->{'GROUPS'}{$group}{'mail'};
        printf "%23s: %-40s\n","sophomorixAddMailQuota",$ref_groups->{'GROUPS'}{$group}{'sophomorixAddMailQuota'};
        printf "%23s: %-40s\n","sophomorixMailAlias",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailAlias'};
        printf "%23s: %-40s\n","sophomorixMailList",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailList'};
        print $line;
        # sophomorix quota attributes
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixAddQuota'} } ){
            printf "%23s: %-40s\n","sophomorixAddQuota",$item;
	}

        # members
        print $line2;
        print "| Admins:        | Members:       | AdminGroups:        | MemberGroups:       |\n";
        print $line2;
        for (my $i=0;$i<$max;$i++){
	    # default display values:
            my $admin="";
            my $member="";
            my $admingroup="";
            my $membergroup="";
            # modify defaults if defined:
            if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i]){
                $admin=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i];
            }
            if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i]){
                $member=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i];
            }
            if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups'}[$i]){
                $admingroup=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups'}[$i];
            }
            if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups'}[$i]){
                $membergroup=$ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups'}[$i];
            }
            printf "|%15s |%15s |%20s |%20s |\n",$admin,$member,$admingroup,$membergroup;
	}
        print $line2;
        # sum up
        printf "| Admins: %6s | Members:%6s | AdminGroups: %6s | MemberGroups:%6s |\n",
            $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'},
            $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'},
            $ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups_count'},
            $ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups_count'};
        print $line2;

        # optional -v : memberships
        if ($log_level>1){
            print "memberOf:\n";
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'memberOf'} } ){
                print "$item\n";
	    }
            print $line;
            print "member:\n";
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'member'} } ){
                print "$item\n";
	    }
            print $line;
        }
	print "\n";
    }
}



sub console_print_mail_user {
    my ($arg_ref) = @_;
    my $ref_mail = $arg_ref->{ref_mail};
    my $ref_sophomorix_config = $arg_ref->{ref_sophomorix_config};
    my $user = $arg_ref->{user};
    my $log_level=$arg_ref->{log_level};
    my $line="+------------------------------------------".
              "------------------------------------+\n";
    my $role=$ref_mail->{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};
    my $school=$ref_mail->{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'};

    print $line;
    printf "| %-77s|\n", $user." in ".$school;
    print $line;
    printf "%30s: %-40s\n","Addresbook displayName",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'displayName'};
    printf "%30s: %-40s\n","mail",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'mail'};
    if ( $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIAS'} eq "TRUE" ){
        printf "%30s: %-40s\n","Calculated Alias",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIASNAME_LONG'};
    } else {
        printf "%30s: %-40s\n","Calculated Alias",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIAS'};
    }

    printf "%30s: %-40s\n","Calculated maillist membership",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLISTMEMBER'};
    if ( $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLISTMEMBER'} eq "TRUE" ){
        foreach my $list (keys %{ $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'} } ) {
            printf "%30s: %-40s\n","* MAILLIST",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'}{$list};
        }
    }
}



sub console_print_mailquota_user {
    my ($arg_ref) = @_;
    my $ref_quota = $arg_ref->{ref_quota};
    my $ref_sophomorix_config = $arg_ref->{ref_sophomorix_config};
    my $user = $arg_ref->{user};
    my $log_level=$arg_ref->{log_level};
    my $line="+------------------------------------------".
              "------------------------------------+\n";

    # create shortcut vars
    my $role=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};

    ############################################################
    # MailQuota
    my $mailquota_school_default=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'SCHOOLDEFAULT'};
    my $mailquota_user_display;
    my $mailquota_user_comment;
    if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'}){
        $mailquota_user_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'};
	$mailquota_user_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'COMMENT'};
    } else {
        $mailquota_user_display="---";
        $mailquota_user_comment="---";
    }
    my $mailquota_class_display;
    my $mailquota_class_comment;
    if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'}){
        $mailquota_class_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'};
        $mailquota_class_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'COMMENT'};
    } else {
        $mailquota_class_display="---";
        $mailquota_class_comment="comment";
    }

    my $mailcalc_display;
    if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
        # append asterisk
        $mailcalc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}."*";
    } else {
        # append space
        $mailcalc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}." ";
    }

    # printout
    if($log_level>=2){
        # print extensive information
        print $line;
        printf "| %-77s|\n","MailQuota for user ".$user." in MiB (Mebibyte):";
        printf "|%10s %-67s|\n",
               $mailquota_school_default,
               " (A) default MailQuota for sophomorixRole \'".$role."\'";
        if ($mailquota_class_display ne "---"){
            printf "|%10s %-67s|\n",
                   $mailquota_class_display,
                   " (B) Quota at the users class \'".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                   "\': Overrides (A)";
            printf "|%10s %-67s|\n",
                   " ",
                   " Comment: \'".
                   $mailquota_class_comment.
                   "\'";
        } else {
            printf "|%10s %-67s|\n",
                   $mailquota_class_display,
                   " (B) No Quota at the users class \'".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                   "\'";
        }


        foreach my $group ( @{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
            my @reason=();
            my $membership_string="";
            foreach my $reason (keys %{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'REASON'} }) {
                push @reason,$reason;
            }
            @reason = sort @reason;
            $membership_string=join(",",@reason);
	    if (exists $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'}){
		my $add=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'};
                printf "|%10s %-67s|\n",
                       "+ ".
                       $add,
                       " AddMailQuota, member in ".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                       " \'".
                       $group.
                       "\' (".
                       $membership_string.
                       ")";
                printf "|%10s %-67s|\n",
                       "",
                       " Comment: \'".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'COMMENT'}.
                       "\'";
	    } else {
                printf "|%10s %-67s|\n",
                       "0",
                       " No AddMailQuota, member in ".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                       " \'".
                       $group.
                       "\' (".
                       $membership_string.
                       ")";
	    }
        }


        if ($mailquota_user_display eq "---"){
            printf "|%10s %-67s|\n",
                   $mailquota_user_display,
                   " (C) No MailQuota at the user Object \'".
                   $user.
                   "\'";
        } else {
            printf "|%10s %-67s|\n",
                   $mailquota_user_display,
                   " (C) MailQuota at the user will override all above settings";
            printf "|%10s %-67s|\n",
                   " ",
                   " Comment: \'".
                   $mailquota_user_comment.
                   "\'";
        }

        # show calc 
        if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
            printf "|%11s%-67s|\n",
                   $mailcalc_display,
                   " MAILCALC must be set (old MAILCALC is ".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}.
                   " MiB)";
        } else {
            printf "|%11s%-67s|\n",
                   $mailcalc_display,
                   " MAILCALC was already set to ".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}.
                   " MiB";
        }
        print $line;
    } else {
        # print single line
	printf "| %-25s| %-7s|%6s|%5s |%5s | %-18s|\n",
               "$user($role:$mailquota_school_default)",
               "**MQ**",
               $mailcalc_display,
               $mailquota_user_display,
               $mailquota_class_display,
               $ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'GROUPSTRING'};
    }
}



sub console_print_quota_user {
    my ($arg_ref) = @_;
    my $ref_quota = $arg_ref->{ref_quota};
    my $ref_sophomorix_config = $arg_ref->{ref_sophomorix_config};
    my $user = $arg_ref->{user};
    my $log_level = $arg_ref->{log_level};
    my $line="+------------------------------------------".
              "------------------------------------+\n";
    if (not exists $ref_quota->{'QUOTA'}{'USERS'}{$user}){
        print "  WARNING: User $user not found!\n";
        next;
    } 
    # create shortcut vars
    my $role=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};
    my $school=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'};

    # print user end/share begin line
    if($log_level==1){
        #print $line;
    } else {
        print $line;
        printf "| %-77s|\n", $user." in ".$school;
    }

    ############################################################
    # Walk through all shares
    foreach my $share ( @{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }){
        # get values for display
        my $school_default;
        my $share_display;
	if ($share eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
            $school_default=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'quota_default_global'};
	    $share_display="GLOBAL";
	} elsif ($share eq $school){
            $school_default=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'quota_default_school'};
	    $share_display=$share;
        } else {
            $school_default="---";                    
	    $share_display=$share;
        }
  	if ($share eq $DevelConf::name_default_school){
            $share_display="DEFLT";
	}

        # get the users quota or --- for display
        my $quota_user_display;
        my $quota_user_comment;
        if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}
                                {$share}{'sophomorixQuota'}){
	    $quota_user_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}
                                            {$share}{'sophomorixQuota'};
	    $quota_user_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}
	                                    {$share}{'COMMENT'};
	} else {
            $quota_user_display="---";
            $quota_user_comment="---";
        }
        my $quota_class_display;
        my $quota_class_comment;
        if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}
                                {'sophomorixQuota'}{$share}{'VALUE'}){
	    $quota_class_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}
	                                     {'sophomorixQuota'}{$share}{'VALUE'};
	    $quota_class_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}
	                                     {'sophomorixQuota'}{$share}{'COMMENT'};

        } else {
            $quota_class_display="---";
            $quota_class_comment="---";
        }

        my $calc_display;
        if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} eq "TRUE"){
            # append asterisk
            $calc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'CALC'}."*";
        } else {
                # append space
                $calc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'CALC'}." ";
        }

        # printout
        if($log_level>=2){
            # print extensive information
            print $line;
            printf "| %-77s|\n",$share." share for user ".$user." in MiB (Mebibyte):";
            printf "|%10s %-67s|\n",
                $school_default,
                " (A) default Quota for sophomorixRole \'".$role."\'";
            if ($quota_class_display ne "---"){
                printf "|%10s %-67s|\n",
                       "",
                       " (B) Quota at the users class \'".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                       "\': Overrides (A)";
                printf "|%10s %-67s|\n",
                       $quota_class_display,
                       " Comment: \'".
                       $quota_class_comment.
                       "\'";
    	    } else {
                printf "|%10s %-67s|\n",
                       $quota_class_display,
                       " (B) No Quota at the users class \'".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                       "\'";
            }
            foreach my $group ( @{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
                my @reason=();
                my $membership_string="";
                foreach my $reason (keys %{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'REASON'} }) {
                    push @reason,$reason;
                }
                @reason = sort @reason;
                $membership_string=join(",",@reason);
		if (exists $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'}){
		    my $add=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'};
                    printf "|%10s %-67s|\n","+ ".$add,
                           " AddQuota, member in ".
                           $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                           " \'".
                           $group.
                           "\' (".
                           $membership_string.")";
                    printf "|%10s %-67s|\n","",
                           " Comment: \'".
                           $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'COMMENT'}.
                           "\'";
		} else {
                    printf "|%10s %-67s|\n","0",
                           " No AddQuota, member in ".
                           $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                           " \'".
                           $group.
                           "\' (".
                           $membership_string.")";
		}
            }
            if ($quota_user_display eq "---"){
                printf "|%10s %-67s|\n",$quota_user_display," (C) No Quota at the user Object \'".$user."\'";
            } else {
                printf "|%10s %-67s|\n",$quota_user_display," (C) Quota at the user will override all above settings";
                printf "|%10s %-67s|\n"," "," Comment: \'".$quota_user_comment."\'";
            }

            # show calc 
            if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} eq "TRUE"){
                printf "|%11s%-67s|\n",
                       $calc_display,
                       " CALC must be set for ".$user." on ".$share;
            } else {
                printf "|%11s%-67s|\n",
                       $calc_display,
                       " CALC was already set for ".$user." on ".$share;
                my $mib=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}/1024;
                printf "|%11s%-67s|\n",
                       "",
                       " SMB share quota was set to ".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}." Bytes (".
                       $mib.
                       " MiB)";
            }
	} else {
            # print single line
	    printf "| %-25s| %-7s|%6s|%5s |%5s | %-18s|\n",
                   "$user($role:$school_default)",
                   $share_display,
                   $calc_display,
                   $quota_user_display,
                   $quota_class_display,
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'GROUPSTRING'};
        }
    } # end of share walk
}



sub _console_print_user_full {
    my ($ref_users,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="################################################################################\n";
    my $line= "--------------------------------------------------------------------------------\n";

    # UNKNOWN_USERS
    foreach my $user (@{ $ref_users->{'LISTS'}{'UNKNOWN_USERS'} }){
        print "\n";
        print $line1;
        print "Nothing known about user: $user\n";
        print $line1;
    }

    # DELETED_USERS
    my $user_count_deleted=0;
    my $user_count_deleted_max=$#{ $ref_users->{'LISTS'}{'DELETED_USERS'} }+1;
    foreach my $user (@{ $ref_users->{'LISTS'}{'DELETED_USERS'} }){
        $user_count_deleted++;
        print "\n";
        print $line1;
        print "Deleted user $user_count_deleted/$user_count_deleted_max: $user\n";
        print $line1;
        print "LOGFILES ($ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'} Entries):\n";
        foreach my $epoch (@{ $ref_users->{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }){
            print "  ".$ref_users->{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}."\n";
        }
    }

    # USERS in AD
    my $user_count=0;
    foreach my $user (@{ $ref_users->{'LISTS'}{'USERS'} }){
        $user_count++;
        print "\n";
        print $line1;
        print "User $user_count/$ref_users->{'COUNTER'}{'TOTAL'} in AD: ",
              "$user in school $ref_users->{'USERS'}{$user}{'sophomorixSchoolname'}\n";
        print "$ref_users->{'USERS'}{$user}{'dn'}\n";
        print $line1;
        if (exists $ref_sophomorix_config->{'LOOKUP'}{'BINDUSERS'}{$ref_users->{'USERS'}{$user}{'sophomorixRole'}}){
            # its a bind user
            print "Bind DN for $user:\n",
                  "  $ref_users->{'USERS'}{$user}{'dn'}\n";
            print "PASSWORD for $user (PWDFileExists: $ref_users->{'USERS'}{$user}{'PWDFileExists'}):\n",
                  "  $ref_users->{'USERS'}{$user}{'PASSWORD'}\n";
            print $line;
        } elsif (exists $ref_sophomorix_config->{'LOOKUP'}{'ADMINISTRATORS'}{$ref_users->{'USERS'}{$user}{'sophomorixRole'}}){
            # its an adminisrator
            printf "%29s: %-40s\n","PWDFileExists",$ref_users->{'USERS'}{$user}{'PWDFileExists'};
            printf "%29s: %-40s\n","PASSWORD",$ref_users->{'USERS'}{$user}{'PASSWORD'};
            if ($ref_users->{'USERS'}{$user}{'PWDFileExists'} eq "TRUE"){
                printf "%29s: %-40s\n","PWDFile",$ref_users->{'USERS'}{$user}{'PWDFile'};
            }
            print $line;
        }

        printf "%29s: %-40s\n","displayName",$ref_users->{'USERS'}{$user}{'displayName'};
        printf "%29s: %-40s\n","sn",$ref_users->{'USERS'}{$user}{'sn'};
        printf "%29s: %-40s\n","givenName",$ref_users->{'USERS'}{$user}{'givenName'};
        printf "%29s: %-40s\n","sophomorixFirstnameASCII",$ref_users->{'USERS'}{$user}{'sophomorixFirstnameASCII'};
        printf "%29s: %-40s\n","sophomorixSurnameASCII",$ref_users->{'USERS'}{$user}{'sophomorixSurnameASCII'};
        printf "%29s: %-40s\n","sophomorixBirthdate",$ref_users->{'USERS'}{$user}{'sophomorixBirthdate'};
        printf "%29s: %-40s\n","sophomorixUnid",$ref_users->{'USERS'}{$user}{'sophomorixUnid'};
        printf "%29s: %-40s\n","sophomorixAdminClass",$ref_users->{'USERS'}{$user}{'sophomorixAdminClass'};
        printf "%29s: %-40s\n","sophomorixExitAdminClass",$ref_users->{'USERS'}{$user}{'sophomorixExitAdminClass'};
        printf "%29s: %-40s\n","sophomorixSchoolname",$ref_users->{'USERS'}{$user}{'sophomorixSchoolname'};
        printf "%29s: %-40s\n","sophomorixAdminFile",$ref_users->{'USERS'}{$user}{'sophomorixAdminFile'};
        printf "%29s: %-40s\n","sophomorixComment",$ref_users->{'USERS'}{$user}{'sophomorixComment'};
        printf "%29s: %-40s\n","sophomorixFirstPassword",$ref_users->{'USERS'}{$user}{'sophomorixFirstPassword'};
        printf "%29s: %-40s\n","sophomorixExamMode",$ref_users->{'USERS'}{$user}{'sophomorixExamMode'};
        print $line;
        printf "%29s: %-40s\n","sophomorixRole",$ref_users->{'USERS'}{$user}{'sophomorixRole'};
        printf "%29s: %-40s\n","sophomorixStatus",$ref_users->{'USERS'}{$user}{'sophomorixStatus'};
        printf "%29s: %-40s\n","sophomorixCreationDate",$ref_users->{'USERS'}{$user}{'sophomorixCreationDate'};
        printf "%29s: %-40s\n","sophomorixTolerationDate",$ref_users->{'USERS'}{$user}{'sophomorixTolerationDate'};
        printf "%29s: %-40s\n","sophomorixDeactivationDate",$ref_users->{'USERS'}{$user}{'sophomorixDeactivationDate'};
        printf "%29s: %-40s\n","userAccountControl",$ref_users->{'USERS'}{$user}{'userAccountControl'};
        print $line;
        printf "%29s: %-40s\n","mail",$ref_users->{'USERS'}{$user}{'mail'};
        printf "%29s: %-40s\n","sophomorixMailQuota",$ref_users->{'USERS'}{$user}{'sophomorixMailQuota'};
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixMailQuotaCalculated'}){
            printf "%29s: %-40s\n","sophomorixMailQuotaCalculated",
                $ref_users->{'USERS'}{$user}{'sophomorixMailQuotaCalculated'};
        } else {
            printf "%29s: %-40s\n","sophomorixMailQuotaCalculated","(undef)";
        }

        print $line;
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixQuota'} } ){
            printf "%29s: %-40s\n","sophomorixQuota",$item;
	}

        print $line;
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixWebuiPermissions'} } ){
            printf "%29s: %-40s\n","sophomorixWebuiPermissions",$item;
	}
        print "sophomorixWebuiPermissionsCalculated:\n";
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixWebuiPermissionsCalculated'} } ){
            print "   $item\n";
	}

        print $line;
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'memberOf'} } ){
            print "memberOf: $item\n";
	}

        # samba stuff:
        print $line;
        if ($log_level>=2){
            printf "%19s: %-50s\n","homeDirectory",$ref_users->{'USERS'}{$user}{'homeDirectory'};
            printf "%19s: %-50s\n","homeDrive",$ref_users->{'USERS'}{$user}{'homeDrive'};

            printf "%19s: %-50s\n","accountExpires",$ref_users->{'USERS'}{$user}{'accountExpires'};
            printf "%19s: %-50s\n","badPasswordTime",$ref_users->{'USERS'}{$user}{'badPasswordTime'};
            printf "%19s: %-50s\n","badPwdCount",$ref_users->{'USERS'}{$user}{'badPwdCount'};
            printf "%19s: %-50s\n","pwdLastSet",$ref_users->{'USERS'}{$user}{'pwdLastSet'};

            printf "%19s: %-50s\n","lastLogoff",$ref_users->{'USERS'}{$user}{'lastLogoff'};
            printf "%19s: %-50s\n","lastLogon",$ref_users->{'USERS'}{$user}{'lastLogon'};
            printf "%19s: %-50s\n","logonCount",$ref_users->{'USERS'}{$user}{'logonCount'};

            if ($ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_RELEASE'} eq "17.10"){
                #my $sid = Net::LDAP::SID->new($ref_users->{'USERS'}{$user}{'objectSid'});

                printf "%19s: %-50s\n","objectSid",$ref_users->{'USERS'}{$user}{'objectSid'};
                printf "%19s: %-50s\n","objectGUID","(binary)";
            } else {
                printf "%19s: %-50s\n","objectSid","(binary)";
                printf "%19s: %-50s\n","objectGUID","(binary)";
            }

            printf "%19s: %-50s\n","sAMAccountType",$ref_users->{'USERS'}{$user}{'sAMAccountType'};
            printf "%19s: %-50s\n","userPrincipalName",$ref_users->{'USERS'}{$user}{'userPrincipalName'};

            printf "%19s: %-50s\n","uSNChanged",$ref_users->{'USERS'}{$user}{'uSNChanged'};
            printf "%19s: %-50s\n","uSNCreated",$ref_users->{'USERS'}{$user}{'uSNCreated'};

            printf "%19s: %-50s\n","codePage",$ref_users->{'USERS'}{$user}{'codePage'};
            printf "%19s: %-50s\n","countryCode",$ref_users->{'USERS'}{$user}{'countryCode'};
	}

        # unix stuff:
        if ($log_level>=2){
            printf "%19s: %-50s\n","uidNumber",$ref_users->{'USERS'}{$user}{'uidNumber'};
            printf "%19s: %-50s\n","unixHomeDirectory",$ref_users->{'USERS'}{$user}{'unixHomeDirectory'};
            printf "%19s: %-50s\n","primaryGroupID",$ref_users->{'USERS'}{$user}{'primaryGroupID'};
            print $line;
	}
        if ($log_level>=2 and $ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'}>0){
            print "LOGFILES ($ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'} Entries):\n";
            foreach my $epoch (@{ $ref_users->{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }){
                print "  ".$ref_users->{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}."\n";
            }
        } else {
            print "LOGFILES: $ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'} Entries\n";
        }
    }
}



sub _console_print_users_v {
    my ($ref_users_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    # one user per line

    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    my @rolelist=("teacher","student");
    my $line= "+---------------+---+----------------+----------+--------------------------+\n";
    my $line2="+===========================================================================+\n";

    foreach my $school (@school_list){
        $count_string=$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'teacher'}+
	              $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'student'}.
                      " users (".$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'teacher'}.
                      " Teachers + ".
                      $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'student'}.
                      " Students)";
        &print_title("$count_string in school $school:");
        if ($ref_users_v->{'COUNTER'}{$school}{'TOTAL'}==0){
            next;
        }

        foreach my $role (@rolelist){
            print $line;
            my $role_display;
            if ($role eq "student"){
                $role_display="Students";
            } elsif ($role eq "teacher"){
                $role_display="Teachers";
            } else {
                $role_display=$role;
            }
	    printf "|%5s %-9s| S | AdminClass     | Role     | displayName              |\n",
                $ref_users_v->{'COUNTER'}{$school}{'by_role'}{$role},$role_display;
            if ($#{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } >-1){
                print $line;
                foreach my $user ( @{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } ){
                    #my $gcs  = Unicode::GCString->new($ref_users_v->{'USERS'}{$user}{'displayName'});
                    if ($role eq "schooladministrator"){
                        $role="sadmin";
                    }
                    if ($role eq "schoolbinduser"){
                        $role="sbind";
                    }
	  	    printf "| %-14s| %-2s| %-15s| %-9s| %-23s\n",
                        $user,
                        $ref_users_v->{'USERS'}{$user}{'sophomorixStatus'},
                        $ref_users_v->{'USERS'}{$user}{'sophomorixAdminClass'},
                        $role,
		        $ref_users_v->{'USERS'}{$user}{'displayName'};
                }
            }
            print $line;
        }
    } # school end 
}



sub _console_print_admins_v {
    my ($ref_users_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    # one user per line
    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    @school_list=($ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'},@school_list);

    my $line="+----------------------+-+-------------------------+------+--------------------------------+\n";

    foreach my $school (@school_list){
        my $count_admin;
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            $count_admin=$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'globaladministrator'}+
                          $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'globalbinduser'};
            
        } else {
            $count_admin=$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schooladministrator'}+
                          $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'};
        }

        &print_title("$count_admin administrators in school $school:");
        if ($count_admin==0){
            next;
        }
        print $line;
        print "| Administrator        |P| displayName             | Role | Comment                        |\n";
        print $line;
        foreach my $role ( @{ $ref_sophomorix_config->{'LISTS'}{'ALLADMINS'} } ){
            if ($#{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } >-1){
                foreach my $user ( @{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } ){
                    #my $gcs  = Unicode::GCString->new($ref_users_v->{'USERS'}{$user}{'displayName'});
		    my $role_display=$ref_sophomorix_config->{'LOOKUP'}{'ALLADMINS'}{$role};
	  	    printf "| %-21s|%-1s| %-24s| %-4s | %-31s|\n",
                        $user,
                        substr($ref_users_v->{'USERS'}{$user}{'PWDFileExists'},0,1),,
                        $ref_users_v->{'USERS'}{$user}{'displayName'},
                        $role_display,
		        $ref_users_v->{'USERS'}{$user}{'sophomorixComment'};
                }
            }
        }
        print $line; 
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            print "P: Password file exists(T) or not(F)   gadm: globaladministrator   gbin: globalbinduser\n";
        } else {
            print "P: Password file exists(T) or not(F)   sadm: schooladministrator   sbin: schoolbinduser\n";
        }
        print "\n";
    } # school end 
}



sub _console_print_shares {
    my ($ref_share,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $count_share=0;
    my $count_school=0;
    my $line="+----------------------------------------------------------------------------+\n"; 

    # order shares before listing
    my @shares=(@{ $ref_share->{'LISTS'}{'GLOBAL'} },
                @{ $ref_share->{'LISTS'}{'SCHOOLS'} },
                @{ $ref_share->{'LISTS'}{'OTHER_SHARES'} });

    foreach my $share ( @shares ){
        $count_share++;
        print "$line";
        printf "| %2s) SMB-Share: %-60s|\n",$count_share,$share." (Type: ".$ref_share->{'SHARES'}{$share}{'TYPE'}.")";
        print "$line";

        if ($ref_share->{'SHARES'}{$share}{'TYPE'} eq "SCHOOL"){
            print"Configuration files: (*: exists, -:nonexisting)\n";
            foreach my $file ( @{ $ref_share->{'SHARES'}{$share}{'FILELIST'} } ){
                print "   ".$ref_share->{'SHARES'}{$share}{'FILE'}{$file}{'EXISTSDISPLAY'}." ".$file."\n";
            }
            print "SMB-share for school $share:\n";
        }
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTSDISPLAY'},
                                  "SMB-share $share";
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFSDISPLAY'},
                                  "msdfs root = ".$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFS'};
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSERDISPLAY'},
                                  "aquota.user exists = ".$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSER'};
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'},
                                  "smbcquotas -F => ".$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'};
        print "\n";
    }
}



sub _console_print_ui {
    my ($ref_ui,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $count_share=0;
    my $line="+----------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq ""){
        # prepend global as school
        @school_list=($ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'},
                      @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} });
    } else {
        @school_list=($school_opt);
    }

    my @rolelist=("globaladministrator","schooladministrator","teacher","student");

    foreach my $school (@school_list){
        print "\n";
        &print_title("School $school:");
        foreach my $role (@rolelist){
            if ($#{ $ref_ui->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } >-1){
                print $line;
                printf "| %-70s|\n", $school." --> sophomorixRole: ".$role;
                print $line;
                foreach my $user ( @{ $ref_ui->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } ){
                    print " $user ($ref_ui->{'UI'}{'USERS'}{$user}{'displayName'}, $role):\n"; 
                    print " sophomorixWebuiPermissionsCalculated:\n";
                    foreach my $item ( @{ $ref_ui->{'UI'}{'USERS'}{$user}{'OLD'}{'sophomorixWebuiPermissionsCalculated'} } ){
                        print "    $item\n";
	            }
                print $line;
                }
	    }
        }
    } # end $school
}



sub _console_print_mail_full {
    my ($ref_mail,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="#####################################################################\n";

    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    @school_list=($ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'},@school_list);
    foreach my $school (@school_list){
        &print_title("Mailaccounts/Maillists of school $school:");
        # there are 0 users
        if($#{ $ref_mail->{'LISTS'}{'USER_by_SCHOOL'}{$school} }==-1){
            print "     0 sophomorix users in school $school\n";
            next;
        }

        # there are users
        ############################################################
        # Walk through users
        print "Mailaccounts: (MAILLISTMEMBERS: *)\n";
        foreach my $user (@{ $ref_mail->{'LISTS'}{'USER_by_SCHOOL'}{$school} }){
            my $alias="ALIAS=FALSE";
            my $maillistmember_string;
            if ($ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLISTMEMBER'} eq "TRUE"){
                $maillistmember_string="*"; # *=TRUE
            } else {
                $maillistmember_string="-"; #-=FALSE
            }
            if ($ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIAS'} eq "TRUE"){
                $alias="ALIAS=".$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIASNAME'};
            }
            my $user_string="  ".$maillistmember_string." ".
                            $user.
                            " (".
                            $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'displayName'}.
                            ", ".
                            $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}.
                            " MiB, ".
                            $alias.
                            ")\n";
  
	    print $user_string;
        }
        print "\n";

        ############################################################
        # Walk through mailists
        foreach my $maillist ( @{ $ref_mail->{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} } ){
	    print "Maillist $maillist ($ref_mail->{'MAILLIST'}{$maillist}{'mail'}):\n";
            foreach my $member ( @{ $ref_mail->{'MAILLIST'}{$maillist}{'LIST'} } ){
	        print "  * $member\n";
            }
            print "\n";
        }
    } # end of school
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



sub ymdhms_to_date {
    my ($string)=@_;
    my ($ymdhms,$timezone)=split(/\./,$string);
    my ($year,$month,$day,$hour,$minute,$second)=unpack 'A4 A2 A2 A2 A2 A2',$ymdhms;
    my $date=$year."-".$month."-".$day." ".$hour.":".$minute.":".$second;
    return $date;
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
    my ($year,$month,$day,$hour,$minute,$second)=unpack 'A4 A2 A2 A2 A2 A2',$ymdhms;
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
    #my ($type,$pid,@arguments) = @_;
    my ($type,$pid,$ref_arguments) = @_;
    # $type: lock (lock when not existing)
    # $type, steal when existing
    # $pid: steal only when this pid is in the lock file

    # prepare datastring to write into lockfile
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $lock="lock::${timestamp}::creator::$0";
#    foreach my $arg (@arguments){
    foreach my $arg ( @{ $ref_arguments}  ){    
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



# command execution 
######################################################################
sub call_sophomorix_command {
    my ($log_level,$json,$command)=@_;
    my $all_opt="";
    if ($log_level==2){
	$all_opt=$all_opt."v";
    } elsif ($log_level==3){
        $all_opt=$all_opt."vv";
    }
    if ($json==1){
        $all_opt=$all_opt."j";
    } elsif ($json==2){
        $all_opt=$all_opt."jj";
    } elsif ($json==3){
        $all_opt=$all_opt."jjj";
    }
    if ($all_opt ne ""){
        $all_opt="-".$all_opt;
    }
    my $full_command=$command." ".$all_opt;
    print "$full_command\n";
    system($full_command);
}



# reading configuration files
######################################################################
sub config_sophomorix_read {
    my ($ldap,$root_dse,$ref_result,$json)=@_;
    my %sophomorix_config=();

    my ($smb_pwd)=&Sophomorix::SophomorixSambaAD::AD_get_passwd($DevelConf::sophomorix_AD_admin,
                                                                $DevelConf::secret_file_sophomorix_AD_admin);
    # read epoch
    $sophomorix_config{'UNIX'}{'EPOCH'}=time;

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

    # read sophomorix.ini
    &read_sophomorix_ini(\%sophomorix_config,$ref_result);
    # read lsbrelease
    &read_lsbrelease(\%sophomorix_config,$ref_result);
    # read smb.conf
    &read_smb_conf(\%sophomorix_config,$ref_result);
    # read more samba stuff
    &read_smb_net_conf_list(\%sophomorix_config,$ref_result);
    &read_smb_domain_passwordsettings(\%sophomorix_config,$smb_pwd,$ref_result);

    #my %encodings_set = map {lc $_ => undef} @encodings_arr;

    # Adding some defaults: ????? better to move the defaults to an external file ?????
    # default school
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'CONF_FILE'}=
        $DevelConf::path_conf_sophomorix."/".$DevelConf::name_default_school."/school.conf"; 
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'TEMPLATES_LATEX_DIR'}=
                            $DevelConf::path_conf_sophomorix."/".$DevelConf::name_default_school."/".
                            $sophomorix_config{'INI'}{'LATEX'}{'TEMPLATES_CUSTOM_SUBDIR'};

    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'SCHOOL_LONGNAME'}=
        "School"; 
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'OU_TOP'}=
        "OU=".$DevelConf::name_default_school.",".$DevelConf::AD_schools_ou.",".$root_dse; 

    # Adding repdir absolute paths
    opendir REPDIR, $DevelConf::path_conf_devel_repdir or 
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$DevelConf::path_conf_devel_repdir." not found!");
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
    my $ref_master_sophomorix=&read_master_ini($DevelConf::path_conf_master_sophomorix,$ref_result);
    my $ref_modmaster_sophomorix=&check_config_ini($ref_master_sophomorix,$DevelConf::file_conf_sophomorix,$ref_result);
    &load_sophomorix_ini($ref_modmaster_sophomorix,\%sophomorix_config,$ref_result);

    ##################################################
    # SCHOOLS  
    # read the *.school.conf
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'}=
            "OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
                 if ($school eq $DevelConf::name_default_school){
                     # default-school
                     $sophomorix_config{'SCHOOLS'}{$school}{'SCHOOL'}=
                          $DevelConf::name_default_school;
                     $sophomorix_config{'SCHOOLS'}{$school}{'PREFIX'}="";
                     $sophomorix_config{'SCHOOLS'}{$school}{'POSTFIX'}="";
                 } else {
                     # *school
                     $sophomorix_config{'SCHOOLS'}{$school}{'SCHOOL'}=$school;
                     $sophomorix_config{'SCHOOLS'}{$school}{'PREFIX'}=$school."-";
                     $sophomorix_config{'SCHOOLS'}{$school}{'POSTFIX'}="-".$school;
                     $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'}=
                         $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
                 }

        # load the master ini
        my $ref_master=&read_master_ini($DevelConf::path_conf_master_school,$ref_result);
        my $conf_school=$sophomorix_config{'SCHOOLS'}{$school}{'CONF_FILE'};
        # modify the master
        my $ref_modmaster=&check_config_ini($ref_master,$conf_school,$ref_result);
        &load_school_ini($root_dse,$school,$ref_modmaster,\%sophomorix_config,$ref_result);
        # mountpoint
        $sophomorix_config{'SCHOOLS'}{$school}{'MOUNTPOINT'}=
            $sophomorix_config{'INI'}{'PATHS'}{'MOUNTPOINT'}."/schools/".$school;
        # mailconf
        if ($sophomorix_config{'SCHOOLS'}{$school}{'MAILTYPE'} ne "none"){
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONFDIR'}=
                $DevelConf::path_conf_sophomorix."/".$school."/".
                $sophomorix_config{'SCHOOLS'}{$school}{'MAILTYPE'};
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONF'}=
                $DevelConf::path_conf_sophomorix."/".$school."/".
                $school.".".$sophomorix_config{'SCHOOLS'}{$school}{'MAILTYPE'}.".conf";
        } else {
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONFDIR'}="none";
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONF'}="none";
        }
    }

    # GLOBAL
    $sophomorix_config{$DevelConf::AD_global_ou}{'OU_TOP'}=
        "OU=".$DevelConf::AD_global_ou.",".$root_dse;
    # read global
    $sophomorix_config{$DevelConf::AD_global_ou}{'SCHOOL'}=$sophomorix_config{'INI'}{'GLOBAL'}{'SCHOOLNAME'};
    #$sophomorix_config{$DevelConf::AD_global_ou}{'SCHOOL'}="global2";
    $sophomorix_config{$DevelConf::AD_global_ou}{'PREFIX'}="";
    # mountpoint
    $sophomorix_config{$DevelConf::AD_global_ou}{'MOUNTPOINT'}=
        $sophomorix_config{'INI'}{'PATHS'}{'MOUNTPOINT'}."/".$sophomorix_config{'INI'}{'GLOBAL'}{'SCHOOLNAME'};

    # SCHOOL
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'OU_TOP'}=
        "OU=".$DevelConf::name_default_school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'SCHOOL'}=
        $DevelConf::name_default_school;
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'PREFIX'}="";
    # mountpoint
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'MOUNTPOINT'}=
        $sophomorix_config{'INI'}{'PATHS'}{'MOUNTPOINT'}."/schools/".$DevelConf::name_default_school;


    #print Dumper(%sophomorix_config);
    #exit;

   # Working on the sections of sophomorix.ini
    ###############################################
    foreach my $section  (keys %{$sophomorix_config{'INI'}}) {
        if ($section eq "SCHOOLS"){
            # do something
        } elsif ($section eq "ROLE"){
            # create LOOKUP for ROLES
            foreach my $keyname (keys %{$sophomorix_config{'INI'}{'ROLE'}}) {
                $sophomorix_config{'LOOKUP'}{'ROLES'}{$sophomorix_config{'INI'}{'ROLE'}{$keyname}}=$keyname;
            }
        } elsif ($section eq "SYNC_MEMBER"){
            my @keepgroup=&ini_list($sophomorix_config{'INI'}{$section}{'KEEPGROUP'});
	    foreach my $group (@keepgroup) {
                # save in lookup table
                $sophomorix_config{'INI'}{$section}{'KEEPGROUP_LOOKUP'}{$group}="keepgroup";
            }
        } elsif ($section=~m/^administrator\./){ 
            # remember in lists
            my ($string,$name)=split(/\./,$section);
	    push @{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
	    push @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
            $sophomorix_config{'LOOKUP'}{'ADMINISTRATORS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
            $sophomorix_config{'LOOKUP'}{'ALLADMINS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
        } elsif ($section=~m/^binduser\./){ 
            my ($string,$name)=split(/\./,$section);
            # remember in lists
	    push @{ $sophomorix_config{'LISTS'}{'BINDUSERS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
	    push @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
            $sophomorix_config{'LOOKUP'}{'BINDUSERS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
            $sophomorix_config{'LOOKUP'}{'ALLADMINS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
        } elsif ($section=~m/^userfile\./ or $section=~m/^devicefile\./ or $section=~m/^classfile\./){ 
            my ($string,$name,$extension)=split(/\./,$section);
            foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
                my $filename;
                if ($school eq $DevelConf::name_default_school){
                    $filename = $name.".".$extension;
                } else {
                    $filename = $school.".".$name.".".$extension;
                }
                if ($string eq "userfile"){
                    # role
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'sophomorixRole'}=
                        $sophomorix_config{'INI'}{$section}{'USER_ROLE'};
                    # type
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'sophomorixType'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_TYPE'};
                    # GROUP_OU
#                    $sophomorix_config{'INI'}{$section}{'GROUP_OU'}=
#                        &remove_whitespace($sophomorix_config{'INI'}{$section}{'GROUP_OU'});
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'GROUP_OU'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_OU'};
                    # field5
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'FIELD_5'}=
                        $sophomorix_config{'INI'}{$section}{'FIELD_5'};
                    # field6
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'FIELD_6'}=
                        $sophomorix_config{'INI'}{$section}{'FIELD_6'};
                    # force group
                    $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'FORCE_GROUP'}=
                        $sophomorix_config{'INI'}{$section}{'FORCE_GROUP'};
                    # forced groupname
                    if (defined $sophomorix_config{'INI'}{$section}{'FORCE_GROUPNAME'}){
#                        if ($school eq $DevelConf::name_default_school){
                            $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'FORCE_GROUPNAME'}=
                                $sophomorix_config{'INI'}{$section}{'FORCE_GROUPNAME'};
#                        } else {
#                            $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'FORCE_GROUPNAME'}=
#                                $school."-".$sophomorix_config{'INI'}{$section}{'FORCE_GROUPNAME'};
#                        }
                    } else {
                        $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'FORCE_GROUPNAME'}="FALSE";
                    }
                    # MANMEMBEROF
                    my @manmember=&ini_list($sophomorix_config{'INI'}{$section}{'MANMEMBEROF'});
                    foreach my $manmember (@manmember){
                        $manmember=&replace_vars($manmember,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'MANMEMBEROF'} }, $manmember; 
                    }
                    # MEMBEROF
                    my @member=&ini_list($sophomorix_config{'INI'}{$section}{'MEMBEROF'});
                    foreach my $member (@member){
                        $member=&replace_vars($member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'MEMBEROF'} }, $member; 
                    }
                    # SOPHOMORIXMEMBEROF
                    my @s_member=&ini_list($sophomorix_config{'INI'}{$section}{'SOPHOMORIXMEMBEROF'});
                    foreach my $s_member (@s_member){
                        $s_member=&replace_vars($s_member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{'SOPHOMORIXMEMBEROF'} }, $s_member; 
                    }
                } elsif ($string eq "classfile"){
                    # role
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$filename}{'sophomorixRole'}=
                        $sophomorix_config{'INI'}{$section}{'USER_ROLE'};
                    # field5
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$filename}{'FIELD_5'}=
                        $sophomorix_config{'INI'}{$section}{'FIELD_5'};
                    # field6
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$filename}{'FIELD_6'}=
                        $sophomorix_config{'INI'}{$section}{'FIELD_6'};
                    # force group
                    $sophomorix_config{'FILES'}{'CLASS_FILE'}{$filename}{'FORCE_GROUP'}=
                        $sophomorix_config{'INI'}{$section}{'FORCE_GROUP'};

                } elsif ($string eq "devicefile"){
                    # role
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'sophomorixRole'}=
                        $sophomorix_config{'INI'}{$section}{'USER_ROLE'};
                    # type
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'sophomorixType'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_TYPE'};
                    # GROUP_OU
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'GROUP_OU'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_OU'};
                    # MANMEMBEROF
                    my @manmember=&ini_list($sophomorix_config{'INI'}{$section}{'MANMEMBEROF'});
                    foreach my $manmember (@manmember){
                        $manmember=&replace_vars($manmember,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'MANMEMBEROF'} }, $manmember; 
                    }
                    # MEMBEROF
                    my @member=&ini_list($sophomorix_config{'INI'}{$section}{'MEMBEROF'});
                    foreach my $member (@member){
                        $member=&replace_vars($member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'MEMBEROF'} }, $member; 
                    }
                    # SOPHOMORIXMEMBEROF
                    my @s_member=&ini_list($sophomorix_config{'INI'}{$section}{'SOPHOMORIXMEMBEROF'});
                    foreach my $s_member (@s_member){
                        $s_member=&replace_vars($s_member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'SOPHOMORIXMEMBEROF'} }, $s_member; 
                    }
                }
            }
        }
    }

    # Working on the Lists of sophomorix.ini
    ###############################################
    # GLOBAL
    # OU for Administrators ????
    $sophomorix_config{$DevelConf::AD_global_ou}{ADMINS}{OU}=
        $sophomorix_config{'INI'}{'OU'}{'AD_management_ou'}.",".$sophomorix_config{$DevelConf::AD_global_ou}{OU_TOP};

    # GROUP in section GLOBAL
    foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'GLOBAL'}{'GROUP'}) ){
        my ($groupname,$grouptype,$sub_ou)=split(/\|/,$entry);
        my $cn_group="CN=".$groupname.",".$sub_ou.",".
            $sophomorix_config{$DevelConf::AD_global_ou}{'OU_TOP'};
        $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP_CN'}{$cn_group}=$groupname;
        $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP'}{$groupname}=
            $sub_ou.",".
            $sophomorix_config{$DevelConf::AD_global_ou}{'OU_TOP'};
        $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP_TYPE'}{$groupname}=$grouptype;
    }

    # GROUP in section SCHOOLS
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        $sophomorix_config{'SCHOOLS'}{$school}{'ADMINS'}{OU}=
            $sophomorix_config{'INI'}{'OU'}{'AD_management_ou'}.",".$sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
        foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'SCHOOLS'}{'GROUP'}) ){
            my ($groupname,$grouptype,$sub_ou)=split(/\|/,$entry);
            $groupname=&replace_vars($groupname,\%sophomorix_config,$school);
            my $cn_group="CN=".$groupname.",".$sub_ou.",".
                $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP_CN'}{$cn_group}=$groupname;
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP'}{$groupname}=
                $sub_ou.",".
                $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP_TYPE'}{$groupname}=$grouptype;
        }
    }

    # GROUPMEMBEROF in section GLOBAL
    foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'GLOBAL'}{'GROUPMEMBEROF'}) ){
        my ($membergroup,$group)=split(/\|/,$entry);
        $sophomorix_config{'GLOBAL'}{'GROUP_MEMBEROF'}{$membergroup}=$group;
    }

    # GROUPMEMBEROF in section SCHOOLS
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'SCHOOLS'}{'GROUPMEMBEROF'}) ){
            my ($membergroup,$group)=split(/\|/,$entry);
            $membergroup=&replace_vars($membergroup,\%sophomorix_config,$school);
            $group=&replace_vars($group,\%sophomorix_config,$school);
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP_MEMBEROF'}{$membergroup}=$group;
        }
    }

    # create MANAGEMENTGROUPLIST from MANAGEMENTGROUP 
    my @managementgrouplist=&Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUP'});
    $sophomorix_config{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'}=[ \@managementgrouplist ];

    # sorting some lists
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        @{ $sophomorix_config{'SCHOOLS'}{$school}{'FILELIST'} } = 
            sort @{ $sophomorix_config{'SCHOOLS'}{$school}{'FILELIST'} };
    }

    if ($#{ $sophomorix_config{'LISTS'}{'SCHOOLS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} } = sort @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} };
    }
    if ($#{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} } = sort @{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} };
    }
    if ($#{ $sophomorix_config{'LISTS'}{'BINDUSERS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'BINDUSERS'} } = sort @{ $sophomorix_config{'LISTS'}{'BINDUSERS'} };
    }
    if ($#{ $sophomorix_config{'LISTS'}{'ALLADMINS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} } = sort @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} };
    }
    return %sophomorix_config; 
}


 
sub replace_vars {
    my ($string,$ref_sophomorix_config,$school)=@_;
    my $replacement=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'PREFIX'};
    $string=~s/\@\@SCHOOLPREFIX\@\@/$replacement/g; 
    $string=~s/\@\@SCHOOLNAME\@\@/$school/g; 
    return $string;
}



sub read_smb_conf {
    my ($ref_sophomorix_config,$ref_result)=@_;
    &print_title("Reading $DevelConf::smb_conf");
    if (not -e $DevelConf::smb_conf){
        print "\nERROR: $DevelConf::smb_conf not found!\n\n";
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$DevelConf::smb_conf." not found!");
        return;
    }
    tie %{ $ref_sophomorix_config->{'samba'}{'smb.conf'} }, 'Config::IniFiles',
        ( -file => $DevelConf::smb_conf, 
          -handle_trailing_comment => 1,
        );
    # add some calculated stuff
    # Domain DNS: i.e. DC=linuxmuster,DC=local or DC=LINUXMUSTER,DC=LOCAL
    my $domain=$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'realm'};
    $domain=~tr/A-Z/a-z/; # make lowercase
    my @dns=split(/\./,$domain);
    $domain_dns = join(',DC=', @dns);
    $domain_dns="DC=".$domain_dns;
    $ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'DomainDNS'}=$domain_dns;
    
}



sub read_sophomorix_ini {
    my ($ref_sophomorix_config,$ref_result)=@_;
    &print_title("Reading $DevelConf::sophomorix_ini");
    if (not -e $DevelConf::sophomorix_ini){
        print "\nERROR: $DevelConf::sophomorix_ini not found!\n\n";
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$DevelConf::sophomorix_ini." not found!");
        return;
    }
    tie %{ $ref_sophomorix_config->{'INI'} }, 'Config::IniFiles',
        ( -file => $DevelConf::sophomorix_ini, 
          -handle_trailing_comment => 1,
        );
}



sub read_lsbrelease {
    my ($ref_sophomorix_config,$ref_result)=@_;
    open(LSB_RELEASE,"<$ref_sophomorix_config->{'INI'}{'LINUX'}{'LSB_RELEASE'}") || 
        die "Cannot find $ref_sophomorix_config->{'INI'}{'LINUX'}{'LSB_RELEASE'}\n";
    while (<LSB_RELEASE>){
        chomp();
        my ($key,$value)=split(/=/);
        $ref_sophomorix_config->{'linux'}{'lsb-release'}{$key}=$value;
    }
    close(LSB_RELEASE);
    $allowed_distrib_id=$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_ID'};
    $distrib_id=$ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_ID'};
    $release=$ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_RELEASE'};
    if ($distrib_id ne $allowed_distrib_id){
	print "ERROR: sophomorix is best run on $allowed_distrib_id (You are using: $distrib_id)\n";
        exit;
    }
    if ($release==$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_STABLE'} or
        $release==$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_UPCOMING'} or
        $release==$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_EXPERIMENTAL'}){
        print "Distro-check: $distrib_id $release is OK\n";
    } else {
	print "ERROR: sophomorix runs only on certain $allowed_distrib_id distributions:\n";
	print "       $ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_STABLE'} (STABLE)\n";
	print "       $ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_UPCOMING'} (UPCOMING)\n";
	print "       $ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_EXPERIMENTAL'} (EXPERIMENTAL)\n";
        print "You have $distrib_id $release\n";
        exit;
    }
}



sub ini_list {
    my ($ref)=@_;
    # returns empty list if parameter not given
    if (not defined $ref){
        my @list=();
        return @list;
    }
    
    # returns one element list if parameter is key->value
    if ($#{ $ref }==-1 ){
        my @list=($ref);
        return @list;
    }

    # returns multi element list if parameter is specified multiple times
    return @{ $ref };

    # example code
    #my @list=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.global'}{'MEMBERSHIP'});
    #    foreach my $item (@list){
    #        print "ITEM: $item\n";
    #    }
}



sub read_smb_net_conf_list {
    my ($ref_sophomorix_config,$ref_result)=@_;
    my $tmpfile="/tmp/net_conf_list";
    &print_title("Parsing: net conf list");
    system("net conf list > $tmpfile");
    tie %{ $ref_sophomorix_config->{'samba'}{'net_conf_list'} }, 'Config::IniFiles',
        ( -file => $tmpfile, 
          -handle_trailing_comment => 1,
        );
    system("rm $tmpfile");
    # create sharelist
    foreach my $share (keys %{ $ref_sophomorix_config->{'samba'}{'net_conf_list'} }) {
        push @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} }, $share; 
    }
    if ($#{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} } >0){
        @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} }= sort @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} };
    }
}



sub read_smb_domain_passwordsettings {
    my ($ref_sophomorix_config,$smb_pwd,$ref_result)=@_;
    &print_title("Asking domain passwordsettings from samba");
    my $string=`samba-tool domain passwordsettings show --password='$smb_pwd' -U $DevelConf::sophomorix_AD_admin`;
    my @lines=split(/\n/,$string);
    foreach my $line (@lines){
        my ($key,$value)=split(/:/,$line);
        if (defined $value){
            $key=&remove_whitespace($key);
            $key=~s/\)//g;
            $key=~s/\(//g;
            $key=~s/ /_/g;
            $value=&remove_whitespace($value);
            if($Conf::log_level>=3){
                print "   * <$key> ---> <$value>\n";
            }
            $ref_sophomorix_config->{'samba'}{'domain_passwordsettings'}{$key}=$value;
        }
    }
}



sub read_master_ini {
    my ($masterfile,$ref_result)=@_;
    my %master=();
    &print_title("Reading $masterfile");
    if (not -e $masterfile){
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$masterfile." not found!");
        return;
        #print "\nERROR: $masterfile not found!\n\n";
        #exit;
    }
    tie %master, 'Config::IniFiles',
        ( -file => $masterfile, 
          -handle_trailing_comment => 1,
        );
    return \%master;
}



sub check_config_ini {
    my ($ref_school,$configfile,$ref_result)=@_;
    # take the master reference as school reference and overwrite it
    &print_title("Reading $configfile");
    if (not -e $configfile){
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$configfile." not found!");
        return;
        #print "\nERROR: $configfile not found!\n\n";
        #exit;
    }
    tie %config, 'Config::IniFiles',
        ( -file => $configfile, 
          -handle_trailing_comment => 1,
        );
    # walk through all settings in the fonfig
    foreach my $section ( keys %config ) {
        foreach my $parameter ( keys %{$config{$section}} ) {
            #print "Verifying if parameter $parameter is valid in section $section\n";
            if (exists $ref_school->{$section}{$parameter}){
                #print "parameter $section -> $parameter is valid OK\n";
                # overwrite  $ref_school
                $ref_school->{$section}{$parameter}=$config{$section}{$parameter};
            } else {
		print " * ERROR: ".$parameter." is NOT valid in section ".$section."\n";
                &result_sophomorix_add($ref_result,
                                       "ERROR",-1,
                                       $ref_parameter,
                                       $parameter.
                                       " is NOT valid in section ".
                                       $section.
                                       " of ".
                                       $configfile.
                                       "!");
                #print "   * WARNING: $parameter is NOT valid in section $section\n";
            }
        }
    }
    return $ref_school;
}



sub load_school_ini {
    my ($root_dse,$school,$ref_modmaster,$ref_sophomorix_config,$ref_result)=@_;
    foreach my $section ( keys %{ $ref_modmaster } ) {
	if ($section eq "school"){
            ##### school section ########################################################################
            # walk through parameters
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * SCHOOL $school: Para: $parameter -> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'SCHOOLS'}{$school}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
            }
                # add more stuff
                foreach my $member ( @DevelConf::AD_schools_group_members ){
                    my ($group)=&Sophomorix::SophomorixSambaAD::AD_get_name_tokened($member,$school,"group");
                    push @{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'SCHOOLGROUP_MEMBERGROUPS'} }, $group;
                }
	} elsif ($section=~m/^userfile\./ or $section=~m/^devicefile\./ or $section=~m/^classfile\./){ 
            ##### file.* section ########################################################################
	    my ($string,$name,$extension)=split(/\./,$section);
            my $filename;
            my $prefix;
            my $postfix;
            my $ou_top;
            # calculate some things
            if ($school eq $DevelConf::name_default_school){
                $filename=$name.".".$extension;
                $prefix="";
                $postfix="";
                $ou_top=$ref_sophomorix_config->{'SCHOOLS'}{$DevelConf::name_default_school}{OU_TOP};
            } else {
                $filename=$school.".".$name.".".$extension;
                $prefix=$school."-";
                $postfix="-".$school;
                $ou_top=$ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP};
            }
            # load parameters
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * FILE $filename: $parameter ---> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
            }

            if ($string eq "userfile"){
                # add some redundant stuff for convenience
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'PATH_ABS_UTF8'}=
                    $DevelConf::path_conf_tmp."/".$filename.".utf8";
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'PATH_ABS_REPORT_OFFICE'}=
                    $ref_sophomorix_config->{'INI'}{'PATHS'}{'REPORT_OFFICE'}."/report.office.".$filename;
                # save unchecked filter script for error messages
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT_CONFIGURED}=
                    $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT};
            } elsif ($string eq "classfile"){
                # add some redundant stuff for convenience
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'PATH_ABS_UTF8'}=
                    $DevelConf::path_conf_tmp."/".$filename.".utf8";
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'PATH_ABS_REPORT_OFFICE'}=
                    $ref_sophomorix_config->{'INI'}{'PATHS'}{'REPORT_OFFICE'}."/report.office.".$filename;
                # save unchecked filter script for error messages
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{FILTERSCRIPT_CONFIGURED}=
                    $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{FILTERSCRIPT};
            }

            if ($name eq "students" or
                $name eq "extrastudents"or
                $name eq "teachers"
		){
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'SCHOOL'}=$school;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'OU_TOP'}=$ou_top;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'FILETYPE'}="users";
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'PREFIX'}=$prefix;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'POSTFIX'}=$postfix;
                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$filename;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'PATH_ABS'}=$path_abs;
                push @{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'FILELIST'} },$path_abs;
            } elsif ($name eq "devices"){
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'FILETYPE'}="devices";
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'SCHOOL'}=$school;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'OU_TOP'}=$ou_top;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'PREFIX'}=$prefix;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'POSTFIX'}=$postfix;
                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$filename;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'PATH_ABS'}=$path_abs;
                push @{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'FILELIST'} },$path_abs;
            } elsif ($name eq "extraclasses"){
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'SCHOOL'}=$school;
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'OU_TOP'}=$ou_top;
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'FILETYPE'}="classes";
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'PREFIX'}=$prefix;
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'POSTFIX'}=$postfix;
                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$filename;
                $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$filename}{'PATH_ABS'}=$path_abs;
                push @{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'FILELIST'} },$path_abs;
            }

            # test filterscript for userfiles
            if ($string eq "userfile"){
                if (defined $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}){
                    # save unchecked filter script for error messages
                    $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT_CONFIGURED}=
                        $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT};
	            my $filter_script=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT};
                    if ($filter_script eq "---"){
                        #$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}=$filter_script;
 	            } elsif (-f $filter_script and -x $filter_script and $filter_script=~m/^\//){
                        # configured value is a file and executable
                        $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}=$filter_script;
                    } else {
                        $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}="ERROR_FILTERSCRIPT";
                        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                            "FILTERSCRIPT=".$filter_script." -> FILTERSCRIPT must be an absolute path to an executable script");
                    }
                }
                # test encoding
                if (defined $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING}){
                    my $enc=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING};
                    if (exists $ref_sophomorix_config->{'ENCODINGS'}{$enc} or 
                        $enc eq "auto"){
                    } else {
                        $ref_sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{ENCODING}="ERROR_ENCODING";
                        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                              "ENCODING ".$enc." not listed by 'iconv --list' and not 'auto'");
                    }
                }
                # test if encoding force is yes/no
                if (defined $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE}){
                    if($ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE} eq "yes" or
                       $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE} eq "no" ){
                       # OK
                    } else {
                        #print "   * ERROR: ENCODING_FORCE=".
                        #      $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE}.
                        #      " accepts only \"yes\" or \"no\"\n";
                        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                            "ENCODING_FORCE=".
                            $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE}.
                            " -> ENCODING_FORCE accepts only 'yes' or 'no'");
                        #return;
		        #exit;
                    }
                }
            }
	} elsif ($section=~m/^classfile\./){ 
            # classfile
	} elsif ($section=~m/^role\./){ 
            ##### role.* section ########################################################################
	    my ($string,$name)=split(/\./,$section);
	    my $role=$name; # student, ...
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * ROLE $role: $parameter ---> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'ROLES'}{$school}{$role}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
		if (exists $ref_sophomorix_config->{'INI'}{'UI'}{$parameter}){
                    # Parameter is an UI
                    my @entries=split(/,/,$ref_modmaster->{$section}{$parameter});
                    foreach my $entry (@entries){
                        my ($module,$switch)=split(/:/,$entry);
                        if ($switch eq "TRUE"){
                            push @{ $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI_LIST'}{$parameter}{'TRUE'} }, $module;
                            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{$parameter}{'TRUE'}{$module}="TRUE";
                        } elsif ($switch eq "FALSE"){
                            push @{ $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI_LIST'}{$parameter}{'FALSE'} }, $module;
                            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{$parameter}{'FALSE'}{$module}="FALSE";
                        } else {
                            print "\nERROR: $switch must be TRUE/FALSE in school $school, role $role for $parameter\n\n";
                            exit;
                        }
                    }
                }    
            }
	} elsif ($section=~m/^type\./){ 
            ##### type.* section ########################################################################
	    my ($string,$name)=split(/\./,$section);
            my $typename;
            if ($school eq $DevelConf::name_default_school){
                $typename=$name;
            } else {
                $typename=$school."-".$name;
            }
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * TYPE $typename: $parameter ---> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'TYPES'}{$typename}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
            }
	} elsif ($section=~m/^managementgroup\./){ 
            ##### managementgroup.* section ########################################################################
	    my ($string,$name)=split(/\./,$section);
            my $managementgroupname;
            if ($school eq $DevelConf::name_default_school){
                $managementgroupname=$name;
            } else {
                $managementgroupname=$school."-".$name;
            }
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * MANAGEMENTGROUP $managementgroupname: $parameter ---> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'MANAGEMENTGROUPS'}{$managementgroupname}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
            }
        } else {
            ##### unnown section ########################################################################
            &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                "Section ".$section." -> unknown, not processed");
            #print "ERROR: Section $section: unknown, not processed\n\n";
            #exit;
        }
    }
}



sub load_sophomorix_ini {
    my ($ref_modmaster_sophomorix,$ref_sophomorix_config,$ref_result)=@_;
    foreach my $section ( keys %{ $ref_modmaster_sophomorix } ) {
        if ($section eq "global"){
            foreach my $parameter ( keys %{ $ref_modmaster_sophomorix->{$section}} ) {
                if ($Conf::log_level>=3){
                    print "   * $section: $parameter ---> <".
                          $ref_modmaster_sophomorix->{$section}{$parameter}.">\n";
                }
                if ($parameter eq "SCHOOLS"){
		    my @schools=split(/,/,$ref_modmaster_sophomorix->{$section}{$parameter});
                    foreach my $school (@schools){
                        $school=&remove_whitespace($school);
                        push @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }, $school; 
                        $ref_sophomorix_config->{'SCHOOLS'}{$school}{'CONF_FILE'}=
                            $DevelConf::path_conf_sophomorix."/".$school."/".$school.".school.conf";
                        $ref_sophomorix_config->{'SCHOOLS'}{$school}{'TEMPLATES_LATEX_DIR'}=
                            $DevelConf::path_conf_sophomorix."/".$school."/".
                            $ref_sophomorix_config->{'INI'}{'LATEX'}{'TEMPLATES_CUSTOM_SUBDIR'};
                    }
                } else {
                    $ref_sophomorix_config->{$DevelConf::AD_global_ou}{$parameter}=
                        $ref_modmaster_sophomorix->{$section}{$parameter};
                }
            }
        } else {
            ##### unnown section ########################################################################
            &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,"Section ".$section.": unknown, not processed");
            return;
            #print "ERROR: Section $section: unknown, not processed\n\n";
            #exit;
        }
    }
}

# working with the JSON result hash
######################################################################
sub result_sophomorix_init {
    my ($scriptname)=@_;
    my %sophomorix_result=();
    $sophomorix_result{'SCRIPTNAME'}=$scriptname;
    $sophomorix_result{'JSONINFO'}="RESULT";
    $sophomorix_result{'JSONCOMMENT'}="---";
    return %sophomorix_result; 
}



sub result_sophomorix_add {
    # $type: ERROR|WARNUNG
    # $num: -1, no number, else look in ERROR|WARNING db
    # $ref_parameter: list of parameters to be fitted in db string
    # $message: used if errnumber is not found in db
    my ($ref_result,$type,$num,$ref_parameter,$message)=@_;

#    print "LIST of parameters:\n";
#    foreach my $para ( @{ $ref_parameter}  ){ 
#        print "$para\n";
#    } 

    if ($type eq "ERROR" or $type eq "WARNING" ){
        # get error from db, update $message_de, $message_en
        push @{ $ref_result->{'OUTPUT'} }, 
            {TYPE       => $type, 
             NUMBER     => $num,
             MESSAGE_EN => $message,
             MESSAGE_DE => $message,
            };
    } else {
        push @{ $ref_result->{'OUTPUT'} }, 
            {TYPE           => "UNKNOWN", 
             INTERNAL_ERROR => "unknown type ".$type."in  result_sophomorix_add",
            };
        print "Unknown result type $type";
    }
}



sub result_sophomorix_add_log {
    # $type: ERROR|WARNUNG
    # $num: -1, no number, else look in ERROR|WARNING db
    # $ref_parameter: list of parameters to be fitted in db string
    # $message: used if errnumber is not found in db
    my ($ref_result,$log_message)=@_;
    push @{ $ref_result->{'OUTPUT'} }, 
        {TYPE       => "LOG", 
         LOG => $log_message,
        };
}


sub result_sophomorix_add_summary {
 my ($arg_ref) = @_;
    my $ref_result = $arg_ref->{sophomorix_result};
    my $name = $arg_ref->{NAME};
    my $title = $arg_ref->{TITLE};
    my $result = $arg_ref->{RESULT};
    my $result_type = $arg_ref->{RESULT_TYPE};
    my $description_pre  = $arg_ref->{DESCRIPTION_PRE};
    my $description_post = $arg_ref->{DESCRIPTION_POST};
    my $format_type = $arg_ref->{FORMAT_TYPE};
    my $file = $arg_ref->{FILE};
    my $encoding = $arg_ref->{ENCODING};

    if ($name eq "HEADER"){
        my %header = (TITLE => $title);
        push @{ $ref_result->{'SUMMARY'} }, {$name => \%header};
    } else {
        my %hash=();
        if (defined $result){
            $hash{'RESULT'}=$result;
        }
        if (defined $result_type){
            $hash{'RESULT_TYPE'}=$result_type;
        }
        if (defined $description_pre){
            $hash{'DESCRIPTION_PRE'}=$description_pre;
        }
        if (defined $description_post){
            $hash{'DESCRIPTION_POST'}=$description_post;
        }
        if (defined $format_type){
            $hash{'FORMAT_TYPE'}=$format_type;
        }
        if (defined $file){
            $hash{'FILE'}=$file;
        }
        if (defined $encoding){
            $hash{'ENCODING'}=$encoding;
        }
        push @{ $ref_result->{'SUMMARY'} }, {$name => \%hash};
    }
}



sub result_sophomorix_check_exit {
    my ($ref_result,$ref_sophomorix_config,$json)=@_;
    my $log=0;
    my $warn=0;
    my $err=0;
    # count results
    foreach my $line ( @{ $ref_result->{'OUTPUT'}}  ){
	print "$line\n";
        if ($line->{'TYPE'} eq "ERROR"){
            $err++;
        } elsif ($line->{'TYPE'} eq "WARNING"){
            $warn++;
        } elsif ($line->{'TYPE'} eq "LOG"){
            $log++;
        } else {

        }
    } 
    # check if i need to exit
    if ($err>0 or $warn>0){
        $ref_result->{'JSONCOMMENT'}="Configuration check failed";
        &result_sophomorix_print($ref_result,$ref_sophomorix_config,$json);
        exit;
    } else {
        &print_title("$err ERRORS, $warn WARNINGS -> let's go");
    }
}



sub result_sophomorix_print {
    my ($ref_result,$ref_sophomorix_config,$json)=@_;
      if ($json==0){
          # be quiet
          print "Calling console printout\n";
          # print OUTPUT
          foreach my $line ( @{ $ref_result->{'OUTPUT'}}  ){
              if ($line->{'TYPE'} eq "LOG"){
	          printf "%-7s%3s: %-65s \n",$line->{'TYPE'},"",$line->{'LOG'};
              } else {
	          printf "%-7s%3s: %-65s \n",$line->{'TYPE'},$line->{'NUMBER'},$line->{'MESSAGE_EN'};
              }
          } 
          # print RESULT
          foreach my $line ( @{ $ref_result->{'SUMMARY'}}  ){
              foreach my $name ( keys %{ $line } ) {
		  #print "Name: $name\n";
                  if ($name eq "HEADER"){
                      print "##### ".$line->{$name}{'TITLE'}."\n";
                  } elsif ($line->{$name}{'FORMAT_TYPE'}==0){ # just print RESULT
                      #print "Format 0\n";
                      print "RESULT    : ".$line->{$name}{'RESULT'}."\n";
                  } elsif ($line->{$name}{'FORMAT_TYPE'}==1){
                      #print "Format 1\n";
                      printf "%6s %-65s \n",$line->{$name}{'RESULT'},$line->{$name}{'DESCRIPTION_POST'};
                  } elsif ($line->{$name}{'FORMAT_TYPE'}==2){
                      #print "Format 2\n";
                      print $line->{$name}{'DESCRIPTION_PRE'}.": ".$line->{$name}{'RESULT'}."\n";
	          } else {
                      print "Format unknown\n";
                  }
              }
          }
      } elsif ($json==1){
          # pretty output
          my $json_obj = JSON->new->allow_nonref;
          my $utf8_pretty_printed = $json_obj->pretty->encode( $ref_result );
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "$utf8_pretty_printed";
      } elsif ($json==2){
          # compact output
          my $json_obj = JSON->new->allow_nonref;
          my $utf8_json_line   = $json_obj->encode( $ref_result  );
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "$utf8_json_line";
      } elsif ($json==3){
          &print_title("DUMP: ".$ref_result->{'JSONCOMMENT'});
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} Dumper( $ref_result );
      }
}



# other
######################################################################

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



sub dir_listing_user {
    # directory listing for supervisor of session only
    my ($sam,$smb_dir,$smb_admin_pass,$ref_sessions,$ref_sophomorix_config)=@_;
    print "      * fetching filelist of user $sam  ($smb_dir)\n";
    my $smb = new Filesys::SmbClient(username  => $DevelConf::sophomorix_file_admin,
                                     password  => $smb_admin_pass,
                                     debug     => 0);
    # empty for a start
    $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}=();
    $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'}=();
    my $fd = $smb->opendir($smb_dir);
    while (my $file = $smb->readdir_struct($fd)) {
        if ($file->[1] eq "."){next};
        if ($file->[1] eq ".."){next};
        if ($file->[0] == 7) {
        #print "Directory ",$file->[1],"\n";
        $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}{$file->[1]}{'TYPE'}="d";
        push @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }, $file->[1]; 
    } elsif ($file->[0] == 8) {
        #print "File ",$file->[1],"\n";
        $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}{$file->[1]}{'TYPE'}="f";
        push @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }, $file->[1]; 
    } else {

    }
  }
  # sort
  if ($#{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }>0 ){
      @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} } = 
        sort @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} };
  }
  #close($fd); # ?????????????? gives error
}



sub quota_listing_session_participant {
    # quota listng for participant only
    my ($participant,$session,$supervisor,$ref_sessions)=@_;
    print "      * fetching quota of participant $participant  --> todo\n";

    # session ids
    $ref_sessions->{'id'}{$session}{'PARTICIPANTS'}{$participant}{'quota'}{'/dev/sda1'}{'COMMENT'}="Home";
    $ref_sessions->{'id'}{$session}{'PARTICIPANTS'}{$participant}{'quota'}{'/dev/sda1'}{'hardlimit'}="xxx MB";


    # supervisors
    $ref_sessions->{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$session}{'PARTICIPANTS'}
                   {$participant}{'quota'}{'/dev/sda1'}{'hardlimit'}="xxx MB";
    $ref_sessions->{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$session}{'PARTICIPANTS'}
                   {$participant}{'quota'}{'/dev/sda1'}{'comment'}="Home";
}



# sophomorix logging to command.log
######################################################################
sub log_script_start {
    my $stolen=0;
#    my @arguments = @_;
    my ($ref_arguments,$ref_result) = @_;
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $skiplock=0;
    # scripts that are locking the system
    my $log="${timestamp}::start::  $0";
    my $log_locked="${timestamp}::locked:: $0";
    my $count=0;
#    foreach my $arg (@arguments){
    foreach my $arg ( @{ $ref_arguments}  ){ 
        $count++;
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        if ($arg eq "--skiplock"){
            $skiplock=1;
        }

        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $ { $ref_arguments }[$count]="xxxxxx";
            # $arguments[$count]="xxxxxx";
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
#            $stolen=&lock_sophomorix("steal",$locking_pid,@arguments);
            $stolen=&lock_sophomorix("steal",$locking_pid,$ref_arguments);
            last;
        } else {
	    print "Process with PID $locking_pid is still running\n";
        }

        if ($try_count==$max_try_count){
            &print_title("try again later ...");
            exit;
        } else {
            sleep 1;
        }
    }
    
    if (exists ${DevelConf::lock_scripts}{$0} 
           and $stolen==0
           and $skiplock==0){
#	&lock_sophomorix("lock",0,@arguments);
	&lock_sophomorix("lock",0,$ref_arguments);
    }
    &print_title("$0 started ...");
    #&nscd_stop();
}



sub log_script_end {
    my ($ref_arguments,$ref_result,$ref_sophomorix_config,$json) = @_;
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $log="${timestamp}::end  ::  $0";
    my $count=0;
   foreach my $arg ( @{ $ref_arguments}  ){    
        $count++;
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $ { $ref_arguments }[$count]="xxxxxx";
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
    &result_sophomorix_add_log($ref_result,"$0 terminated regularly");
    # output the result object
    &result_sophomorix_print($ref_result,$ref_sophomorix_config,$json);
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

#    my @arguments = @_;
#    my ($ref_arguments,$ref_result,$json,$ref_parameter) = @_;
    # 5) arguments of calling script
    my $ref_arguments=shift;
    # 6) reference to result hsh
    my $ref_result=shift;
    # 7) $json option
    my $json=shift;
    # 8) replacement parameter list for error scripts
    my $ref_parameter=shift;
    # 9) config
    my $ref_sophomorix_config=shift;

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
    foreach my $arg ( @{ $ref_arguments}  ){  
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $ { $ref_arguments }[$count]="xxxxxx";
        }
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
    # put message in json object
    &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$message);

    # output the result object
    &result_sophomorix_print($ref_result,$ref_sophomorix_config,$json);
    exit $return;
}



sub log_user_add {
    my ($arg_ref) = @_;
    my $sam = $arg_ref->{sAMAccountName};
    my $role = $arg_ref->{sophomorixRole};
    my $school = $arg_ref->{sophomorixSchoolname};
    my $time_stamp_AD = $arg_ref->{time_stamp_AD};
    my $lastname = $arg_ref->{lastname};
    my $firstname = $arg_ref->{firstname};
    my $adminclass = $arg_ref->{adminclass};
    my $unid = $arg_ref->{unid};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $log_line="ADD::".$sam."::".$lastname."::".$firstname."::".$adminclass."::".
                 $role."::".$school."::".$time_stamp_AD."::".
                 $ref_sophomorix_config->{'UNIX'}{'EPOCH'}.
                 "::".$unid."::\n";

    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_ADD'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}



sub log_user_update {
    my ($arg_ref) = @_;
    my $sam = $arg_ref->{sAMAccountName};
    my $unid = $arg_ref->{unid};
    my $time_stamp_AD = $arg_ref->{time_stamp_AD};
    my $update_log_string = $arg_ref->{update_log_string};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    $update_log_string=~s/,$//g;# remove trailing ,

    my $log_line="UPDATE::".$sam."::".$unid."::".$time_stamp_AD."::".
                 $ref_sophomorix_config->{'UNIX'}{'EPOCH'}.
                 "::".$update_log_string."::\n";

    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_UPDATE'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}



sub log_user_kill {
    my ($arg_ref) = @_;
    my $sam = $arg_ref->{sAMAccountName};
    my $role = $arg_ref->{sophomorixRole};
    my $school = $arg_ref->{sophomorixSchoolname};
    my $time_stamp_AD = $arg_ref->{time_stamp_AD};
    my $lastname = $arg_ref->{lastname};
    my $firstname = $arg_ref->{firstname};
    my $adminclass = $arg_ref->{adminclass};
    my $unid = $arg_ref->{unid};
    my $home_delete_string = $arg_ref->{home_delete_string};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $log_line="KILL::".$sam."::".$lastname."::".$firstname."::".$adminclass."::".
                 $role."::".$school."::".$time_stamp_AD."::".
                 $ref_sophomorix_config->{'UNIX'}{'EPOCH'}.
                 "::HOME_DELETED=".$home_delete_string."::".$unid."::\n";

    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_KILL'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}



sub get_login_avoid {
    # avoid logins of recently killed users
    my ($ref_sophomorix_config)=@_;
    my %login_avoid=();
    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	        $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_KILL'};
    my $reuse_limit=86400*$ref_sophomorix_config->{'INI'}{'LOGIN_REUSE'}{'REUSE_LIMIT_DAYS'};
    if (not -f $logfile){
        # nothing foun
        return \%login_avoid;
    }
    open (KILL,"<$logfile");
    while(<KILL>){
        #print $_;
        chomp();
        my ($type,$login,$last,$first,$class,$role,$school,$time_AD,$epoch,$homedel,$unid)=split(/::/);
        my $unused_sec=$ref_sophomorix_config->{'UNIX'}{'EPOCH'}-$epoch;
        #print "$login unused for $unused_sec seconds (Min. limit for re-use is $reuse_limit)\n";
        if ($unused_sec<$reuse_limit){
            $login_avoid{'AVOID_LOGINS'}{$login}{'UNUSED'}=$unused_sec;
        }
    }
    close(KILL);
    return \%login_avoid;
}



sub create_test_login {
    # $ref_AD_check --> $ref_forbidden_logins
    my ($identifier_ascii,
        $file,
        $login_wish,
        $ref_forbidden_logins,
        $ref_login_avoid,
        $line_num,
        $ref_users_file,
        $ref_sophomorix_config)=@_;
    my ($surname_login,$firstname_login,$birthdate)=split(";", $identifier_ascii);
    my $login_check_ok; # the approved login name

    $surname_login=~s/-//g;  # remove minus
    $surname_login=~s/\.//g; # remove dots
    $surname_login=~s/ //g;  # remove whitespace
    $surname_login=~tr/A-Z/a-z/; # only small letters
    $surname_login=~s/[^a-zA-Z0-9]//; # ignore non a-z

    $firstname_login=~s/-//g; # remove minus
    $firstname_login=~s/\.//g; # remove dots
    $firstname_login=~s/ //g;  # remove whitespace
    $firstname_login=~tr/A-Z/a-z/; # only small letters
    $firstname_login=~s/[^a-zA-Z0-9]//; # ignore non a-z

    my $login_name_to_check;
    if ($login_wish eq "---"){
        ############################################################
        # login creation
        if ($ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'FIRSTNAME_CHARS'}==0 and 
            $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_CHARS'}==0){
            print "\n   WARNING: File $file is not configured for auto login creation\n\n";
            return "---";
        }
        # firstname+surname or surname+firstname
        if ( $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_FIRSTNAME_REVERSE'} eq "yes"){
            $login_part_2=substr($surname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_CHARS'});
            $login_part_1=substr($firstname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'FIRSTNAME_CHARS'});
        } else {
            $login_part_1=substr($surname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_CHARS'});
            $login_part_2=substr($firstname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'FIRSTNAME_CHARS'});
        }

        ############################################################
        # test proposed login
        $login_name_to_check="$login_part_1"."$login_part_2";
        if (not exists $ref_forbidden_logins->{'FORBIDDEN'}{$login_name_to_check} and
            not exists $ref_login_avoid->{'AVOID_LOGINS'}{$login_name_to_check} ){
            # not forbidden an not to be avoided -> use it!
            $login_check_ok=$login_name_to_check;
        } else {
            # if login is not OK: add 1,2,3,... until OK
            my $login_name_to_check_mod=$login_name_to_check;
            my $i=1; # start for appending numbers
            while (exists $ref_forbidden_logins->{'FORBIDDEN'}{$login_name_to_check_mod} or
                   exists $ref_login_avoid->{'AVOID_LOGINS'}{$login_name_to_check_mod} ){
                # Append number
                $login_name_to_check_mod="$login_name_to_check"."$i";
                $i=$i+1;
            }
            # Nun kann modifizierter Loginname benutzt werden
            $login_check_ok=$login_name_to_check_mod;
        } 
    } else {
        ############################################################
        # check wish login
        $login_char_length = length $login_wish;
        if (not $login_wish=~m/^[a-z0-9-_]+$/){
            # put in result hash ?????
            print "\n";
	    print "   ERROR: $login_wish contains invalid characters for a login name!\n"; 
	    print "    LINE: $ref_users_file->{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}\n";
	    print "          ($file LINE $line_num)\n";
            print "          Allowed characters are: a-z0-9-_\n\n";
            exit;
        } elsif ($login_char_length<2){
            print "\n";
	    print "   ERROR: $login_wish ist to short for a login name!\n";
	    print "    LINE: $ref_users_file->{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}\n";
	    print "          ($file LINE $line_num)\n";
            print "          Minimum characters for login names are 2\n\n";
            exit;
        } elsif (not $login_wish=~m/^[a-z]+/){
            print "\n";
	    print "   ERROR: $login_wish does not begin with a-z\n";
	    print "    LINE: $ref_users_file->{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}\n";
	    print "          ($file LINE $line_num)\n";
            print "          Login names must begin with a-z\n\n";
            exit;
        } elsif (exists $ref_forbidden_logins->{'FORBIDDEN'}{$login_wish}){
            # forbidden login
            # put in result hash ?????
	    print "\n"; 
	    print "   ERROR: $login_wish FOR $identifier_ascii FORBIDDEN ($file)\n"; 
	    print "    LINE: $ref_users_file->{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}\n";
	    print "          ($file LINE $line_num)\n";
	    print "          REASON: $ref_forbidden_logins->{'FORBIDDEN'}{$login_wish}\n"; 
            exit;
        } elsif (exists $ref_login_avoid->{'AVOID_LOGINS'}{$login_wish}){
            # non reusable login
            my $days=int($ref_login_avoid->{'AVOID_LOGINS'}{$login_wish}{'UNUSED'}/86400);
            # put in result hash ?????
	    print "\n   WARNING: $login_wish was used $days days ago (Not recommended to re-use $login_wish already)\n\n"; 
	    print "        LINE: $ref_users_file->{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}\n";
	    print "              ($file LINE $line_num)\n";
        }
        $login_check_ok=$login_wish;
    }

    # the found loginname is added to the forbidden logins from now on
    $ref_forbidden_logins->{'FORBIDDEN'}{$login_check_ok}="new";
    return $login_check_ok;
}



# backup stuff before modifying
######################################################################
# option 2: add, move, kill, update
# option 3 before, after
# optopn 4: cp should be correct
#  what is this mv for: &backup_auk_file($zeit,"add","after","mv");
sub backup_auk_file {
    my ($time, $str, $str2,$ref_sophomorix_config) = @_;
    my $input=$ref_sophomorix_config->{'INI'}{'PATHS'}{'CHECK_RESULT'}."/sophomorix.".$str;
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
    my $user = $arg_ref->{user};
    my $group = $arg_ref->{group};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $ntacl_abs=$DevelConf::path_conf_devel_ntacl."/".$ntacl.".template";
    if ($ntacl eq "noacl" or $ntacl eq "nontacl"){
        print "   Skipping ACL/NTACL creation for $smbpath\n";
        return;
    } elsif (not -r $ntacl_abs){ # -r: readable
        print "\nERROR: $ntacl_abs not found/readable\n\n";
        exit;
    } 
    print "\n";
    &Sophomorix::SophomorixBase::print_title("Set NTACL ($smbpath from $ntacl), user=$user,group=$group,school=$school (start)");
    #print "Setting the NTACL for $smbpath from $ntacl (user=$user, group=$group, school=$school):\n";
    my $smbcacls_option="";
    open(NTACL,"<$ntacl_abs");
    my $line_count=0;
    while (<NTACL>) {
        $_=~s/\s+$//g;# remove trailing whitespace
        if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
            next;
        }
        if (/^CONTROL:/){
            # do something special for CONTROL line
            print "*** skipping $_\n";
            next;
        }
        
        my $line=$_;
        $line_count++;
        chomp($line);
        # replacements in line go here
        $line=~s/\@\@WORKGROUP\@\@/$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}/;

        if ($user ne ""){
            $line=~s/\@\@USER\@\@/$user/;
        }
        if ($group ne ""){
            $line=~s/\@\@GROUP\@\@/$group/;
        }
        if ($school ne ""){
            my $prefix=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'PREFIX'};
            $line=~s/\@\@SCHOOLNAME\@\@/$school/;
            $line=~s/\@\@SCHOOLPREFIX\@\@/$prefix/;
        }

        # create multiple lines? from one line
        if ($line_count==1){
            $smbcacls_option=$line;
        } else {
            $smbcacls_option=$smbcacls_option.",".$line;
        }
    }
    $smbcacls_option="\"".$smbcacls_option."\"";
    my $smbcacls_base_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCACLS'}.
                              " -U ".$DevelConf::sophomorix_file_admin."%'".
                              $smb_admin_pass."' //$root_dns/$school $smbpath --set ";
    my $smbcacls_command=$smbcacls_base_command.$smbcacls_option;
    print "* $smbcacls_base_command\n";
    print "  $smbcacls_option\n";
    my $smbcacls_return=system("$smbcacls_command");
    if($smbcacls_return==0){
 	print "NTACLS set successfully ($smbcacls_return)\n";
    } else {
        &result_sophomorix_add($ref_sophomorix_result,"ERROR",-1,$ref_parameter,"FAILED ($smbcacls_return): $smbcacls_command");
	print "ERROR setting NTACLS ($smbcacls_return)\n";
    }
    close(NTACL);
    &Sophomorix::SophomorixBase::print_title("Set NTACL ($smbpath from $ntacl), user=$user,group=$group,school=$school (end)");
    print "\n";
}



# ?????? deprecated ???
sub old_ACL_set_file_obsolete {
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

    if($Conf::log_level>=2){
        print "\nPatched ACL:\n\n";
        system("cat $tmp");
        print "\n";
    }

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
        if ( $random eq "yes") {
	    $password=&create_plain_password($length,@password_chars);
        } else {
            $password=$DevelConf::student_password_default;
	}
    } elsif ($role eq "student") {
        # Student
        if ($random  eq "yes") {
	    $password=&create_plain_password($length,@password_chars);
        } else {
            $password=$DevelConf::teacher_password_default;
        }
    }
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
    my ($root_dns,$school,$group_basename,$user,$role,$ref_sophomorix_config)=@_;
    my $homedirectory;  # as needed to fill the attribute 'homeDirectory (using \\)
    my $unix_home;      # (works only if share is on the same server)
    my $smb_rel_path;   # option for smbclient
    
    my $school_smbshare;
    if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        $school_smbshare=$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
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
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_ROLE'}){
        # examuser
        if ($group_basename eq ""){
            # no subdir
            $smb_rel_path=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$user;
            $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."\\".$user;
            $unix_home=$DevelConf::homedir_all_schools."/".$school."/".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$user;
        } else {
            # with subdir
            $smb_rel_path=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$group_basename."/".$user;
            $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."\\".$group_basename."\\".$user;
            $unix_home=$DevelConf::homedir_all_schools."/".$school."/".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$group_basename."/".$user;
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$root_dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
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
    my ($root_dns,$school,$group,$type,$ref_sophomorix_config)=@_;
    my $smb_share; # as needed for perl module 'homeDirectory (using //)
    my $unix_dir; # unix-path (works only if share is on the same server)
    my $smb_rel_path; # option for smbclient

    my $school_smbshare=$school;
    if ($school eq "---"){
        $school=$DevelConf::name_default_school;
        $school_smbshare=$DevelConf::name_default_school;
    } elsif ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        $school_smbshare=$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
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


######################################################################
# END OF FILE
# Return true=1
1;
