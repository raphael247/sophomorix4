#!/usr/bin/perl -w
# This perl module SophomorixSambaAD is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linuxmuster.net

package Sophomorix::SophomorixSambaAD;
require Exporter;
#use File::Basename;
use Unicode::Map8;
use Unicode::String qw(utf16);
use Net::LDAP;
use Net::LDAP::Control::Sort;
use List::MoreUtils qw(uniq);
use File::Basename;
use Math::Round;
use Data::Dumper;

# for smb://
use POSIX;
use Filesys::SmbClient;

$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 

@ISA = qw(Exporter);

@EXPORT_OK = qw( );
@EXPORT = qw(
            AD_get_passwd
            AD_get_unicodepwd
            AD_set_unicodepwd
            AD_bind_admin
            AD_unbind_admin
            AD_get_sessions
            AD_session_manage
            AD_user_set_exam_mode
            AD_user_unset_exam_mode
            AD_user_create
            AD_user_update
            AD_user_setquota
            AD_get_user
            AD_get_group
            AD_computer_create
            AD_computer_kill
            AD_computer_update
            AD_user_move
            AD_user_kill
            AD_remove_sam_from_sophomorix_attributes
            AD_group_create
            AD_group_kill
            AD_group_addmember
            AD_group_addmember_management
            AD_group_removemember
            AD_group_update
            AD_group_list
            AD_get_schoolname
            AD_get_name_tokened
            AD_ou_create
            AD_school_create
            AD_object_search
            AD_get_AD
            AD_get_AD_for_check
            AD_get_AD_for_device
            AD_get_ui
            AD_get_quota
            AD_get_users_v
            AD_get_groups_v
            AD_get_shares_v
            AD_get_full_userdata
            AD_get_full_devicedata
            AD_get_full_groupdata
            AD_get_printdata
            AD_get_schema
            AD_class_fetch
            AD_project_fetch
            AD_group_fetch
            AD_dn_fetch_multivalue
            AD_project_sync_members
            AD_object_move
            AD_debug_logdump
            AD_login_test
            AD_dns_get
            AD_dns_create
            AD_dns_zonecreate
            AD_dns_kill
            AD_dns_zonekill
            AD_repdir_using_file
            AD_examuser_create
            AD_examuser_kill
            AD_smbclient_testfile
            next_free_uidnumber_set
            next_free_uidnumber_get
            next_free_gidnumber_set
            next_free_gidnumber_get
            );


sub AD_get_unicodepwd {
    my ($sam,$ref_sophomorix_config) = @_;
    my $string=`ldbsearch --url $ref_sophomorix_config->{'INI'}{'PATHS'}{'SAM_LDB'} "sAMAccountName=$sam" unicodePwd`;
    my @lines=split("\n",$string);
    my $unicodepwd;
    foreach my $line (@lines){
        if ($line=~m/unicodePwd/){
            my ($attr,$pass)=split("::",$line);
            $unicodepwd=&Sophomorix::SophomorixBase::remove_whitespace($pass);
            last; # dont look further
        }
    }
    return $unicodepwd;
}



sub AD_set_unicodepwd {
    my ($user,$unicodepwd,$ref_sophomorix_config) = @_;

    # ???
    my ($ldap,$root_dse) = &AD_bind_admin(\@arguments,\%sophomorix_result,$json);

    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$user);
    system("mkdir -p $ref_sophomorix_config->{'INI'}{'PATHS'}{'TMP_PWDUPDATE'}");
    my $ldif=$ref_sophomorix_config->{'INI'}{'PATHS'}{'TMP_PWDUPDATE'}."/".$user.".ldif";
    open(LDIF,">$ldif")|| die "ERROR: $!";
    print LDIF "dn: $dn\n";
    print LDIF "changetype: modify\n";
    print LDIF "replace: unicodePwd\n";
    print LDIF "unicodePwd:: $unicodepwd\n";
    close(LDIF);
    # load ldif file
    my $com="ldbmodify -H /var/lib/samba/private/sam.ldb --controls=local_oid:1.3.6.1.4.1.7165.4.3.12:0 $ldif";
    my $res=system($com);
    if (not $res==0){
        print "ERROR: password update failed, $res returned\n";
    }
    system("rm $ldif");
    # ???
    &AD_unbind_admin($ldap);
}



sub AD_get_passwd {
    my ($user,$pwd_file)=@_;
    my $password="";
    if (-e $pwd_file) {
        open (SECRET, $pwd_file);
        while(<SECRET>){
            $password=$_;
            chomp($password);
        }
        close(SECRET);
    } else {
        print "Password of samba user $user must ",
               "be in $pwd_file\n";
        exit;
    }
    return($password);
}



sub AD_bind_admin {
    my ($ref_arguments,$ref_result,$json) = @_;
    if (not -e $DevelConf::secret_file_sophomorix_AD_admin){
        print "\nERROR: Connection to AD failed: No password found!\n\n";
        print "sophomorix connects to AD with the user $DevelConf::sophomorix_AD_admin:\n";
        print "  A) Make sure $DevelConf::sophomorix_AD_admin exists:\n";
        print "     samba-tool user create $DevelConf::sophomorix_AD_admin %<password>% \n";
        print "     (Replace <password> according to: samba-tool domain passwordsettings show)\n";
        print "  B) Store the Password of $DevelConf::sophomorix_AD_admin (without newline character) in:\n";
        print "     $DevelConf::secret_file_sophomorix_AD_admin\n";
        print "\n";
        exit;
    }

    my ($smb_pwd)=&AD_get_passwd($DevelConf::sophomorix_AD_admin,$DevelConf::secret_file_sophomorix_AD_admin);
    my $host="ldaps://localhost";
    # check connection to Samba4 AD
    if($Conf::log_level>=3){
        print "   Checking Samba4 AD connection ...\n";
    }

    #my $ldap = Net::LDAP->new('ldaps://localhost')  or  die "$@";
    my $ldap = Net::LDAP->new($host) or &Sophomorix::SophomorixBase::log_script_exit(
         "No connection to Samba4 AD!",1,1,0,$ref_arguments,$ref_result,$json);

    if($Conf::log_level>=2){
        print "Retrieving RootDSE...\n";
    }
    my $dse = $ldap->root_dse();
    # get naming Contexts
    my @contexts = $dse->get_value('namingContexts');

    ## get supported LDAP versions as an array reference
    #my $versions = $dse->get_value('supportedLDAPVersion', asref => 1);
    my $root_dse=$contexts[0];
    if($Conf::log_level>=3){
        foreach my $context (@contexts){
            print "      * NamingContext: <$context>\n";
        }
    }

    if($Conf::log_level>=2){
        print "   * RootDSE: $root_dse\n";
    }

    # admin bind
    my $sophomorix_AD_admin_dn="CN=".$DevelConf::sophomorix_AD_admin.",CN=Users,".$root_dse;
    if($Conf::log_level>=2){
        print "Binding with $sophomorix_AD_admin_dn\n";
    }
    my $mesg = $ldap->bind($sophomorix_AD_admin_dn, password => $smb_pwd);
    # show errors from bind
    my $return=&AD_debug_logdump($mesg,2,(caller(0))[3]);
    if ($return==0){
        print "Please verify the password file for $sophomorix_AD_admin_dn\n\n";
        exit;
    }

    # Testing if sophomorix schema is present
    # ldbsearch -H ldap://localhost -UAdministrator%<password> -b cn=Schema,cn=Configuration,DC=linuxmuster,DC=local cn=Sophomorix-User
    if($Conf::log_level>=2){
        print "Testing if the Sophomorix Schema exists (Sophomorix-User)...\n";
    }

    my $base="CN=Sophomorix-User,CN=Schema,CN=Configuration,".$root_dse;
    my $filter="(cn=Sophomorix-User)";
    my $mesg2 = $ldap->search(
                       base   => $base,
                       scope => 'base',
                       filter => $filter,
                            );
    my $res = $mesg2->count; 
    if ($res!=1){
            print "   * ERROR: Sophomorix-Schema nonexisting\n";
        exit;
    } elsif ($res==1){
        if($Conf::log_level>=2){
            print "   * Sophomorix-Schema exists\n";
        }
    }
    return ($ldap,$root_dse);
}



sub AD_unbind_admin {
    my ($ldap) = @_;
    my $mesg = $ldap->unbind();
    #  show errors from unbind
    $mesg->code && die $mesg->error;
}



sub AD_dns_get {
    # get dns domain from RootDSE
    my ($root_dse) = @_;
    my @dns_part_stripped=(); # without 'DC='
    my @dns_part=split(/,/,$root_dse);
    foreach my $part (@dns_part){
        $part=~s/DC=//g;
        push @dns_part_stripped, $part;
    }
    my $dns_name = join(".",@dns_part_stripped);
    if($Conf::log_level>=2){
        my $caller=(caller(0))[3];
        print "$caller RootDSE: $root_dse -> DNS: $dns_name\n";
    }
    return $dns_name;
}



sub AD_dns_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smb_pwd = $arg_ref->{smb_pwd};
    my $dns_server = $arg_ref->{dns_server};
    #my $dns_zone = $arg_ref->{dns_zone};
    my $dns_node = $arg_ref->{dns_node};
    my $dns_ipv4 = $arg_ref->{dns_ipv4};
    my $dns_type = $arg_ref->{dns_type};
    my $dns_cn = $arg_ref->{dns_cn};
    my $filename = $arg_ref->{filename};
    my $school = $arg_ref->{school};
    my $role = $arg_ref->{role};
    my $comment = $arg_ref->{comment};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # calc dnsNode, reverse lookup
    my @octets=split(/\./,$dns_ipv4);
    my $dns_zone=$octets[2].".".$octets[1].".".$octets[0].".in-addr.arpa";
    my $dns_last_octet=$octets[3];
    my $dns_admin_description=$DevelConf::dns_node_prefix_string." from ".$filename;

    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title(
              "Creating dnsNode: $dns_node");
    } 

    # set defaults if not defined
    if (not defined $filename){
        $filename="---";
    }
    if (not defined $comment or $comment eq ""){
        $comment="---";
    }
    if (not defined $dns_cn){
        $dns_cn=$dns_node;
    }
    if (not defined $dns_server){
        $dns_server="localhost";
    }
    if (not defined $dns_type){
        $dns_type="A";
    }
    
    ############################################################
    # adding dnsNode with samba-tool
    my $command="samba-tool dns add $dns_server $root_dns $dns_node $dns_type $dns_ipv4".
                " --password='$smb_pwd' -U $DevelConf::sophomorix_AD_admin";
    print "   * $command\n";
    # system($command);
    my $res=`$command`;
    print "       -> $res";

    ############################################################
    # adding comments to recognize the dnsNode as created by sophomorix
    my ($count,$dn_exist_dnshost,$cn_exist_dnshost)=&AD_object_search($ldap,$root_dse,"dnsNode",$dns_node);
    print "   * Adding Comments to dnsNode $dns_node\n";
    if ($count > 0){
             print "   * dnsNode $dns_node exists ($count results)\n";
             my $mesg = $ldap->modify( $dn_exist_dnshost, add => {
                                       adminDescription => $dns_admin_description,
                                       cn => $dns_cn,
                                       sophomorixRole => $role,
                                       sophomorixAdminFile => $filename,
                                       sophomorixSchoolname => $school,
                                       sophomorixComputerIP => $dns_ipv4,
                                       sophomorixDnsNodename => $dns_node,
                                       sophomorixComment => $comment,
                                      });
             &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    ############################################################
    # adding reverse lookup with samba-tool
    my $command_reverse="samba-tool dns add $dns_server $dns_zone $dns_last_octet PTR $dns_node ".
                " --password='$smb_pwd' -U $DevelConf::sophomorix_AD_admin";
    print "   * $command_reverse\n";
    my $res2=`$command_reverse`;
    print "       -> $res2";

    ############################################################
    # adding comments to recognize the dnsNode reverse lookup as created by sophomorix
    my $dns_node_reverse="DC=".$dns_last_octet.",DC=".$dns_zone.",CN=MicrosoftDNS,DC=DomainDnsZones,".$root_dse;
    print "   * dnsNode $dns_node (reverse lookup $dns_node_reverse)\n";
    my $mesg = $ldap->modify( $dns_node_reverse, replace => {
                              adminDescription => $dns_admin_description,
                              cn => $dns_cn,
                              sophomorixRole => $role,
                              sophomorixAdminFile => $filename,
                              sophomorixSchoolname => $school,
                              sophomorixComputerIP => $dns_ipv4,
                              sophomorixDnsNodename => $dns_node,
                              sophomorixComment => $comment,
                    });
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    return;
}



sub AD_dns_zonecreate {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $smb_pwd = $arg_ref->{smb_pwd};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_zone = $arg_ref->{dns_zone};
    my $dns_admin_description = $arg_ref->{dns_admin_description};
    my $dns_cn = $arg_ref->{dns_cn};
    my $filename = $arg_ref->{filename};
    my $school = $arg_ref->{school};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title(
              "Creating dnsZone: $dns_zone");
    } 

    # set defaults if not defined
    if (not defined $filename){
        $filename="---";
    }
     if (not defined $dns_admin_description){
        $dns_admin_description=$DevelConf::dns_zone_prefix_string." from ".$filename;
    }
    if (not defined $dns_cn){
        $dns_cn=$dns_zone;
    }
    if (not defined $dns_server){
        $dns_server="localhost";
    }

    ############################################################
    # adding dnsNode with samba-tool
    my $command="samba-tool dns zonecreate $dns_server $dns_zone --password='$smb_pwd' -U $DevelConf::sophomorix_AD_admin";
    print "   * $command\n";
    #system($command);
    my $res=`$command`;
    print "       -> $res";

    ############################################################
    # adding comments to recognize the dnsZone as created by sophomorix
    my ($count,$dn_exist_dnszone,$cn_exist_dnszone)=&AD_object_search($ldap,$root_dse,"dnsZone",$dns_zone);
    print "   * Adding Comments to dnsZone $dns_zone\n";

    if ($count > 0){
             print "   * dnsZone $dns_zone exists ($count results)\n";
             my $mesg = $ldap->modify($dn_exist_dnszone, add => {
                                      adminDescription => $dns_admin_description,
                                      cn => $dns_cn,
                                      sophomorixRole => $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSZONE_ROLE'},
                                      sophomorixAdminFile => $filename,
                                      sophomorixSchoolname => $school,
                                     });
             &AD_debug_logdump($mesg,2,(caller(0))[3]);
             return;
         }
}



sub AD_dns_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smb_pwd = $arg_ref->{smb_pwd};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_zone = $arg_ref->{dns_zone};
    my $dns_node = $arg_ref->{dns_node};
    my $dns_ipv4 = $arg_ref->{dns_ipv4};
    my $dns_type = $arg_ref->{dns_type};

    if (not defined $dns_server){
        $dns_server="localhost";
    }
    if (not defined $dns_type){
        $dns_type="A";
    }

    # delete dnsNode
    if ($dns_ipv4 ne "NXDOMAIN" and $dns_ipv4 ne "NOERROR"){
        my $command="samba-tool dns delete $dns_server ".
                    "$dns_zone $dns_node $dns_type $dns_ipv4 ".
                    "--password='$smb_pwd' -U $DevelConf::sophomorix_AD_admin";
        print "   * $command\n";
        system($command);
    }

    # delete reverse lookup ?????? deleted with the zone?
    #$dns_type="PTR";
    #my $command="samba-tool dns delete $dns_server ".
    #            "$dns_zone $dns_node $dns_type $dns_ipv4 ".
    #            "--password='$smb_pwd' -U $DevelConf::sophomorix_AD_admin";
    #print "     * $command\n";
    #system($command);
}



sub AD_dns_zonekill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $smb_pwd = $arg_ref->{smb_pwd};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_zone = $arg_ref->{dns_zone};

    if (not defined $dns_server){
        $dns_server="localhost";
    }

    my $command="samba-tool dns zonedelete $dns_server $dns_zone --password='$smb_pwd' -U $DevelConf::sophomorix_AD_admin";
    print "   * $command\n";
    system($command);
}



sub AD_repdir_using_file {
    my ($arg_ref) = @_;
    # mandatory options
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $repdir_file = $arg_ref->{repdir_file};
    my $ref_AD = $arg_ref->{AD};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # optional options
    my $school = $arg_ref->{school};
    my $project = $arg_ref->{project};
    my $administrator_home = $arg_ref->{administrator_home};
    my $teacherclass = $arg_ref->{teacherclass};
    my $teacher_home = $arg_ref->{teacher_home};
    my $adminclass = $arg_ref->{adminclass};
    my $extraclass = $arg_ref->{extraclass};
    my $subdir = $arg_ref->{subdir};
    my $student_home = $arg_ref->{student_home};

    # abs path
    my $repdir_file_abs=$ref_sophomorix_config->{'REPDIR_FILES'}{$repdir_file};
    my $entry_num=0; # was $num
    my $line_num=0;
    &Sophomorix::SophomorixBase::print_title("Repairing from file: $repdir_file (start)");
    print "";
    # option school
    my @schools=("");
    if (defined $school){
        @schools=($school);
    }

    # reading repdir file
    open(REPDIRFILE, "<$repdir_file_abs")|| die "ERROR: $repdir_file_abs $!";
    while (<REPDIRFILE>) {
        my $line=$_;
        $line_num++;
        my $group_type="";
        my $groupvar_seen=0; # a group variable was in this line
        chomp($line);   
        if ($line eq ""){next;} # next on empty line
        if(/^\#/){next;} # next on comments
        $entry_num++;
        if (/\@\@SCHOOL\@\@/ and not defined $school) {
            @schools = @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };

        }

        if (/\@\@ADMINCLASS\@\@/) {
            $group_type="adminclass";
            $groupvar_seen++;
        }
        if (/\@\@EXTRACLASS\@\@/) {
            $group_type="extraclass";
            $groupvar_seen++;
        }
        if (/\@\@TEACHERCLASS\@\@/) {
            $group_type="teacherclass";
            $groupvar_seen++;
        }
        if (/\@\@PROJECT\@\@/) {
            $group_type="project";
            $groupvar_seen++;
        }
        if (/\@\@SUBDIR\@\@/) {
            #$group_type="project";
            #$groupvar_seen++;
            if (defined $subdir and $subdir eq ""){
                # replace SUBDIR and / with ""
                $line=~s/\/\@\@SUBDIR\@\@//;
            } else {
                # replace SUBDIR with $subdir
                $line=~s/\@\@SUBDIR\@\@/$subdir/;
            }
        }
        if (/\$directory_management/) {
            $group_type="admins";
            # go through one group loop for admins
        }

        my ($entry_type,$path_with_var, $owner, $groupowner, $permission,$ntacl,$ntaclonly) = split(/::/,$line);
        if (not defined $ntaclonly){
            $ntaclonly="";            
        }

        # replacing $vars in path
        my @old_dirs=split(/\//,$path_with_var);
        my @new_dirs=();
        foreach my $dir (@old_dirs){
            $dir=">".$dir."<"; # add the ><, so that no substrings will be replaced
            # /var
            $dir=~s/>\$path_log</${DevelConf::path_log}/;
            $dir=~s/>\$path_log_user</${DevelConf::path_log_user}/;
            # /srv/samba
            $dir=~s/>\$homedir_all_schools</${DevelConf::homedir_all_schools}/;
            $dir=~s/>\$homedir_global</${DevelConf::homedir_global}/;
            # other
            $dir=~s/>\$directory_students</${DevelConf::directory_students}/;
            $dir=~s/>\$directory_teachers</${DevelConf::directory_teachers}/;
            $dir=~s/>\$directory_projects</${DevelConf::directory_projects}/;
            $dir=~s/>\$directory_management</${DevelConf::directory_management}/;
            $dir=~s/>\$directory_examusers</${DevelConf::directory_examusers}/;
            $dir=~s/>\$directory_share</${DevelConf::directory_share}/;
            $dir=~s/>\$directory_program</${DevelConf::directory_program}/;
            # remove <,>
            $dir=~s/^>//g;
            $dir=~s/<$//g;
	    push @new_dirs,$dir;
        }
        $path_with_var=join("/",@new_dirs);

        print "------------------------------------------------------------\n";
        print "$entry_num) Line $line_num:  $line:\n";
        if($Conf::log_level>=3){
            print "   Type:       $entry_type\n";
            print "   Path:       $path_with_var\n";
            print "   Owner:      $owner\n";
            print "   Group:      $groupowner\n";
            print "   Group-Type: $group_type\n";
            print "   Perm:       $permission\n";
            print "   NTACL:     $ntacl\n";
            print "   Schools:    @schools\n";
        }

        ########################################
        # school loop start             
        foreach my $school (@schools){
            my $path=$path_with_var;
            my $path_smb=$path_with_var;
            if ($school eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
                if ($path_smb eq $DevelConf::homedir_global){
                    $path_smb="/";
                } else {
                    $path_smb=~s/$DevelConf::homedir_global//; # for school
                    $path_smb=~s/\@\@SCHOOL\@\@\///; # for homdirs
                }
            } else {
                $path=~s/\@\@SCHOOL\@\@/$school/;
                if ($path_smb eq "\@\@SCHOOL\@\@"){
                    $path_smb="/";
                } else {
                    $path_smb=~s/\@\@SCHOOL\@\@\///;
                }
            }
            if($Conf::log_level>=3){
                print "   Determining path for school $school:\n";
                print "      * Path after school: $path (smb: $path_smb)\n";
            }
            # determining groups to walk through
            my @groups;
            if (defined $project){
                @groups=($project);
            } elsif (defined $teacherclass){
                @groups=($teacherclass);
            } elsif (defined $adminclass){
                @groups=($adminclass);
            } elsif (defined $extraclass){
                @groups=($extraclass);
            } elsif(defined $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'groups_BY_sophomorixType'}{$group_type}){
                # there is a group list -> use it
                @groups=@{ $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'groups_BY_sophomorixType'}{$group_type} };
            } else {
                @groups=("");
            }
            ########################################
            # group loop start
            foreach my $group (@groups){
                if ($group eq "" and $groupvar_seen>0){
                    # skip, if a groupvar should be replaced, but there is only an empty string a group
                    print "Skipping $line:\n";
                    print "  -> group would be replaced by empty string\n";
                    next;
                }

                my $group_basename=$group;
                $group_basename=&Sophomorix::SophomorixBase::get_group_basename($group,$school);
                my $path_after_group=$path;
                $path_after_group=~s/\@\@ADMINCLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@EXTRACLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@TEACHERCLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@PROJECT\@\@/$group_basename/;
                my $path_after_group_smb=$path_smb;
                $path_after_group_smb=~s/\@\@ADMINCLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@EXTRACLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@TEACHERCLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@PROJECT\@\@/$group_basename/;
                if($Conf::log_level>=3){      
                    print "      * Path after group:  $path_after_group (smb: $path_after_group_smb)\n";
                }

                ########################################
                # user loop start
                my @users=("");
                if ($path_after_group=~/\@\@USER\@\@/) {
                    # determining list of users
                    if (defined $administrator_home){
                        @users=($administrator_home);
                    } elsif (defined $teacher_home){
                        @users=($teacher_home);
                    } elsif (defined $student_home){
                        @users=($student_home);
                    } elsif (defined $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'users_BY_group'}{$group}){
                        @users = @{ $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'users_BY_group'}{$group} };
                    } else {
                        print "\n";
                        print "##### No users in $group (school $school) #####\n";
                        # empty list means do nothing in next loop
                        @users=();
                    }
                }
                foreach my $user (@users){
                    my $path_after_user=$path_after_group;
                    $path_after_user=~s/\@\@USER\@\@/$user/;
                    my $path_after_user_smb=$path_after_group_smb;
                    $path_after_user_smb=~s/\@\@USER\@\@/$user/;

                    $path_after_user_smb=~s/\@\@COLLECT_DIR_HOME\@\@/$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'COLLECT_DIR_HOME_'.$ref_sophomorix_config->{'GLOBAL'}{'LANG'}}/;
                    $path_after_user_smb=~s/\@\@SHARE_DIR_HOME\@\@/$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'SHARE_DIR_HOME_'.$ref_sophomorix_config->{'GLOBAL'}{'LANG'}}/;
                    $path_after_user_smb=~s/\@\@TRANSFER_DIR_HOME\@\@/$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'TRANSFER_DIR_HOME_'.$ref_sophomorix_config->{'GLOBAL'}{'LANG'}}/;
                    if($Conf::log_level>=3){      
                        print "      * Path after user:   $path_after_user (smb: $path_after_user_smb)\n";
	            }
                    if ($entry_type eq "SMB"){
                        # smbclient
                        my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                                              " -U ".$DevelConf::sophomorix_file_admin."%'".
                                              $smb_admin_pass."'"." //$root_dns/$school -c 'mkdir $path_after_user_smb'";
                        my $user_typeout;
                        if ($user eq ""){
                            $user_typeout="<none>";
                        } else {
                            $user_typeout=$user;
                        }
                        if ($group eq ""){
                            $group_typeout="<none>";
                        } else {
                            $group_typeout=$group;
                        }
                        print "\nUser: $user_typeout in group $group_typeout in school $school\n";
                        print "---------------------------------------------------------------\n";
                        if ($ntaclonly ne "ntaclonly"){
                            print "* $smbclient_command\n";
                            system($smbclient_command);
		        } else {
                            print "* NOT executed (ntaclonly): $smbclient_command\n";
                        }

                        # smbcacls
                        &Sophomorix::SophomorixBase::NTACL_set_file({root_dns=>$root_dns,
                                                                     user=>$user,
                                                                     group=>$group,
                                                                     school=>$school,
                                                                     ntacl=>$ntacl,
                                                                     smbpath=>$path_after_user_smb,
                                                                     smb_admin_pass=>$smb_admin_pass,
                                                                     sophomorix_config=>$ref_sophomorix_config,
                                                                     sophomorix_result=>$ref_sophomorix_result,
                                                                   });
                   } elsif ($entry_type eq "LINUX"){
                        mkdir $path_after_user;
                        my $chown_command="chown ".$owner.".".$groupowner." ".$path_after_user;
                        print "          $chown_command\n";
                        system($chown_command);
                        chmod oct($permission), $path_after_user;
                    } else {
                        print "\nERROR: $entry_type unknown\n\n";
                        exit;
                    }
                } # user loop end 
            } # group loop end 
        } # school loop end
        print "--- DONE with $entry_num) Line $line_num:  $line ---\n";
    }
    close(REPDIRFILE);
    &Sophomorix::SophomorixBase::print_title("Repairing from file: $repdir_file (end)");
}



sub AD_user_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{login};
    my $identifier = $arg_ref->{identifier};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,$deactivation_date_AD,
        $school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
        &AD_get_user({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      user=>$user,
                    });
    $home_directory_AD=~s/\\/\//g;
    my $smb_home="smb:".$home_directory_AD;

    &Sophomorix::SophomorixBase::print_title("Killing User $user ($user_count):");
    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$user);
    &AD_remove_sam_from_sophomorix_attributes($ldap,$root_dse,"user",$user);

    if ($count > 0){
        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_PREFIX_EN'}.
                                         " $user".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_PREFIX_DE'}.
                                         " $user".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_POSTFIX_DE'};
            $json_progress{'STEP'}=$user_count;
            $json_progress{'FINAL_STEP'}=$max_user_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }

        # deleting user
	my $kill_return=-1;
        my $home_delete=-1;
        my $home_delete_string="";

        my $command="samba-tool user delete ". $user;
        print "   # $command\n";
        $kill_return=system($command);

        # deleting home
        if ($role_AD eq "student" or 
            $role_AD eq "teacher" or 
            $role_AD eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'} or
            $role_AD eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}
           ){
              my $smb = new Filesys::SmbClient(username  => $DevelConf::sophomorix_file_admin,
                                               password  => $smb_admin_pass,
                                               debug     => 0);
              #print "Deleting: $smb_home\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
              $home_delete=$smb->rmdir_recurse($smb_home);
              if($home_delete==1){
                  $home_delete_string="TRUE";
                  print "OK: Deleted with succes $smb_home\n";
              } else {
                  $home_delete_string="FALSE";
                  print "ERROR: rmdir_recurse $smb_home $!\n";
              }
        }

        if ($kill_return==0){
            # log the killing of a user 
            &Sophomorix::SophomorixBase::log_user_kill({sAMAccountName=>$user,
                                                        sophomorixRole=>$role_AD, 
                                                        home_delete_string=>$home_delete_string,
                                                        sophomorixSchoolname=>$school_AD,
                                                        firstname=>$firstname_utf8_AD,    
                                                        lastname=>$lastname_utf8_AD,
                                                        adminclass=>$adminclass_AD,
                                                        unid=>$unid_AD,
                                                        sophomorix_config=>$ref_sophomorix_config,
                                                        sophomorix_result=>$ref_sophomorix_result,
                                                      });
	}
        return;
    } else {
        print "   * User $user nonexisting ($count results)\n";
        return;
    }
}



sub AD_remove_sam_from_sophomorix_attributes {
    my ($ldap,$root_dse,$objectclass,$object)=@_;
    # removes a username/groupname from the listed sophomorix attributes
    # $objectclass: user,group (objectClass of the object that will be removed)
    # $object: sAMAccountName of the object that will be removed 
    &Sophomorix::SophomorixBase::print_title("Removing object $object from sophomorix attributes");
    my @attr_list=();
    if ($objectclass eq "user"){
        @attr_list=("sophomorixMembers","sophomorixAdmins");
    } elsif ($objectclass eq "group"){
        @attr_list=("sophomorixMemberGroups","sophomorixAdminGroups");
    } else {
        print "\nWARNING: Could not determine attribute list ( AD_remove_sam_from_sophomorix_attributes)\n\n";
        return;
    }
    foreach my $attr (@attr_list){
        my $filter="(&(objectClass=group)(".$attr."=".$object."))";
        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['sAMAccountName']
                                );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        my $max_attr = $mesg->count; 
        for( my $index = 0 ; $index < $max_attr ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            print "   * user $object is in $attr of $sam -> removing ...\n";
            #print "     $dn\n";
            my $mesg2 = $ldap->modify( $dn,
     	    	              delete => {
                              $attr => $object,
                              });
            &AD_debug_logdump($mesg2,2,(caller(0))[3]);
        }
    }
}



sub AD_computer_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $computer = $arg_ref->{computer};
    my $computer_count = $arg_ref->{computer_count};
    my $max_computer_count = $arg_ref->{max_computer_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    &Sophomorix::SophomorixBase::print_title("Killing computer $computer ($computer_count):");
    my $dn="";
    my $filter="(&(objectClass=computer)(sAMAccountName=".$computer."))";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName']
                         );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $count_result = $mesg->count;
    if ($count_result==1){
        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_PREFIX_EN'}.
                                         " $computer".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_PREFIX_DE'}.
                                         " $computer".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_POSTFIX_DE'};
            $json_progress{'STEP'}=$computer_count;
            $json_progress{'FINAL_STEP'}=$max_computer_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }
        my ($entry,@entries) = $mesg->entries;
        $dn = $entry->dn();
        print "   * DN: $dn\n";
        my $mesg = $ldap->delete( $dn );
    } else {
        print "   * WARNING: $computer not found/to many items ($count_result results)\n";     
    }
}



sub AD_computer_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $computer = $arg_ref->{computer};
    my $computer_count = $arg_ref->{computer_count};
    my $attrs_count = $arg_ref->{attrs_count};
    my $ref_replace = $arg_ref->{replace};
    my $max_computer_count = $arg_ref->{max_computer_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    print "\n";
    &Sophomorix::SophomorixBase::print_title(
          "Updating computer ${computer_count}/$max_computer_count: $computer ($attrs_count attributes) (start)");
    # get dn
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => "sAMAccountName=$computer",
                         );
    my $max = $mesg->count; 
    if ($max==1){
        my $entry = $mesg->entry(0);
        my $dn = $entry->dn();
        print "   DN: $dn\n";
        foreach my $attr (keys  %{ $ref_replace->{$computer}{'REPLACE'} }){
            print "     Update $attr to \"$ref_replace->{$computer}{'REPLACE'}{$attr}\"\n";
        }
        # modify
        my $mesg = $ldap->modify( $dn,
                          replace => { %{ $ref_replace->{$computer}{'REPLACE'} } } 
                         );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    } else {
        print "\nNot updating, $max results found for computer $computer\n\n";
        exit 88;
    }


#print Dumper($ref_replace);
    &Sophomorix::SophomorixBase::print_title(
          "Updating computer ${computer_count}/$max_computer_count: $computer (end)");
}



sub AD_group_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school_opt = $arg_ref->{school};
    my $group = $arg_ref->{group};
    my $type_opt = $arg_ref->{type};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $group_count = $arg_ref->{group_count};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my ($existing,
        $type,
        $school,
        $status,
        $description)=
        &AD_get_group({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      group=>$group,
                    });

    if (defined $school_opt){
        $school=$school_opt; # override school
    }
    if (defined $type_opt){
        $type=$type_opt; # override type
    }
    if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        $school_smbshare=$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
    } elsif ($school eq "---"){
        $school=$DevelConf::name_default_school;
    }

    my ($smb_share,$unix_dir,$unc,$smb_rel_path)=
        &Sophomorix::SophomorixBase::get_sharedirectory($root_dns,$school,$group,$type,$ref_sophomorix_config);

    &Sophomorix::SophomorixBase::print_title("Killing group $group ($type, $school):");
    &AD_remove_sam_from_sophomorix_attributes($ldap,$root_dse,"group",$group);

    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count > 0){
        if ($type eq "adminclass"){
            ### adminclass #####################################
            # deleting share if possible, when succesful  the account
            # do not delete ./homes if not empty !
            if ($smb_share ne  "unknown"){
                #my $smb = new Filesys::SmbClient(username  => $DevelConf::sophomorix_file_admin,
                #                                 password  => $smb_admin_pass,
                #                                 debug     => 3);
                ## trying to delete homes (success only if it is empty)
                my $smb_share_homes=$smb_share."/homes";
                #my $return1=$smb->rmdir($smb_share_homes);
                my $homes=$smb_rel_path."/homes";
                my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                                      " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'".
                                      $smb_admin_pass."' ".$unc." -c 'rmdir $homes;'";
                print "$smbclient_command\n";
                my $smbclient_return=system($smbclient_command);
                print "   --> smbclient returned $smbclient_return\n";

                my $smbclient_command_ls=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                                         " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'".
                                         $smb_admin_pass."' ".$unc." -c 'ls $homes;'";
                print "$smbclient_command_ls\n";
                my $return1=system($smbclient_command_ls);
                print "   --> smbclient returned $return1\n";

                if($return1==1 or $return1==256){
                    print "OK: Deleted empty dir with success $smb_share_homes\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                    # go on an recursively delete group/share and
                    #my $return2=$smb->rmdir_recurse($smb_share);


                    my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                                          " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'".
                                          $smb_admin_pass."' ".$unc." -c 'deltree $smb_rel_path;'";
                    print "$smbclient_command\n";
                    my $smbclient_return=system($smbclient_command);
                    print "   --> smbclient returned $smbclient_return\n";


                    my $smbclient_command_ls=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                                             " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'".
                                             $smb_admin_pass."' ".$unc." -c 'ls $smb_rel_path;'";
                    print "$smbclient_command_ls\n";
                    my $return2=system($smbclient_command_ls);
                    print "   --> smbclient returned $return2\n";

                    if($return2==1 or $return2==256){
                        print "OK: Deleted with succes $smb_share\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                        # deleting the AD account
                        my $command="samba-tool group delete ". $group;
                        print "   # $command\n";
                        system($command);
                    } else {
                        print "ERROR: deltree $unc $smb_rel_path $!\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                    }
                } else {
                    print "ERROR: rmdir $unc $homes $!\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                }

            }
	} elsif ($type eq "project"){
            # delete the share, when succesful the group
            if ($smb_share ne  "unknown"){
                my $smb = new Filesys::SmbClient(username  => $DevelConf::sophomorix_file_admin,
                                                 password  => $smb_admin_pass,
                                                 debug     => 0);
                # trying to delete homes (success only if it is empty)
                my $return1=$smb->rmdir_recurse($smb_share);
                if($return1==1){
                    print "OK: Deleted with succes $smb_share\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                    # deleting the AD account
                    my $command="samba-tool group delete ". $group;
                    print "   # $command\n";
                    system($command);
                } else {
                    print "ERROR: rmdir_recurse $smb_share $!\n";
                }
            }
	} elsif ($type eq "room"){
            ### rooms from sophomorix-device #####################################
            # there is no share, just delete the group
            my $command="samba-tool group delete ". $group;
            print "   # $command\n";
            system($command);
	} elsif ($type eq "sophomorix-group"){
            ### sophomorix-group #####################################
            # there is no share, just delete the group
            my $command="samba-tool group delete ". $group;
            print "   # $command\n";
            system($command);
	} elsif ($type eq "hardwareclass"){
            ### hardwareclass #####################################
            # just delete the group
            my $command="samba-tool group delete ". $group;
            print "   # $command\n";
            system($command);
	} elsif (exists $ref_sophomorix_config->{'LOOKUP'}{'HOST_GROUP_TYPE'}{$type}){
            # just delete the host group
            my $command="samba-tool group delete ". $group;
            print "   # $command   ($ref_sophomorix_config->{'LOOKUP'}{'HOST_GROUP_TYPE'}{$type})\n";
            system($command);
        } else {
            print "ERROR: Not killing Group of unknown type $type\n";
        }
        return;
    } else {
       print "   * Group $group nonexisting ($count results)\n";
       return;
    }
}



sub AD_computer_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $name = $arg_ref->{name};
    my $room = $arg_ref->{room};
    my $room_basename = $arg_ref->{room_basename};
    my $role = $arg_ref->{role};
    my $sophomorix_comment = $arg_ref->{sophomorix_comment};
    my $computer_count = $arg_ref->{computer_count};
    my $max_computer_count = $arg_ref->{max_computer_count};
    my $school = $arg_ref->{school};
    my $filename = $arg_ref->{filename};
    my $mac = $arg_ref->{mac};
    my $ipv4 = $arg_ref->{ipv4};
    my $creationdate = $arg_ref->{creationdate};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # calculation
    my $display_name=$name;
    my $smb_name=$name."\$";

    my $creationdate_ok;
    if (defined $creationdate){
        $creationdate_ok=$creationdate;
    } else {
        $creationdate_ok=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
    }

    # avoid error for empty attribute
    if (not defined $sophomorix_comment or $sophomorix_comment eq ""){
        $sophomorix_comment="---";
    }

    # sophomorixDnsNodename
    my $s_dns_nodename=$name;
    $s_dns_nodename=~tr/A-Z/a-z/; # in Kleinbuchstaben umwandeln

    # dns
    my $root_dns=&AD_dns_get($root_dse);

    $dns_name=$name.".".$root_dns;
    my @service_principal_name=("HOST/".$name,
                                "HOST/".$dns_name,
                                "RestrictedKrbHost/".$name,
                                "RestrictedKrbHost/".$dns_name,
                               );
    my $room_ou=$ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'GROUP_OU'};
    $room_ou=~s/\@\@FIELD_1\@\@/$room_basename/g; 
    my $dn_room = $room_ou.",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    my $dn="CN=".$name.",".$dn_room;
    my $prefix=$school;
    if ($school eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }

    if($Conf::log_level>=1){
        &Sophomorix::SophomorixBase::print_title(
              "Creating workstation $computer_count: $name");
        print "   DN:                    $dn\n";
        print "   DN(Parent):            $dn_room\n";
        print "   Name:                  $name\n";
        print "   Room:                  $room\n";
        print "   School:                $school\n";
        print "   File:                  $filename\n";
        print "   Prefix:                $prefix\n";
        print "   sAMAccountName:        $smb_name\n";
        print "   dNSHostName:           $dns_name\n";
        print "   sophomorixDnsNodename: $s_dns_nodename\n";
        foreach my $entry (@service_principal_name){
            print "   servicePrincipalName:  $entry\n";
        }
        print "\n";
    }

    if ($json>=1){
        # prepare json object
        my %json_progress=();
        $json_progress{'JSONINFO'}="PROGRESS";
        $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_PREFIX_EN'}.
                                     " $name".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_POSTFIX_EN'};
        $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_PREFIX_DE'}.
                                     " $name ".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_POSTFIX_DE'};
        $json_progress{'STEP'}=$computer_count;
        $json_progress{'FINAL_STEP'}=$max_computer_count;
        # print JSON Object
        &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                          json=>$json,
                                                          sophomorix_config=>$ref_sophomorix_config,
                                                        });
    }

    $ldap->add($dn_room,attr => ['objectClass' => ['top', 'organizationalUnit']]);
    my $result = $ldap->add( $dn,
                   attr => [
                   sAMAccountName => $smb_name,
                   displayName => "Computer ".$display_name,
                   dNSHostName => $dns_name,
#                   givenName   =s> "Computer",
#                   sn   => "Account",
#                   cn   => $name_token,
                   cn   => $name,
                   accountExpires => '9223372036854775807', # means never
                   servicePrincipalName => \@service_principal_name,
#                   unicodePwd => $uni_password,
#                   sophomorixExitAdminClass => "unknown", 
                   sophomorixComputerIP => $ipv4,
                   sophomorixComputerMAC => $mac,
                   sophomorixComputerRoom => $room,
                   sophomorixStatus => "P",
                   sophomorixAdminClass => $room,    
#                   sophomorixFirstPassword => $sophomorix_first_password, 
#                   sophomorixFirstnameASCII => $firstname_ascii,
#                   sophomorixSurnameASCII  => $surname_ascii,
                   sophomorixRole => $role,
                   sophomorixComment => $sophomorix_comment,
                   sophomorixSchoolPrefix => $prefix,
                   sophomorixSchoolname => $school,
                   sophomorixAdminFile => $filename,
                   sophomorixCreationDate => $creationdate_ok, 
                   sophomorixDnsNodename => $s_dns_nodename, 
                   userAccountControl => '4096',
                   instanceType => '4',
                   objectclass => ['top', 'person',
                                   'organizationalPerson',
                                   'user','computer' ],
#                   'objectClass' => \@objectclass,
                           ]
                           );
    &AD_debug_logdump($result,2,(caller(0))[3]);
}



sub AD_session_manage {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
#    my $creationdate = $arg_ref->{creationdate};
    my $supervisor = $arg_ref->{supervisor};
    my $create = $arg_ref->{create};
    my $kill = $arg_ref->{kill};
    my $session = $arg_ref->{session};
    my $new_comment = $arg_ref->{comment};
    my $developer_session = $arg_ref->{developer_session};
    my $new_participants = $arg_ref->{participants};
    my $ref_sessions = $arg_ref->{sessions_ref};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # the updated session string
    my $session_string_new="";
    my $session_new="";        

    if (not defined $new_comment or $new_comment eq ""){
        $new_comment="---";
    } else {
        # remove ; from comment
        $new_comment=~s/;//g;
    }
    if (not defined $new_participants){
        $new_participants="";
    }

    # creating the session string
    $session_string="---";
    $session_string_old="---";
    if ($create eq "TRUE"){
        if ($developer_session ne ""){
            # creating sessions with arbitrary names for testing
            $session_new=$developer_session;
            $session_string_new=$developer_session.";".$new_comment.";".$new_participants.";";
        } else {
            # new session
            # this is the default
            $session_new=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_FILE'};
            $session_string_new=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_FILE'}.
                                ";".$new_comment.";".$new_participants.";";
        }
    } elsif (defined $session and defined $new_participants and defined $new_comment){
        # modifying the session
        if (defined $ref_sessions->{'ID'}{$session}{'SUPERVISOR'}{'sAMAccountName'}){
            # get data from session hash
            $session_new=$session;
            $supervisor=$ref_sessions->{'ID'}{$session}{'SUPERVISOR'}{'sAMAccountName'};
            $session_string_old=$ref_sessions->{'ID'}{$session}{'sophomorixSessions'};
            my ($unused,$old_comment,$old_participants)=split(/;/,$session_string_old);
	    if ($new_comment eq "---"){
                $new_comment=$old_comment;
	    }
            if($new_participants eq ""){
                $new_participants=$old_participants;
            }
            $session_string_new=$session.";".$new_comment.";".$new_participants.";";
        } else {
            print "\n Session $session not found\n\n";
            return;
        }
    } else {
        print "\nI do not know what you want me to do\n\n";
        return;
    }

    # locating the supervisors DN
    my ($count,$dn,$rdn)=&AD_object_search($ldap,$root_dse,"user",$supervisor);

    ############################################################
    if ($count==1){
        my %new_sessions=();
        my @new_sessions=();
        my @old_sessions = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"sophomorixSessions");

        # push old sessions into hash (drop doubles)
        foreach my $old_session (@old_sessions){
            my ($id,$old_comment,$old_participants) = split(/;/,$old_session);
            $new_sessions{$id}=$old_comment.";".$old_participants.";";
        }

        if ($kill eq "TRUE"){
	    print "Killing session $session_new\n";
            $session_string_new="---";
            delete $new_sessions{$session_new};
        } else {
            # overwrite the changing session
            $new_sessions{$session_new}=$new_comment.";".$new_participants.";";
        }

        # write the hash into a list
        foreach my $session ( keys %new_sessions ) {
            my $string=$session.";".$new_sessions{$session};
            push @new_sessions, $string;
	    #print "String: $string\n";
        }

        if($Conf::log_level>=1){
            print "   Supervisor:  $supervisor\n";
            print "   DN:          $dn\n";
            print "   Session:     $session_new\n";
            print "      Old:      $session_string_old\n";
            print "      New:      $session_string_new\n";
        }

        # updating session with the hash
        my $mesg = $ldap->modify($dn,
                          replace => {'sophomorixSessions' => \@new_sessions }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    } else {
        print "\nWARNING: User $supervisor not found in ldap, skipping session creation\n\n";
        return;
    }
}



#sub AD_session_set_exam {
sub AD_user_set_exam_mode {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $supervisor = $arg_ref->{supervisor};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    print "   * Setting exam mode for session participant $participant (Supervisor: $supervisor)\n";
    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$participant);
    if (not $count==1){
        print "ERROR: Could not set exam mode for nonexisting user $participant\n";
        return 1;
    }
    &AD_user_update({ldap=>$ldap,
                     root_dse=>$root_dse,
                     dn=>$dn,
                     user=>$participant,
                     user_count=>$user_count,
                     max_user_count=>$max_user_count,
                     exammode=>$supervisor,
                     uac_force=>"disable",
                     json=>$json,
                     sophomorix_config=>$ref_sophomorix_config,
                     sophomorix_result=>$ref_sophomorix_result,
                   });
    return 0;
}



#sub AD_session_unset_exam {
sub AD_user_unset_exam_mode {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    print "   * Unsetting exam mode for session participant $participant\n";
    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$participant);
    if (not $count==1){
        print "ERROR: Could not unset exam mode for nonexisting user $participant\n";
        return 1;
    }
    &AD_user_update({ldap=>$ldap,
                     root_dse=>$root_dse,
                     dn=>$dn,
                     user=>$participant,
                     user_count=>$user_count,
                     max_user_count=>$max_user_count,
                     exammode=>"---",
                     uac_force=>"enable",
                     json=>$json,
                     sophomorix_config=>$ref_sophomorix_config,
                     sophomorix_result=>$ref_sophomorix_result,
                   });
    return 0;
}

 

sub AD_user_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $identifier = $arg_ref->{identifier};
    my $login = $arg_ref->{login};
    my $group = $arg_ref->{group};
    my $group_basename = $arg_ref->{group_basename};
    my $firstname_ascii = $arg_ref->{firstname_ascii};
    my $surname_ascii = $arg_ref->{surname_ascii};
    my $firstname_utf8 = $arg_ref->{firstname_utf8};
    my $surname_utf8 = $arg_ref->{surname_utf8};
    my $birthdate = $arg_ref->{birthdate};
    my $sophomorix_first_password = $arg_ref->{sophomorix_first_password};
    my $unid = $arg_ref->{unid};
    my $uidnumber_wish = $arg_ref->{uidnumber_wish};
    my $school = $arg_ref->{school};
    my $role = $arg_ref->{role};
    my $type = $arg_ref->{type};
    my $creationdate = $arg_ref->{creationdate};
    my $tolerationdate = $arg_ref->{tolerationdate};
    my $deactivationdate = $arg_ref->{deactivationdate};
    my $status = $arg_ref->{status};
    my $file = $arg_ref->{file};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $creationdate_ok;
    if (defined $creationdate){
        $creationdate_ok=$creationdate;
    } else {
        $creationdate_ok=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
    }

    print "\n";
    &Sophomorix::SophomorixBase::print_title(
          "Creating user $user_count/$max_user_count : $login (start)");

    # set defaults if not defined
    if (not defined $identifier){
        $identifier="---";
    }
    if (not defined $uidnumber_wish or $uidnumber_wish eq "---"){
        $uidnumber_wish=&next_free_uidnumber_get($ldap,$root_dse);
    }

    if ($tolerationdate eq "---"){
        $tolerationdate=$DevelConf::default_date;
    }
    if ($deactivationdate eq "---"){
        $deactivationdate=$DevelConf::default_date;
    }
    $school=&AD_get_schoolname($school);

    $group=&Sophomorix::SophomorixBase::replace_vars($group,$ref_sophomorix_config,$school);
    $group_basename=&Sophomorix::SophomorixBase::replace_vars($group_basename,$ref_sophomorix_config,$school);

    # calculate
    my $shell="/bin/false";
    my $display_name = $firstname_utf8." ".$surname_utf8;
    my $user_principal_name = $login."\@".$root_dns;
    my $mail = $login."\@".$root_dns;

    my ($homedirectory,$unix_home,$unc,$smb_rel_path)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school,
                                                       $group_basename,
                                                       $login,
                                                       $role,
                                                       $ref_sophomorix_config);
    # ou
    my $class_ou;
    my $dn_class;
    my $dn;
    if ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'administrator.global'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{ADMINS}{OU};
        $dn="cn=".$login.",".$dn_class;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'administrator.school'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{'SCHOOLS'}{$school}{ADMINS}{OU};
	$dn="cn=".$login.",".$dn_class;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'binduser.global'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{ADMINS}{OU};
        $dn="cn=".$login.",".$dn_class;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'binduser.school'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{'SCHOOLS'}{$school}{ADMINS}{OU};
	$dn="cn=".$login.",".$dn_class;
    } else {
        # from file
        if (exists $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'GROUP_OU'}){
            $class_ou=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'GROUP_OU'};
        } else {
            $class_ou=$ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$file}{'GROUP_OU'};
        }
        $class_ou=~s/\@\@FIELD_1\@\@/$group_basename/g; 
        $dn_class = $class_ou.",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
        $dn="CN=".$login.",".$dn_class;
    }

    # password generation
    my $uni_password=&_unipwd_from_plainpwd($sophomorix_first_password);

    ## build the conversion map from your local character set to Unicode    
    #my $charmap = Unicode::Map8->new('latin1')  or  die;
    ## surround the PW with double quotes and convert it to UTF-16
    #my $uni_password = $charmap->tou('"'.$sophomorix_first_password.'"')->byteswap()->utf16();

    my $prefix=$school;
    if ($school eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }

    # settingthe dates according to status
    if (defined $status and $status eq "T"){
        $deactivationdate=$DevelConf::default_date;
    } elsif (defined $status and 
       ($status eq "U" or 
        $status eq "A" or 
        $status eq "E" or 
        $status eq "S" or 
        $status eq "P" )){
        $deactivationdate=$DevelConf::default_date;
        $tolerationdate=$DevelConf::default_date;
    }

    if ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } else {
        # user from a file
        # keep $sophomorix_first_password
    }

    my $firstname_initial_utf8=&Sophomorix::SophomorixBase::extract_initial($firstname_utf8);
    my $surname_initial_utf8=&Sophomorix::SophomorixBase::extract_initial($surname_utf8);

    if($Conf::log_level>=1){
        print "   DN:                 $dn\n";
        print "   DN(Parent):         $dn_class\n";
        print "   Surname(ASCII):     $surname_ascii\n";
        print "   Surname(UTF8):      $surname_utf8\n";
        print "   Firstname(ASCII):   $firstname_ascii\n";
        print "   Firstname(UTF8):    $firstname_utf8\n";
        print "   Initials(UTF8):     $firstname_initial_utf8 $surname_initial_utf8\n";
        print "   Birthday:           $birthdate\n";
        print "   Identifier:         $identifier\n";
        print "   School:             $school\n"; # Organisatinal Unit
        print "   Role(User):         $role\n";
        print "   Status:             $status\n";
        print "   Type(Group):        $type\n";
        print "   Group:              $group ($group_basename)\n"; # lehrer oder klasse
        #print "   GECOS:              $gecos\n";
        #print "   Login (to check):   $login_name_to_check\n";
        print "   Login (check OK):   $login\n";
        print "   Password:           $sophomorix_first_password\n";
        # sophomorix stuff
        print "   Creationdate:       $creationdate_ok\n";
        print "   Tolerationdate:     $tolerationdate\n";
        print "   Deactivationdate:   $deactivationdate\n";
        print "   Unid:               $unid\n";
        print "   Unix-uidNumber:     $uidnumber_wish\n";
        print "   File:               $file\n";
        print "   homeDirectory:      $homedirectory\n";
        print "   unixHomeDirectory:  $unix_home\n";
    }

    if ($json>=1){
        # prepare json object
        my %json_progress=();
        $json_progress{'JSONINFO'}="PROGRESS";
        $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_PREFIX_EN'}.
                                     " $login ($firstname_utf8 $surname_utf8)".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_POSTFIX_EN'};
        $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_PREFIX_DE'}.
                                     " $login ($firstname_utf8 $surname_utf8) ".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_POSTFIX_DE'};
        $json_progress{'STEP'}=$user_count;
        $json_progress{'FINAL_STEP'}=$max_user_count;
        # print JSON Object
        &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                          json=>$json,
                                                          sophomorix_config=>$ref_sophomorix_config,
                                                        });
    }

    # make sure $dn_class exists
    $ldap->add($dn_class,attr => ['objectClass' => ['top', 'organizationalUnit']]);

    my $user_account_control;
    if (defined $status and $status ne "---"){
        if ($status eq "L" or
            $status eq "D" or
            $status eq "F" or
            $status eq "R" or
            $status eq "K"
            ){
	    $user_account_control=$DevelConf::default_user_account_control_disabled;
	} else {
	    $user_account_control=$DevelConf::default_user_account_control;
        }
    }

    # create quotalist
    my @quotalist;
    if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        # school <global>: only one quota entry
        @quotalist=("$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NEWUSER'}:---:"); 
   } else {
       # other schools: global + school quota entry
       @quotalist=("$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NEWUSER'}:---:",
                   "$school:---:---:$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NEWUSER'}:---:");
    }

    # add the user
    my $result = $ldap->add( $dn,
                   attr => [
                   sAMAccountName => $login,
                   givenName => $firstname_utf8,
                   sn => $surname_utf8,
                   displayName => [$display_name],
                   userPrincipalName => $user_principal_name,
                   mail => $mail,
                   unicodePwd => $uni_password,
                   homeDrive => "H:",
                   homeDirectory => $homedirectory,
                   unixHomeDirectory => $unix_home,
                   sophomorixExitAdminClass => "unknown", 
                   sophomorixUnid => $unid,
                   sophomorixStatus => $status,
                   sophomorixAdminClass => $group,    
                   sophomorixAdminFile => $file,    
                   sophomorixFirstPassword => $sophomorix_first_password, 
                   sophomorixFirstnameASCII => $firstname_ascii,
                   sophomorixSurnameASCII  => $surname_ascii,
                   sophomorixBirthdate  => $birthdate,
                   sophomorixRole => $role,
                   sophomorixUserToken => "---",
                   sophomorixFirstnameInitial => $firstname_initial_utf8,
                   sophomorixSurnameInitial => $surname_initial_utf8,
                   sophomorixQuota=> [@quotalist],
                   sophomorixMailQuota=>"---:---:",
                   sophomorixMailQuotaCalculated=>$ref_sophomorix_config->{'INI'}{'MAILQUOTA'}{'CALCULATED_DEFAULT'},
                   sophomorixCloudQuotaCalculated=>"---",
                   sophomorixSchoolPrefix => $prefix,
                   sophomorixSchoolname => $school,
                   sophomorixCreationDate => $creationdate_ok, 
                   sophomorixTolerationDate => $tolerationdate, 
                   sophomorixDeactivationDate => $deactivationdate, 
                   sophomorixComment => "created by sophomorix", 
                   sophomorixWebuiDashboard => "---", 
                   sophomorixExamMode => "---", 
                   userAccountControl => $user_account_control,
                   uidNumber => $uidnumber_wish,
                   objectclass => ['top', 'person',
                                     'organizationalPerson',
                                     'user' ],
#                   'objectClass' => \@objectclass,
                           ]
                           );
    my $add_result=&AD_debug_logdump($result,2,(caller(0))[3]);
    if ($add_result!=0){ # add was succesful
        # log the killing of a user 
        &Sophomorix::SophomorixBase::log_user_add({sAMAccountName=>$login,
                                                   sophomorixRole=>$role, 
                                                   #home_delete_string=>$home_delete_string,
                                                   sophomorixSchoolname=>$school,
                                                   firstname=>$firstname_utf8,    
                                                   lastname=>$surname_utf8,
                                                   adminclass=>$group,
                                                   unid=>$unid,
                                                   sophomorix_config=>$ref_sophomorix_config,
                                                   sophomorix_result=>$ref_sophomorix_result,
                                                 });
    }

    ######################################################################
    # memberships of created user
    ######################################################################
    if ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        #######################################################
        # global binduser
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.global'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.global'}{'MEMBEROF'});
        foreach my $group (@member){
            &AD_group_addmember({ldap => $ldap,
                                  root_dse => $root_dse, 
                                  group => $group,
                                  addmember => $login,
                                });
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        #######################################################
        # school binduser
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.school'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            $mangroup=&Sophomorix::SophomorixBase::replace_vars($mangroup,$ref_sophomorix_config,$school);
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.school'}{'MEMBEROF'});
        foreach my $group (@member){
            $group=&Sophomorix::SophomorixBase::replace_vars($group,$ref_sophomorix_config,$school);
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $group,
                                 addmember => $login,
                               });
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        #######################################################
        # global administrator
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.global'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.global'}{'MEMBEROF'});
        foreach my $group (@member){
            &AD_group_addmember({ldap => $ldap,
                                  root_dse => $root_dse, 
                                  group => $group,
                                  addmember => $login,
                                });
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        #######################################################
        # school administrator
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.school'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            $mangroup=&Sophomorix::SophomorixBase::replace_vars($mangroup,$ref_sophomorix_config,$school);
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.school'}{'MEMBEROF'});
        foreach my $group (@member){
            $group=&Sophomorix::SophomorixBase::replace_vars($group,$ref_sophomorix_config,$school);
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $group,
                                 addmember => $login,
                               });
        }
    } else {
        #######################################################
        # user from a file -> get groups from sophomorix_config 
        #######################################################
        # add user to groups
        # MEMBEROF
        foreach my $ref_group (@{ $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'MEMBEROF'} }){
            my $group=$ref_group; # make copy to not modify the hash 
            $group=~s/\@\@FIELD_1\@\@/$group_basename/g; 
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $group,
                                 addmember => $login,
                               }); 
	}

        # SOPHOMORIXMEMBEROF = MEMBEROF + sophomorixMember attribute
        foreach my $ref_s_group (@{ $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SOPHOMORIXMEMBEROF'} }){
            my $s_group=$ref_s_group; # make copy to not modify the hash 
            $s_group=&Sophomorix::SophomorixBase::replace_vars($s_group,$ref_sophomorix_config,$school);
            $s_group=~s/\@\@FIELD_1\@\@/$group_basename/g; 
            # find dn of adminclass.group
            my ($count,$dn_class,$cn_exist,$infos)=&AD_object_search($ldap,$root_dse,"group",$s_group);
            # fetch old members from sophomorixmembers
            my @old_members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn_class,"sophomorixMembers");
            # create a unique list of new members
            my @members = uniq(@old_members,$login); 
            my $members=join(",",@members);
            # update group
            &AD_group_update({ldap=>$ldap,
                              root_dse=>$root_dse,
                              dn=>$dn_class,
                              type=>"adminclass",
                              members=>$members,
                              sophomorix_config=>$ref_sophomorix_config,
                            });
	}

        # MANMEMBEROF
        # add user to management groups
        foreach my $ref_mangroup (@{ $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'MANMEMBEROF'} }){
            my $mangroup=$ref_mangroup; # make copy to not modify the hash 
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
    }

    ############################################################
    # Create filesystem
    ############################################################
    if ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.schooladministrator_home",
                               school=>$school,
                               administrator_home=>$login,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.globaladministrator_home",
                               school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                               administrator_home=>$login,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        # no home
        &Sophomorix::SophomorixBase::print_title("NOT creating HOME: $login (sophomorixRole $role)");
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        # no home
        &Sophomorix::SophomorixBase::print_title("NOT creating HOME: $login (sophomorixRole $role)");
    } elsif ($role eq "teacher"){
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.teacher_home",
                                   school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                                   teacherclass=>$group,
                                   teacher_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        } else {
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.teacher_home",
                                   school=>$school,
                                   teacherclass=>$group,
                                   teacher_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        }
    } elsif ($role eq "student"){
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.student_home",
                                   school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                                   adminclass=>$group,
                                   student_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        } else {
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.student_home",
                                   school=>$school,
                                   adminclass=>$group,
                                   student_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        }
    }  

    &Sophomorix::SophomorixBase::print_title("Creating user $user_count: $login (end)");
    print "\n";
}



sub AD_user_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $dn = $arg_ref->{dn};
    my $firstname_ascii = $arg_ref->{firstname_ascii};
    my $surname_ascii = $arg_ref->{surname_ascii};
    my $firstname_utf8 = $arg_ref->{firstname_utf8};
    my $surname_initial_utf8 = $arg_ref->{surname_initial_utf8};
    my $firstname_initial_utf8 = $arg_ref->{firstname_initial_utf8};
    my $surname_utf8 = $arg_ref->{surname_utf8};
    my $filename = $arg_ref->{filename};
    my $birthdate = $arg_ref->{birthdate};
    my $unid = $arg_ref->{unid};
    my $quota = $arg_ref->{quota};
    my $quota_calc = $arg_ref->{quota_calc};
    my $quota_info = $arg_ref->{quota_info};
    my $mailquota = $arg_ref->{mailquota};
    my $mailquota_calc = $arg_ref->{mailquota_calc};
    my $cloudquota_calc = $arg_ref->{cloudquota_calc};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $hide_pwd = $arg_ref->{hide_pwd};
    my $user = $arg_ref->{user};
    my $firstpassword = $arg_ref->{firstpassword}; # sophomorixFirstpassword
    my $sophomorix_first_password = $arg_ref->{sophomorix_first_password}; # unicodePwd
    my $status = $arg_ref->{status};
    my $comment = $arg_ref->{comment};
    # custom attributes
    my $custom_1 = $arg_ref->{custom_1};
    my $custom_2 = $arg_ref->{custom_2};
    my $custom_3 = $arg_ref->{custom_3};
    my $custom_4 = $arg_ref->{custom_4};
    my $custom_5 = $arg_ref->{custom_5};
    my $custom_multi_1 = $arg_ref->{custom_multi_1};
    my $custom_multi_2 = $arg_ref->{custom_multi_2};
    my $custom_multi_3 = $arg_ref->{custom_multi_3};
    my $custom_multi_4 = $arg_ref->{custom_multi_4};
    my $custom_multi_5 = $arg_ref->{custom_multi_5};
    # intrinsic attributes
    my $intrinsic_1 = $arg_ref->{intrinsic_1};
    my $intrinsic_2 = $arg_ref->{intrinsic_2};
    my $intrinsic_3 = $arg_ref->{intrinsic_3};
    my $intrinsic_4 = $arg_ref->{intrinsic_4};
    my $intrinsic_5 = $arg_ref->{intrinsic_5};
    my $intrinsic_multi_1 = $arg_ref->{intrinsic_multi_1};
    my $intrinsic_multi_2 = $arg_ref->{intrinsic_multi_2};
    my $intrinsic_multi_3 = $arg_ref->{intrinsic_multi_3};
    my $intrinsic_multi_4 = $arg_ref->{intrinsic_multi_4};
    my $intrinsic_multi_5 = $arg_ref->{intrinsic_multi_5};
    #
    my $webui_dashboard = $arg_ref->{webui_dashboard};
    my $webui_permissions = $arg_ref->{webui_permissions};
    my $ref_webui_permissions_calculated = $arg_ref->{webui_permissions_calculated};
    my $school = $arg_ref->{school};
    my $role = $arg_ref->{role};
    my $examteacher = $arg_ref->{exammode};
    my $uac_force = $arg_ref->{uac_force};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};
    # start with empty sharelist
    my @sharelist=();
    
    my $update_log_string="";

    if (not defined $max_user_count){
	$max_user_count="-";
    }

    my ($firstname_utf8_AD,
        $lastname_utf8_AD,
        $adminclass_AD,
        $existing_AD,
        $exammode_AD,
        $role_AD,
        $home_directory_AD,
        $user_account_control_AD,
        $toleration_date_AD,
        $deactivation_date_AD,
        $school_AD,
        $status_AD,
        $firstpassword_AD,
        $unid_AD
       )=&AD_get_user({ldap=>$ldap,
                       root_dse=>$root_dse,
                       root_dns=>$root_dns,
                       user=>$user,
                     });

    # hash of what to replace
    my %replace=();
    # list of what to delete
    my @delete=();

    print "\n";
    &Sophomorix::SophomorixBase::print_title(
          "Updating User ${user_count}/$max_user_count: $user (start)");
    print "   DN: $dn\n";

    if (defined $firstname_utf8 and $firstname_utf8 ne "---"){
        $replace{'givenName'}=$firstname_utf8;
        print "   givenName:                  $firstname_utf8\n";
    }
    if (defined $surname_utf8 and $surname_utf8 ne "---"){
        $replace{'sn'}=$surname_utf8;
        print "   sn:                         $surname_utf8\n";
    }

   # IF first AND last are defined AND one of them is NOT "---" -> update displayname
   if ( (defined $firstname_utf8 and defined $surname_utf8) and 
        ($firstname_utf8 ne "---" or $surname_utf8 ne "---") ){
        # update displayname
        if ($firstname_utf8 ne "---" and $surname_utf8 ne "---"  ){
           $display_name = $firstname_utf8." ".$surname_utf8;
        } elsif ($firstname_utf8 eq "---"){
           $display_name = $firstname_utf8_AD." ".$surname_utf8;
        } elsif ($surname_utf8 eq "---"){
           $display_name = $firstname_utf8." ".$lastname_utf8_AD;
        }
        $replace{'displayName'}=$display_name;
        print "   displayName:                $display_name\n";
    }
    if (defined $firstname_initial_utf8 and $firstname_initial_utf8 ne "---" ){
        $replace{'sophomorixFirstnameInitial'}=$firstname_initial_utf8;
        print "   sophomorixFirstnameInitial: $firstname_initial_utf8\n";
    }
    if (defined $surname_initial_utf8 and $surname_initial_utf8 ne "---" ){
        $replace{'sophomorixSurnameInitial'}=$surname_initial_utf8;
        print "   sophomorixSurnameInitial:   $surname_initial_utf8\n";
    }
    if (defined $firstname_ascii and $firstname_ascii ne "---" ){
        $replace{'sophomorixFirstnameASCII'}=$firstname_ascii;
        print "   sophomorixFirstnameASCII:   $firstname_ascii\n";
    }
    if (defined $surname_ascii and $surname_ascii ne "---"){
        $replace{'sophomorixSurnameASCII'}=$surname_ascii;
        print "   sophomorixSurnameASCII:     $surname_ascii\n";
    }
    if (defined $birthdate and $birthdate ne "---"){
        $replace{'sophomorixBirthdate'}=$birthdate;
        print "   sophomorixBirthdate:        $birthdate\n";
    }
    if (defined $filename and $filename ne "---"){
        $replace{'sophomorixAdminFile'}=$filename;
        print "   sophomorixAdminFile:        $filename\n";
    }
    if (defined $unid and $unid ne "---"){
        if ($unid eq ""){
            $unid="---"; # upload --- for empty unid
        }
        $replace{'sophomorixUnid'}=$unid;
        print "   sophomorixUnid:             $unid\n";
    }
    # firstpassword for sophomorixFirstpassword
    if (defined $firstpassword){
        $replace{'sophomorixFirstPassword'}=$firstpassword;
	if ($hide_pwd==1){
	    print "   sophomorixFirstPassword: ****** (omitted by --hide)\n";
	} else {
	    print "   sophomorixFirstPassword: $firstpassword\n";
	}
    }

    # firstpassword (to create hashed password)
    if (defined $sophomorix_first_password){
        my $uni_password=&_unipwd_from_plainpwd($sophomorix_first_password);
        $replace{'unicodePwd'}=$uni_password;
	if ($hide_pwd==1){
	    print "   unicodePwd:                 ****** (omitted by --hide)\n";
	} else {
	    print "   unicodePwd:                 $sophomorix_first_password\n";
	}
    }

    # quota
    if (defined $quota){
        my %quota_new=();
        my @quota_new=();
        my @quota_old = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"sophomorixQuota");
        foreach my $quota_old (@quota_old){
            my ($share,$value,$calc,$info,$comment)=split(/:/,$quota_old);
            if (not defined $calc){$calc="---";}
            if (not defined $calc){$info="---";}
	    # save old values in quota_new
            $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;
            $quota_new{'QUOTA'}{$share}{'CALC'}=$calc;
            $quota_new{'QUOTA'}{$share}{'INFO'}=$info;
            $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
	    push @sharelist, $share;
        }
        # work on NEW Quota, given by option
	my @schoolquota=split(/,/,$quota);
	foreach my $schoolquota (@schoolquota){
	    my ($share,$value,$comment)=split(/:/,$schoolquota);
	    if (not exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}){
                print "\nERROR: SMB-share $share does not exist!\n\n";
		exit;
	    }
            if ($value=~/[^0-9]/ and $value ne "-1" and $value ne "---"){
                print "\nERROR: Quota value $value does not consist ",
                      "of numerals 0-9 or is -1 or is \"---\"\n\n";
		exit;
	    }
            # overriding quota_new:
            # -----------------------
            # A) user value (used by sophomorix-user)
    	    $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;

            # B) calc value (used by sophomorix-quota)
            if (defined $quota_calc){
                $quota_new{'QUOTA'}{$share}{'CALC'}=$quota_calc;
            } else {
                 $quota_new{'QUOTA'}{$share}{'CALC'}="---";
            }
            # C) info value (used by sophomorix-quota AFTER quota is set successfully)
            if (defined $quota_info){
                $quota_new{'QUOTA'}{$share}{'INFO'}=$quota_info;
            } else {
                $quota_new{'QUOTA'}{$share}{'INFO'}=
                    $ref_sophomorix_config->{'INI'}{'QUOTA'}{'UPDATEUSER'};
	    }
            # D) comment
            if (defined $comment){
                $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
            }
   	    push @sharelist, $share;
	}
        # debug
        #print "OLD: @quota_old\n";
	#print Dumper(%quota_new);
	#print "Sharelist: @sharelist\n";
        # prepare ldap modify list
	@sharelist = uniq(@sharelist);
	@sharelist = sort(@sharelist);
	foreach my $share (@sharelist){
            if ($quota_new{'QUOTA'}{$share}{'VALUE'} eq "---" and 
                $share ne $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'} and
                $share ne $school_AD){
                # push NOT in @quota_new -> attribute will be removed
	    } else {
		# push -> keep attribute
		if (not exists $quota_new{'QUOTA'}{$share}{'CALC'}){
                    # new share
                    $quota_new{'QUOTA'}{$share}{'CALC'}="---";
                }
		if (not defined $quota_new{'QUOTA'}{$share}{'COMMENT'}){
                    $quota_new{'QUOTA'}{$share}{'COMMENT'}="---";
		}
		push @quota_new, $share.":".
                                 $quota_new{'QUOTA'}{$share}{'VALUE'}.":".
                                 $quota_new{'QUOTA'}{$share}{'CALC'}.":".
                                 $quota_new{'QUOTA'}{$share}{'INFO'}.":".
                                 $quota_new{'QUOTA'}{$share}{'COMMENT'}.":";
	    }
	}
	print "   * Setting sophomorixQuota to: @quota_new\n";
        my $quota_new_string=join("|",@quota_new);
        $update_log_string=$update_log_string."\"sophomorixQuota=".$quota_new_string."\",";
        my $mesg = $ldap->modify($dn,replace => { sophomorixQuota => \@quota_new }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # mailquota
    if (defined $mailquota){
        my ($value,$comment)=split(/:/,$mailquota);
        if (not defined $comment){
            $comment="---";
        }
        my $mailquota_new=$value.":".$comment.":";
        $replace{'sophomorixMailQuota'}=$mailquota_new;
        print "   sophomorixMailQuota:        $mailquota_new\n";
    }
    
    # mailquota_calc
    if (defined $mailquota_calc){
        $replace{'sophomorixMailQuotaCalculated'}=$mailquota_calc;
        print "   sophomorixMailQuotaCalculated:        $mailquota_calc\n";
    }
    
    # cloudquota_calc
    if (defined $cloudquota_calc){
        $replace{'sophomorixCloudQuotaCalculated'}=$cloudquota_calc;
        print "   sophomorixCloudQuotaCalculated:       $cloudquota_calc\n";
    }
    
    # status
    if (defined $status and $status ne "---"){
        $replace{'sophomorixStatus'}=$status;
        print "   sophomorixStatus:           $status\n";
        # setting userAccountControl and Dates
        my $user_account_control;
        my $toleration_date;
        my $deactivation_date;
        if ($status eq "U" or
            $status eq "E" or
            $status eq "A" or
            $status eq "S" or
            $status eq "P" 
            ){
            # Status U,E,A,S,P
            $user_account_control=&_uac_enable_user($user_account_control_AD);
            $toleration_date=$DevelConf::default_date;
            $deactivation_date=$DevelConf::default_date;
        } elsif  ($status eq "T"){
            # Status T
            $user_account_control=&_uac_enable_user($user_account_control_AD);
            $toleration_date=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
            $deactivation_date=$DevelConf::default_date;
        } elsif  ($status eq "D" or
                  $status eq "F" or
                  $status eq "L"){
            # Status D,F,L
            $user_account_control=&_uac_disable_user($user_account_control_AD);
            $toleration_date=$toleration_date_AD;
            $deactivation_date=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
        } elsif  ($status eq "K" or
                  $status eq "R"){
            # Status K,R
            $user_account_control=&_uac_disable_user($user_account_control_AD);
            $toleration_date=$toleration_date_AD;
            $deactivation_date=$deactivation_date_AD;
        } else {
            # unknown status
            print "\nERROR: status $status not definned\n\n";
            return;
        }

        # setting the hash
        $replace{'userAccountControl'}=$user_account_control;
        $replace{'sophomorixTolerationDate'}=$toleration_date;
        $replace{'sophomorixDeactivationDate'}=$deactivation_date;
        # print what is set
        print "   sophomorixTolerationDate:   $toleration_date\n";
        print "   sophomorixDeactivationDate: $deactivation_date\n";
        print "   userAccountControl:         $user_account_control",
              " (was: $user_account_control_AD)\n";
    }
    # update userAccountControl for exam users
    if (defined $uac_force and not defined $status){
        my $user_account_control;
        if ($uac_force eq "enable"){
            $user_account_control=&_uac_enable_user($user_account_control_AD);
            $replace{'userAccountControl'}=$user_account_control;
            print "   userAccountControl:         $user_account_control",
                  " (was: $user_account_control_AD)\n";
        } elsif ($uac_force eq "disable"){
            $user_account_control=&_uac_disable_user($user_account_control_AD);
            $replace{'userAccountControl'}=$user_account_control;
            print "   userAccountControl:         $user_account_control",
                  " (was: $user_account_control_AD)\n";
	}
    }
    if (defined $school and $school ne "---"){
        # update sophomorixSchoolname AND sophomorixSchoolPrefix
        $replace{'sophomorixSchoolname'}=$school;
        print "   sophomorixSchoolname:       $school\n";
        my $prefix;
        if ($school eq $DevelConf::name_default_school){
            $prefix="---";
        } else {
            $prefix=$school;
        }
        $replace{'sophomorixSchoolPrefix'}=$prefix;
        print "   sophomorixSchoolPrefix:     $prefix\n";
    } else {
        $school="---";
    }
    if (defined $role and $role ne "---"){
        $replace{'sophomorixRole'}=$role;
        print "   sophomorixRole:             $role\n";
    }
    if (defined $examteacher and $examteacher ne ""){
        $replace{'sophomorixExamMode'}=$examteacher;
        print "   sophomorixExamMode:         $examteacher\n";
    }
    if (defined $comment){
        if ($comment eq ""){
            # delete attr if empty
            push @delete, "sophomorixComment";
        } else {
            $replace{'sophomorixComment'}=$comment;
        }
        print "   sophomorixComment:          $comment\n";
    }

    # custom attributes
    if (defined $custom_1){
        if ($custom_1 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom1";
        } else {
            $replace{'sophomorixCustom1'}=$custom_1;
        }
        print "   sophomorixCustom1:          $custom_1\n";
    }
    if (defined $custom_2){
        if ($custom_2 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom2";
        } else {
            $replace{'sophomorixCustom2'}=$custom_2;
        }
        print "   sophomorixCustom2:          $custom_2\n";
    }
    if (defined $custom_3){
        if ($custom_3 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom3";
        } else {
            $replace{'sophomorixCustom3'}=$custom_3;
        }
        print "   sophomorixCustom3:          $custom_3\n";
    }
    if (defined $custom_4){
        if ($custom_4 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom4";
        } else {
            $replace{'sophomorixCustom4'}=$custom_4;
        }
        print "   sophomorixCustom4:          $custom_4\n";
    }
    if (defined $custom_5){
        if ($custom_5 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom5";
        } else {
            $replace{'sophomorixCustom5'}=$custom_5;
        }
        print "   sophomorixCustom5:          $custom_5\n";
    }

    # custom attributes (multiValue)
    if (defined $custom_multi_1){
        my @custom_multi_1=split(/,/,$custom_multi_1);
        @custom_multi_1 = reverse @custom_multi_1;
        print "   * Setting sophomorixCustomMulti1 to: @custom_multi_1\n";
        my $custom_multi_1_string=join("|",@custom_multi_1);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti1=".$custom_multi_1_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti1' => \@custom_multi_1 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_2){
        my @custom_multi_2=split(/,/,$custom_multi_2);
        @custom_multi_2 = reverse @custom_multi_2;
        print "   * Setting sophomorixCustomMulti2 to: @custom_multi_2\n";
        my $custom_multi_2_string=join("|",@custom_multi_2);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti2=".$custom_multi_2_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti2' => \@custom_multi_2 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_3){
        my @custom_multi_3=split(/,/,$custom_multi_3);
        @custom_multi_3 = reverse @custom_multi_3;
        print "   * Setting sophomorixCustomMulti3 to: @custom_multi_3\n";
        my $custom_multi_3_string=join("|",@custom_multi_3);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti3=".$custom_multi_3_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti3' => \@custom_multi_3 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_4){
        my @custom_multi_4=split(/,/,$custom_multi_4);
        @custom_multi_4 = reverse @custom_multi_4;
        print "   * Setting sophomorixCustomMulti4 to: @custom_multi_4\n";
        my $custom_multi_4_string=join("|",@custom_multi_4);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti4=".$custom_multi_4_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti4' => \@custom_multi_4 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_5){
        my @custom_multi_5=split(/,/,$custom_multi_5);
        @custom_multi_5 = reverse @custom_multi_5;
        print "   * Setting sophomorixCustomMulti5 to: @custom_multi_5\n";
        my $custom_multi_5_string=join("|",@custom_multi_5);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti5=".$custom_multi_5_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti5' => \@custom_multi_5 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # intrinsic attributes (singleValue)
    if (defined $intrinsic_1){
        if ($intrinsic_1 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic1";
        } else {
            $replace{'sophomorixIntrinsic1'}=$intrinsic_1;
        }
        print "   sophomorixIntrinsic1:       $intrinsic_1\n";
    }
    if (defined $intrinsic_2){
        if ($intrinsic_2 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic2";
        } else {
            $replace{'sophomorixIntrinsic2'}=$intrinsic_2;
        }
        print "   sophomorixIntrinsic2:       $intrinsic_2\n";
    }
    if (defined $intrinsic_3){
        if ($intrinsic_3 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic3";
        } else {
            $replace{'sophomorixIntrinsic3'}=$intrinsic_3;
        }
        print "   sophomorixIntrinsic3:       $intrinsic_3\n";
    }
    if (defined $intrinsic_4){
        if ($intrinsic_4 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic4";
        } else {
            $replace{'sophomorixIntrinsic4'}=$intrinsic_4;
        }
        print "   sophomorixIntrinsic4:       $intrinsic_4\n";
    }
    if (defined $intrinsic_5){
        if ($intrinsic_5 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic5";
        } else {
            $replace{'sophomorixIntrinsic5'}=$intrinsic_5;
        }
        print "   sophomorixIntrinsic5:       $intrinsic_5\n";
    }

    # intrinsic attributes (multiValue)
    if (defined $intrinsic_multi_1){
        my @intrinsic_multi_1=split(/,/,$intrinsic_multi_1);
        @intrinsic_multi_1 = reverse @intrinsic_multi_1;
        print "   * Setting sophomorixIntrinsicMulti1 to: @intrinsic_multi_1\n";
        my $intrinsic_multi_1_string=join("|",@intrinsic_multi_1);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti1=".$intrinsic_multi_1_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti1' => \@intrinsic_multi_1 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_2){
        my @intrinsic_multi_2=split(/,/,$intrinsic_multi_2);
        @intrinsic_multi_2 = reverse @intrinsic_multi_2;
        print "   * Setting sophomorixIntrinsicMulti2 to: @intrinsic_multi_2\n";
        my $intrinsic_multi_2_string=join("|",@intrinsic_multi_2);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti2=".$intrinsic_multi_2_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti2' => \@intrinsic_multi_2 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_3){
        my @intrinsic_multi_3=split(/,/,$intrinsic_multi_3);
        @intrinsic_multi_3 = reverse @intrinsic_multi_3;
        print "   * Setting sophomorixIntrinsicMulti3 to: @intrinsic_multi_3\n";
        my $intrinsic_multi_3_string=join("|",@intrinsic_multi_3);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti3=".$intrinsic_multi_3_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti3' => \@intrinsic_multi_3 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_4){
        my @intrinsic_multi_4=split(/,/,$intrinsic_multi_4);
        @intrinsic_multi_4 = reverse @intrinsic_multi_4;
        print "   * Setting sophomorixIntrinsicMulti4 to: @intrinsic_multi_4\n";
        my $intrinsic_multi_4_string=join("|",@intrinsic_multi_4);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti4=".$intrinsic_multi_4_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti4' => \@intrinsic_multi_4 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_5){
        my @intrinsic_multi_5=split(/,/,$intrinsic_multi_5);
        @intrinsic_multi_5 = reverse @intrinsic_multi_5;
        print "   * Setting sophomorixIntrinsicMulti5 to: @intrinsic_multi_5\n";
        my $intrinsic_multi_5_string=join("|",@intrinsic_multi_5);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti5=".$intrinsic_multi_5_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti5' => \@intrinsic_multi_5 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # webui
    if (defined $webui_dashboard){
        if ($webui_dashboard eq ""){
            # delete attr if empty
            push @delete, "sophomorixWebuiDashboard";
        } else {
            $replace{'sophomorixWebuiDashboard'}=$webui_dashboard;
        }
        print "   sophomorixWebuiDashboard:   $webui_dashboard\n";
    }

    if (defined $webui_permissions){
        my @webui_permissions=split(/,/,$webui_permissions);
        @webui_permissions = reverse @webui_permissions;
        print "   * Setting sophomorixWebuiPermissions to: @webui_permissions\n";
        my $webui_permissions_string=join("|",@webui_permissions);
        $update_log_string=$update_log_string."\"sophomorixWebuiPermissions=".$webui_permissions_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixWebuiPermissions' => \@webui_permissions }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    if ( defined $ref_webui_permissions_calculated ){
	print "   * Setting sophomorixWebuiPermissionsCalculated to:\n";
        foreach my $entry (@{ $ref_webui_permissions_calculated }){
            print "      $entry\n";
        }
        my $ref_webui_permissions_calculated_string=join("|",@{ $ref_webui_permissions_calculated });
        $update_log_string=$update_log_string."\"sophomorixWebuiPermissionsCalculated=".$ref_webui_permissions_calculated_string."\",";
        my $mesg = $ldap->modify($dn,
            replace => { sophomorixWebuiPermissionsCalculated => $ref_webui_permissions_calculated }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    } 


    if ($json>=1){
        # prepare json object
        my %json_progress=();
        $json_progress{'JSONINFO'}="PROGRESS";
        $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_PREFIX_EN'}.
                                     " $user".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_POSTFIX_EN'};
        $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_PREFIX_DE'}.
                                     " $user".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_POSTFIX_DE'};
        $json_progress{'STEP'}=$user_count;
        $json_progress{'FINAL_STEP'}=$max_user_count;
        # print JSON Object
        &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                          json=>$json,
                                                          sophomorix_config=>$ref_sophomorix_config,
                                                        });
    }

    #print Dumper(\$replace);
    if (%replace){
        foreach my $key (keys %replace) {
            if ($update_log_string=~m/\"$/){
                $update_log_string=$update_log_string.",";
            }
            $update_log_string=$update_log_string."\"".$key."=".$replace{$key}."\"";
        }
        # modify
        my $mesg = $ldap->modify( $dn,
	  	          replace => { %replace }
                         );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    print "Logging user update\n";
    &Sophomorix::SophomorixBase::log_user_update({sAMAccountName=>$user,
                                                  unid=>$unid_AD,
                                                  school_old=>$school_AD,
                                                  school_new=>$school,
                                                  update_log_string=>$update_log_string,
                                                  sophomorix_config=>$ref_sophomorix_config,
                                                  sophomorix_result=>$ref_sophomorix_result,
                                                });
    &Sophomorix::SophomorixBase::print_title(
          "Updating User ${user_count}/$max_user_count: $user (end)");
    print "\n";
}



sub AD_user_setquota {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $share_count = $arg_ref->{share_count};
    my $max_share_count = $arg_ref->{max_share_count};
    my $share = $arg_ref->{share};
    my $quota = $arg_ref->{quota};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $debug_level = $arg_ref->{debug_level};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};
    &Sophomorix::SophomorixBase::print_title("Setting Quota for user $user on share $share ($share_count/$max_share_count start):");

    # calculate limits
    my $hard_bytes;
    my $soft_bytes;
    if ($quota==-1){
	$hard_bytes=-1;
	$soft_bytes=-1;
    } else {
        $hard_bytes=1024*1024*$quota; # bytes to MiB
        $soft_bytes=int(0.80*$hard_bytes/1024)*1024;
    }

    my $smbcquotas_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
                          " ".$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS_PROTOCOL_OPT'}.
                          " --debuglevel=$debug_level -U ".$DevelConf::sophomorix_file_admin."%'".
                          $smb_admin_pass."'".
                          " -S UQLIM:".$user.":".$soft_bytes."/".$hard_bytes." //$root_dns/$share";
    print "$smbcquotas_command\n";
    my $stdout=`$smbcquotas_command`;
    my $return=${^CHILD_ERROR_NATIVE}; # return of value of $smbcquotas_command
        if ($return==0){
            chomp($return);
            my ($full_user,$colon,$used,$soft_limit,$hard_limit)=split(/\s+/,$stdout);
            my ($unused,$quota_user)=split(/\\/,$full_user);
            $used=~s/\/$//;
            $hard_limit=~s/\/$//;
            if ($hard_limit eq "NO"){
                $hard_limit="NO LIMIT";
            }
            print "QUOTA COMMAND RETURNED: $quota_user has used $used of $hard_limit\n";
            # update the sophomorixQuota entry at the user
	    my $share_quota=$share.":".$quota;
            print "Updating quota for user $user to $share_quota:\n";
            my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$user);
            &AD_user_update({ldap=>$ldap,
                             root_dse=>$root_dse,
                             dn=>$dn,
                             user=>$user,
                             quota=>$share_quota,     # <share>:<quota_on_share>
                             quota_calc=>$quota,      # what was calculated (same as quota_on_share)
                             quota_info=>$hard_limit, # what was set
                             user_count=>$user_count,
                             max_user_count=>$max_user_count,
                             json=>$json,
                             sophomorix_config=>$ref_sophomorix_config,
                             sophomorix_result=>$ref_sophomorix_result,
                           });
	} else {
            print "ERROR: Setting quota on share $share for user $user failed\n";
        }
    &Sophomorix::SophomorixBase::print_title("Setting Quota of user $user on share $share (end)");
}



sub AD_get_user {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};

    my $filter="(&(objectClass=user) (sAMAccountName=".$user."))";
    #my $filter="(sAMAccountName=".$user.")";
     $mesg = $ldap->search( # perform a search
                    base   => $root_dse,
                    scope => 'sub',
                    filter => $filter,
                    attrs => ['sAMAccountName',
                              'sophomorixAdminClass',
                              'sophomorixExamMode',
                              'sophomorixRole',
                              'givenName',
                              'sn',
                              'homeDirectory',
                              'userAccountControl',
                              'sophomorixTolerationDate',
                              'sophomorixDeactivationDate',
                              'sophomorixSchoolname',
                              'sophomorixStatus',
                              'sophomorixFirstPassword',
                              'sophomorixUnid',
                             ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);

    my $max_user = $mesg->count; 
    my $entry = $mesg->entry(0);
    if (not defined $entry){
        my $existing="FALSE";
        return ("","","",$existing);
    } else {
        my $firstname = $entry->get_value('givenName');
        my $lastname = $entry->get_value('sn');
        my $class = $entry->get_value('sophomorixAdminClass');
        my $role = $entry->get_value('sophomorixRole');
        my $exammode = $entry->get_value('sophomorixExamMode');
        my $home_directory = $entry->get_value('homeDirectory');
        my $user_account_control = $entry->get_value('userAccountControl');
        my $toleration_date = $entry->get_value('sophomorixTolerationDate');
        my $deactivation_date = $entry->get_value('sophomorixDeactivationDate');
        my $school = $entry->get_value('sophomorixSchoolname');
        my $status = $entry->get_value('sophomorixStatus');
        my $firstpassword = $entry->get_value('sophomorixFirstPassword');
        my $unid = $entry->get_value('sophomorixUnid');
        my $existing="TRUE";
        return ($firstname,$lastname,$class,$existing,$exammode,$role,
                $home_directory,$user_account_control,$toleration_date,
                $deactivation_date,$school,$status,$firstpassword,$unid);
    }
}



sub AD_get_group {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $group = $arg_ref->{group};

    my $filter="(&(objectClass=group) (sAMAccountName=".$group."))";
     $mesg = $ldap->search( # perform a search
                    base   => $root_dse,
                    scope => 'sub',
                    filter => $filter,
                    attrs => ['sAMAccountName',
                              'sophomorixSchoolname',
                              'sophomorixType',
                              'sophomorixStatus',
                              'description',
                             ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);

    my $max_group = $mesg->count; 
    my $entry = $mesg->entry(0);
    if (not defined $entry){
        my $existing="FALSE";
        return ($existing,"","","","");
    } else {
        my $existing="TRUE";
        my $type = $entry->get_value('sophomorixType');
        my $school = $entry->get_value('sophomorixSchoolname');
        if ($school eq "---"){
            $school=$DevelConf::name_default_school;
        }
        my $status = $entry->get_value('sophomorixStatus');
        my $description = $entry->get_value('description');
        return ($existing,$type,$school,$status,$description);
    }
}



sub AD_user_move {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};
    my $unid = $arg_ref->{unid};
    my $user_count = $arg_ref->{user_count};
    my $group_old = $arg_ref->{group_old};
    my $group_new = $arg_ref->{group_new};
    my $group_old_basename = $arg_ref->{group_old_basename};
    my $group_new_basename = $arg_ref->{group_new_basename};
    my $school_old = $arg_ref->{school_old};
    my $school_new = $arg_ref->{school_new};
    my $role_old = $arg_ref->{role_old};
    my $role_new = $arg_ref->{role_new};
    my $filename_old = $arg_ref->{filename_old};
    my $filename_new = $arg_ref->{filename_new};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # read from config
    my $group_type_new;
    if (defined $ref_sophomorix_config->{'SCHOOLS'}{$school_new}{'GROUP_TYPE'}{$group_new}){
        $group_type_new=$ref_sophomorix_config->{'SCHOOLS'}{$school_new}{'GROUP_TYPE'}{$group_new};
    } else{
        $group_type_new="adminclass";
    }

    my $prefix_new=$school_new;
    if ($school_new eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix_new="---";
    }

    my $filename;
    if ($filename_new eq "---"){
        $filename=$filename_old;
    } else {
        $filename=$filename_new;
    }

    my $target_branch;
    $school_old=&AD_get_schoolname($school_old);
    $school_new=&AD_get_schoolname($school_new);

    if ($role_new eq "student"){
         $target_branch="OU=".$group_new_basename.",OU=Students,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
    } elsif ($role_new eq "teacher"){
#         $target_branch="OU=".$group_new_basename.",OU=Teachers,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
         $target_branch="OU=Teachers,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
    }

    my ($homedirectory_old,$unix_home_old,$unc_old,$smb_rel_path_old)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school_old,
                                                       $group_old_basename,
                                                       $user,
                                                       $role_old,
                                                       $ref_sophomorix_config);
    my ($homedirectory_new,$unix_home_new,$unc_new,$smb_rel_path_new)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school_new,
                                                       $group_new_basename,
                                                       $user,
                                                       $role_new,
                                                       $ref_sophomorix_config);

    # fetch the dn (where the object really is)
    my ($count,$dn,$rdn)=&AD_object_search($ldap,$root_dse,"user",$user);
    if ($count==0){
        print "\nWARNING: $user not found in ldap, skipping\n\n";
        next;
    }
    my ($count_group_old,
        $dn_group_old,
        $rdn_group_old)=&AD_object_search($ldap,$root_dse,"group",$group_old);
    if ($count_group_old==0){
        print "\nWARNING: Group $group_old not found in ldap, skipping\n\n";
        next;
    }
    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title("Moving user $user ($user_count),(start):");
        print "   DN:             $dn\n";
        print "   Target DN:         $target_branch\n";
        print "   Group (Old):       $group_old ($group_old_basename)\n";
        print "   Group (New):       $group_new ($group_new_basename)\n";
        print "   Role (New):        $role_new\n";
        print "   Type (New):        $group_type_new\n";
        print "   School(Old):       $school_old\n";
        print "   School(New):       $school_new\n";
        print "   Prefix(New):       $prefix_new\n";
        print "   Rename:            $smb_rel_path_old -> $smb_rel_path_new\n";
        print "   filename:          $filename\n";
        print "   homeDirectory:     $homedirectory_new\n";
        print "   unixHomeDirectory: $unix_home_new\n";
    }

    # make sure OU and tree exists
    if (not exists $school_created{$school_new}){
         # create new ou
         &AD_school_create({ldap=>$ldap,
                            root_dse=>$root_dse,
                            root_dns=>$root_dns,
                            school=>$school_new,
                            smb_admin_pass=>$smb_admin_pass,
                            sophomorix_config=>$ref_sophomorix_config,
                            sophomorix_result=>$ref_sophomorix_result,
                          });
         # remember new ou to add it only once
         $school_created{$school_new}="already created";
    } else {
        print "   * OU $school_new already created\n";
    }

    # make sure new group exists
    &AD_group_create({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      group=>$group_new,
                      group_basename=>$group_new_basename,
                      description=>$group_new,
                      school=>$school_new,
                      type=>$group_type_new,
                      joinable=>"TRUE",
                      status=>"P",
                      file=>$filename,
                      smb_admin_pass=>$smb_admin_pass,
                      sophomorix_config=>$ref_sophomorix_config,
                      sophomorix_result=>$ref_sophomorix_result,
                    });

    # update user entry
    my $mesg = $ldap->modify( $dn,
		      replace => {
                          sophomorixAdminClass => $group_new,
                          sophomorixExitAdminClass => $group_old,
                          sophomorixSchoolPrefix => $prefix_new,
                          sophomorixSchoolname => $school_new,
                          sophomorixRole => $role_new,
                          homeDirectory => $homedirectory_new,
                          unixHomeDirectory => $unix_home_new,
                      }
               );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    print "Logging user move\n";
    my $update_log_string="\"GROUP:".$group_old."->".$group_new.",ROLE:".$role_old."->".$role_new."\"";
    &Sophomorix::SophomorixBase::log_user_update({sAMAccountName=>$user,
                                                  unid=>$unid,
                                                  school_old=>$school_old,
                                                  school_new=>$school_new,
                                                  update_log_string=>$update_log_string,
                                                  sophomorix_config=>$ref_sophomorix_config,
                                                  sophomorix_result=>$ref_sophomorix_result,
                                                });



    # remove user from old group
    my ($count_oldclass,$dn_oldclass,$cn_oldclass,$info_oldclass)=&AD_object_search($ldap,$root_dse,"group",$group_old);
    my @old_members_oldgroup = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn_oldclass,"sophomorixMembers");
    my @members_oldgroup = &Sophomorix::SophomorixBase::remove_from_list($user,@old_members_oldgroup);
    my $members_oldgroup=join(",",@members_oldgroup);
    &AD_group_update({ldap=>$ldap,
                      root_dse=>$root_dse,
                      dn=>$dn_oldclass,
                      type=>"adminclass",
                      members=>$members_oldgroup,
                      sophomorix_config=>$ref_sophomorix_config,
                    });
    # add user to new group 
    my ($count_newclass,$dn_newclass,$cn_newclass,$info_newclass)=&AD_object_search($ldap,$root_dse,"group",$group_new);
    my @old_members_newgroup = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn_newclass,"sophomorixMembers");
    # create a unique list of new members
    my @members_newgroup = uniq(@old_members_newgroup,$user); 
    my $members_newgroup=join(",",@members_newgroup);
    # update project
    &AD_group_update({ldap=>$ldap,
                      root_dse=>$root_dse,
                      dn=>$dn_newclass,
                      type=>"adminclass",
                      members=>$members_newgroup,
                      sophomorix_config=>$ref_sophomorix_config,
                    });
    # move the object in ldap tree
    &AD_object_move({ldap=>$ldap,
                     dn=>$dn,
                     rdn=>$rdn,
                     target_branch=>$target_branch,
                    });

    # change management groups if school changes
    if ($school_old ne $school_new){
        &Sophomorix::SophomorixBase::print_title("School $school_old --> $school_new, managment groups change (start)");
        my @grouplist=("wifi","internet","webfilter","intranet","printing");
        # removing
        foreach my $group (@grouplist){
            my $management_group=&AD_get_name_tokened($group,$school_old,"management");
            &AD_group_removemember({ldap => $ldap,
                                    root_dse => $root_dse, 
                                    group => $management_group,
                                    removemember => $user,
                                    sophomorix_config=>$ref_sophomorix_config,
                                   });   
        }
        # adding
        foreach my $group (@grouplist){
            my $management_group=&AD_get_name_tokened($group,$school_new,"management");
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $management_group,
                                            addmember => $user,
                                           }); 
        }
        &Sophomorix::SophomorixBase::print_title("School $school_old --> $school_new, managment groups change (start)");
    }


    # move the home directory of the user
    if ($school_old eq $school_new){
        # this is on the same share
        # smbclient ... rename (=move)
#        my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
#                               " -U Administrator%'<password>'".
#                              " //$root_dns/$school_old -c 'rename $smb_rel_path_old $smb_rel_path_new'";
        my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                              " -U ".$DevelConf::sophomorix_file_admin."%'".$smb_admin_pass."'".
                              " //$root_dns/$school_old -c 'rename $smb_rel_path_old $smb_rel_path_new'";
        print "$smbclient_command\n";
        system($smbclient_command);
    } else {
        # this is dirty and works only if the shares are on the same server
        # ????????????????????????????

        my $mv="mv $unix_home_old $unix_home_new";
        print "Moving Home: $mv\n";
        system($mv);
    }

    # fixing the acls on the new home
    if ($role_new eq "student"){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.student_home",
                               school=>$school_new,
                               adminclass=>$group_new,
                               student_home=>$user,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($role_new eq "teacher"){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.teacher_home",
                               school=>$school_new,
                               teacherclass=>$group_new,
                               teacher_home=>$user,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    }
    &Sophomorix::SophomorixBase::print_title("Moving user $user ($user_count),(end)");
    print "\n";
}



sub AD_get_schoolname {
    my ($ou) = @_;
    if ($ou eq "---"){
        my $string=$DevelConf::name_default_school;
        $ou=$string;
    }
    return $ou;
}



sub AD_get_name_tokened {
    # $role is: group type / user role
    # prepend <token> or not, depending on the users role/groups type 
    my ($name,$school,$role) = @_;
    my $name_tokened="";
    if ($role eq "adminclass" or 
        $role eq "extraclass" or 
        $role eq "teacherclass" or
        $role eq "all" or
        $role eq "room" or 
        $role eq "roomws" or
        $role eq "examaccount" or
        $role eq "computer" or
        $role eq "project" or
        $role eq "management" or
        $role eq "administrator" or
        $role eq "sophomorix-group" or
        $role eq "group"){
        if ($school eq "---" 
            or $school eq ""
            or $school eq $DevelConf::name_default_school
           ){
            # SCHOOL, no multischool
            $name_tokened=$name;
        } else {
            # multischool
            if ($DevelConf::token_postfix==0){
                # prefix
                $name_tokened=$school."-".$name;
            } elsif ($DevelConf::token_postfix==1){
                # postfix
                $name_tokened=$name."-".$school;
            }
        }
        if ($role eq "computer"){
            # make uppercase
            $name_tokened=~tr/a-z/A-Z/;
        }
        if ($role eq "project"){
            unless ($name_tokened =~ m/^p\_/) { 
                # add prefix to projects: p_ 
                $name_tokened="p_".$name_tokened;
            }
        }
        return $name_tokened;
    } elsif ($role eq "teacher" or
             $role eq "student"){
        return $name;
    } else {
        return $name;
    }
}



sub AD_school_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_result = $arg_ref->{sophomorix_result};
    my $gidnumber_wish;

    $school=&AD_get_schoolname($school);

    print "\n";
    &Sophomorix::SophomorixBase::print_title("Testing smb shares ...");
    ############################################################
    # providing smb shares
    ############################################################
    # global share
    if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}}){
        print "   * Nothing to do: Global share $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'} exists.\n";
    } else {
        &Sophomorix::SophomorixBase::print_title("Creating $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}");
        system("mkdir -p $DevelConf::homedir_global");
        my $command="net conf addshare ".
                    $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}." ".
                    $DevelConf::homedir_global.
                    " writeable=y guest_ok=N 'Share for school global'";
        print "   * $command\n";
        system($command);
        my $command_mod1="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
# ??????
#                         " 'msdfs root' 'yes'";
                         " 'msdfs root' 'no'";
        print "   * $command_mod1\n";
        system($command_mod1);
        my $command_mod2="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
                         " 'hide unreadable' 'yes'";
        print "   * $command_mod2\n";
        system($command_mod2);
	my $groupstring=$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}.
                        "\\".$DevelConf::sophomorix_file_admin.
                        ", \@".$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}."\\SCHOOLS";
        my $command_mod3="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
                         " 'valid users' '$groupstring'";
        print "   * $command_mod3\n";
        system($command_mod3);
        my $command_mod4="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
                         " 'strict allocate' 'yes'";
        print "   * $command_mod4\n";
        system($command_mod4);

        &Sophomorix::SophomorixBase::read_smb_net_conf_list($ref_sophomorix_config);
    }

    # school share
    if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}){
        print "   * nothing to do: School share $school exists.\n";
    } else {
        &Sophomorix::SophomorixBase::print_title("Creating share for school $school");
        my $unix_path=$DevelConf::homedir_all_schools."/".$school;
        system("mkdir -p $unix_path");
        my $command="net conf addshare ".
                    $school." ".
                    $unix_path.
                    " writeable=y guest_ok=N 'Share for school $school'";
        print "   * $command\n";
        system($command);
        my $command_mod1="net conf setparm ".$school.
# ?????
#                         " 'msdfs root' 'yes'";
                         " 'msdfs root' 'no'";
        print "   * $command_mod1\n";
        system($command_mod1);

        my $command_mod2="net conf setparm ".$school.
                         " 'hide unreadable' 'yes'";
        print "   * $command_mod2\n";
        system($command_mod2);
        my $groupstring=$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}.
                        "\\".$DevelConf::sophomorix_file_admin.
                        ", \@".$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}."\\".$school.
                        ", \@".$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}."\\global-admins";
        my $command_mod3="net conf setparm ".$school.
                         " 'valid users' '$groupstring'";
        print "   * $command_mod3\n";
        system($command_mod3);
        my $command_mod4="net conf setparm ".$school.
                         " 'strict allocate' 'yes'";
        print "   * $command_mod4\n";
        system($command_mod4);

        &Sophomorix::SophomorixBase::read_smb_net_conf_list($ref_sophomorix_config);
    }

    &Sophomorix::SophomorixBase::print_title("Adding school $school in AD (begin) ...");
    ############################################################
    # providing OU=SCHOOLS 
    ############################################################
    my $schools_ou=$DevelConf::AD_schools_ou.",".$root_dse;
    my $result1 = $ldap->add($schools_ou,
                        attr => ['objectClass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result1,2,(caller(0))[3]);
    ############################################################
    # providing group 'SCHOOLS'
    ############################################################
    my $dn_schools="CN=".$DevelConf::AD_schools_group.",".$DevelConf::AD_schools_ou.",".$root_dse;
    &AD_group_create({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      dn_wish=>$dn_schools,
                      school=>$DevelConf::AD_schools_group,
                      group=>$DevelConf::AD_schools_group,
                      group_basename=>$DevelConf::AD_schools_group,
                      description=>"The group that includes all schools",
                      type=>$ref_sophomorix_config->{'INI'}{'SCHOOLS'}{'SCHOOL_GROUP_TYPE'},
                      status=>"P",
                      joinable=>"FALSE",
                      hidden=>"FALSE",
                      smb_admin_pass=>$smb_admin_pass,
                      sophomorix_config=>$ref_sophomorix_config,
                      sophomorix_result=>$ref_sophomorix_result,
                     });
    ############################################################
    # providing the OU=<school>,OU=SCHOOLS for schools
    ############################################################
    my $result2 = $ldap->add($ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP},
                        attr => ['objectClass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result1,2,(caller(0))[3]);
    ############################################################
    # providing group <schoolname>
    ############################################################
    my $dn_schoolname="CN=".$school.",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    print "$dn_schoolname\n";
    &AD_group_create({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      dn_wish=>$dn_schoolname,
                      school=>$school,
                      group=>$school,
                      group_basename=>$school,
                      description=>"The school group of school ".$school,
                      type=>"school",
                      status=>"P",
                      joinable=>"FALSE",
                      hidden=>"FALSE",
                      smb_admin_pass=>$smb_admin_pass,
                      sophomorix_config=>$ref_sophomorix_config,
                      sophomorix_result=>$ref_sophomorix_result,
                     });
    # make group <schoolname> member in SCHOOLS
    &AD_group_addmember({ldap => $ldap,
                         root_dse => $root_dse, 
                         group => $DevelConf::AD_schools_group,
                         addgroup => $school,
                        }); 
    ############################################################
    # sub ou's for OU=*    
    if($Conf::log_level>=2){
        print "   * Adding sub ou's for OU=$school ...\n";
    }
    foreach my $ref_sub_ou (@{ $ref_sophomorix_config->{'INI'}{'SCHOOLS'}{'SUB_OU'} } ){
        my $sub_ou=$ref_sub_ou; # make copy to not modify the hash 
        $dn=$sub_ou.",".$ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP};
        print "      * DN: $dn (RT_SCHOOL_OU) $school\n";
        my $result = $ldap->add($dn,attr => ['objectClass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    ############################################################
    # OU=*    
    if($Conf::log_level>=2){
        print "   * Adding OU's for default groups in OU=$school ...\n";
    }

    &AD_create_school_groups($ldap,$root_dse,$root_dns,$smb_admin_pass,
                             $school,$ref_sophomorix_config);
    ############################################################
    # adding groups to <schoolname>-group
    foreach my $ref_membergroup (@{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'SCHOOLGROUP_MEMBERGROUPS'} } ){
    my $membergroup=$ref_membergroup; # make copy to not modify the hash 
    &AD_group_addmember({ldap => $ldap,
                         root_dse => $root_dse, 
                         group => $school,
                         addgroup => $membergroup,
                        }); 
    }

    ############################################################
    # providing OU=GLOBAL
    ############################################################
    my $result3 = $ldap->add($ref_sophomorix_config->{$DevelConf::AD_global_ou}{OU_TOP},
                        attr => ['objectClass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result3,2,(caller(0))[3]);
    ############################################################
    # sub ou's for OU=GLOBAL    
    if($Conf::log_level>=2){
        print "   * Adding sub ou's for OU=$DevelConf::AD_global_ou ...\n";
    }
    foreach my $sub_ou (@{ $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SUB_OU'} } ){
        $dn=$sub_ou.",".$ref_sophomorix_config->{$DevelConf::AD_global_ou}{OU_TOP};
        print "      * DN: $dn\n";
        my $result = $ldap->add($dn,attr => ['objectClass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    ############################################################
    # OU=GLOBAL    
    if($Conf::log_level>=2){
        print "   * Adding OU's for default groups in OU=$school ...\n";
    }

    &AD_create_school_groups($ldap,$root_dse,$root_dns,$smb_admin_pass,
                             $DevelConf::AD_global_ou,$ref_sophomorix_config,$root_dse);

    # all groups created, add some memberships from GLOBAL
    foreach my $group (keys %{$ref_sophomorix_config->{'GLOBAL'}{'GROUP_MEMBEROF'}}) {
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'GLOBAL'}{'GROUP_MEMBEROF'}{$group},
                             addgroup => $group,
                            }); 
    }
    # all groups created, add some memberships from SCHOOLS
    foreach my $group (keys %{$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_MEMBEROF'}}) {
       &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_MEMBEROF'}{$group},
                             addgroup => $group,
                            }); 
    }

    # school
    &AD_create_school_groups($ldap,$root_dse,$root_dns,$smb_admin_pass,
                             $school,$ref_sophomorix_config);
    # global
    &AD_create_school_groups($ldap,$root_dse,$root_dns,$smb_admin_pass,
                             $DevelConf::AD_global_ou,$ref_sophomorix_config,$root_dse);

    # creating fileystem at last, because groups are needed beforehand for the ACL's 
    # creating filesystem for school
    &AD_repdir_using_file({root_dns=>$root_dns,
                           repdir_file=>"repdir.school",
                           school=>$school,
                           smb_admin_pass=>$smb_admin_pass,
                           sophomorix_config=>$ref_sophomorix_config,
                           sophomorix_result=>$ref_sophomorix_result,
                        });
    # creating filesystem for global
    &AD_repdir_using_file({ldap=>$ldap,
                           root_dns=>$root_dns,
                           repdir_file=>"repdir.global",
                           school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                           smb_admin_pass=>$smb_admin_pass,
                           sophomorix_config=>$ref_sophomorix_config,
                           sophomorix_result=>$ref_sophomorix_result,
                         });
    &Sophomorix::SophomorixBase::print_title("Adding school $school in AD (end) ...");
    print "\n";
}



sub AD_create_school_groups {
    my ($ldap,$root_dse,$root_dns,$smb_admin_pass,$school,$ref_sophomorix_config) = @_;
    if ($school eq $DevelConf::AD_global_ou){
        foreach my $dn (keys %{$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_CN'}}) {
            # create ou for group
            my $group=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_CN'}{$dn};
            my $description="LMN Group, change if you like";
            my $type=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_TYPE'}{$group};
            my $school=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'SCHOOL'};
            # create
            &AD_group_create({ldap=>$ldap,
                              root_dse=>$root_dse,
                              root_dns=>$root_dns,
                              dn_wish=>$dn,
                              school=>$school,
                              group=>$group,
                              group_basename=>$group,
                              description=>$description,
                              type=>$type,
                              status=>"P",
                              joinable=>"TRUE",
                              hidden=>"FALSE",
                              smb_admin_pass=>$smb_admin_pass,
                              sophomorix_config=>$ref_sophomorix_config,
                              sophomorix_result=>$ref_sophomorix_result,
                            });
        }
    } else {
        foreach my $dn (keys %{$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_CN'}}) {
            # create ou for group
            my $group=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_CN'}{$dn};
            my $description="LMN Group, change if you like";
            my $type=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_TYPE'}{$group};
            my $school=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'SCHOOL'};
            # create
            &AD_group_create({ldap=>$ldap,
                              root_dse=>$root_dse,
                              root_dns=>$root_dns,
                              dn_wish=>$dn,
                              school=>$school,
                              group=>$group,
                              group_basename=>$group,
                              description=>$description,
                              type=>$type,
                              status=>"P",
                              joinable=>"TRUE",
                              hidden=>"FALSE",
                              smb_admin_pass=>$smb_admin_pass,
                              sophomorix_config=>$ref_sophomorix_config,
                              sophomorix_result=>$ref_sophomorix_result,
                            });
        }
    }
}


sub AD_object_search {
    my ($ldap,$root_dse,$objectclass,$name) = @_;
    # returns 0,"" or 1,"dn of object"
    # objectClass: group, user, ...
    # check if object exists
    # (&(objectClass=user)(cn=pete)
    # (&(objectClass=group)(cn=7a)
    my $filter;
    my $base;
    if ($objectclass eq "dnsNode" or $objectclass eq "dnsZone"){
        # searching dnsNode
        $base="DC=DomainDnsZones,".$root_dse;
        $filter="(&(objectClass=".$objectclass.") (name=".$name."))"; 
    } elsif  ($objectclass eq "all"){
        # find all 
        $base=$root_dse;
        $filter="(cn=".$name.")"; 
    } else {
        $base=$root_dse;
        $filter="(&(objectClass=".$objectclass.") (cn=".$name."))"; 
    }

    my $mesg = $ldap->search(
                      base   => $base,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['cn']
                            );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $count = $mesg->count;
    if ($count > 0){
        # process first entry
        my ($entry,@entries) = $mesg->entries;
        my $dn = $entry->dn();
        my $cn;
        if (defined $entry->get_value ('cn')){
            $cn = $entry->get_value ('cn');
            $cn="CN=".$cn;
        } else {
            $cn="CN=---";
        } 
        my $info="no sophomorix info available (Role, Type)";
        if ($objectclass eq "group"){
            $info = $entry->get_value ('sophomorixType');
        } elsif ($objectclass eq "user"){
            $info = $entry->get_value ('sophomorixRole');
        } elsif ($objectclass eq "dnsZone"){
            $info = $entry->get_value ('adminDescription');
        } elsif ($objectclass eq "dnsNode"){
            $info = $entry->get_value ('adminDescription');
        }
        return ($count,$dn,$cn,$info);
    } else {
        return (0,"","");
    }
}



sub AD_get_sessions {
    my ($ldap,$root_dse,$root_dns,$json,$show_session,$smb_admin_pass,$ref_sophomorix_config)=@_;
    my %sessions=();
    my %management=();
    my $session_count=0;
    { # begin bock
	my $filter="(& (objectClass=group) (| ";
        foreach my $grouptype (@{ $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'} }){
            $filter=$filter."(sophomorixType=".$grouptype.")";
        }
        $filter=$filter." ) )";
        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['sAMAccountName',
                                  'sophomorixSchoolname',
                                  'sophomorixStatus',
                                  'sophomorixType',
                                  'member',
                                 ]);
        my $max_mangroups = $mesg->count;
        &Sophomorix::SophomorixBase::print_title("$max_mangroups managementgroups found in AD");
        for( my $index = 0 ; $index < $max_mangroups ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$management{'managementgroup'}{$type}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
            $management{'managementgroup'}{$type}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # members
            # creating member lookup table
            my @man_members=$entry->get_value('member');
            foreach my $member (@man_members){
                my ($sam_user,@unused)=split(/,/,$member);
                $sam_user=~s/^CN=//g; # remove leading CN=
                $management{'managementgroup'}{$type}{$sam}{'members'}{$sam_user}=$member;
            }
        }
    } # end block

    # fetching the sessions
    my $filter="(&(objectClass=user)(sophomorixSessions=*)(|(sophomorixRole=student)(sophomorixRole=teacher)))";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName',
                             'sophomorixSessions',
                             'sophomorixRole',
                             'givenName',
                             'sn',
                             'sophomorixSchoolname',
                             'sophomorixExamMode',
                             'sophomorixStatus',
                             'homeDirectory',
                            ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max_user = $mesg->count; 
    if($Conf::log_level>=2){
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix users have sessions");
    }

    $AD{'RESULT'}{'supervisor'}{'student'}{'COUNT'}=$max_user;

    # walk through all supervisors
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        my $supervisor=$entry->get_value('sAMAccountName');
        my @session_list = sort $entry->get_value('sophomorixSessions');
        if($Conf::log_level>=2){
            my $user_session_count=$#session_list+1;
            print "   * User $supervisor has $user_session_count sessions\n";
	}
        # walk through all sessions of the user
        foreach my $session (@session_list){
            $session_count++;
            if($Conf::log_level>=2){
                &Sophomorix::SophomorixBase::print_title("$session_count: User $supervisor has session $session");
            }
            my ($id,$comment,$participants,$string)=split(/;/,$session);

            if ($show_session eq "all" or $id eq $show_session){
                # just go on
                if($Conf::log_level>=2){
                    print "   * Loading partial data of session $id.\n";
                }
            
                # calculate smb_dir
                my $smb_dir=$entry->get_value('homeDirectory');
                $smb_dir=~s/\\/\//g;
                my $transfer=$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'TRANSFER_DIR_HOME_'.
                             $ref_sophomorix_config->{'GLOBAL'}{'LANG'}};
                $smb_dir="smb:".$smb_dir."/".$transfer;
		#print "SMB: $smb_dir\n";

                # save supervisor information
                #--------------------------------------------------
                # save by user
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'sophomorixSessions'}=$session;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'COMMENT'}=$comment;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTSTRING'}=$participants;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixRole'}=$entry->get_value('sophomorixRole');
                $sessions{'SUPERVISOR'}{$supervisor}{'givenName'}=$entry->get_value('givenName');
                $sessions{'SUPERVISOR'}{$supervisor}{'sn'}=$entry->get_value('sn');
                $sessions{'SUPERVISOR'}{$supervisor}{'homeDirectory'}=$entry->get_value('homeDirectory');
                $sessions{'SUPERVISOR'}{$supervisor}{'SMBhomeDirectory'}=$smb_dir;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixExamMode'}=$entry->get_value('sophomorixExamMode');
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
                push @{ $sessions{'SUPERVISOR_LIST'} }, $supervisor; 
                # save by id
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sAMAccountName'}=$supervisor;
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixRole'}=$entry->get_value('sophomorixRole');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'givenName'}=$entry->get_value('givenName');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sn'}=$entry->get_value('sn');
                $sessions{'ID'}{$id}{'sophomorixSessions'}=$session;
                $sessions{'ID'}{$id}{'COMMENT'}=$comment;
                $sessions{'ID'}{$id}{'PARTICIPANTSTRING'}=$participants;
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'homeDirectory'}=$entry->get_value('homeDirectory');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'SMBhomeDirectory'}=$smb_dir;
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixExamMode'}=$entry->get_value('sophomorixExamMode');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
                push @{ $sessions{'ID_LIST'} }, $id; 

                # save participant information
                #--------------------------------------------------
                my @participants=split(/,/,$participants);
                if ($#participants==-1){
                    # skip user detection when participantlist is empty
                    next;
                }

                foreach $participant (@participants){
                    # get userinfo
                    my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
                        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,
                        $deactivation_date_AD,$school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
                        &AD_get_user({ldap=>$ldap,
                                      root_dse=>$root_dse,
                                      root_dns=>$root_dns,
                                      user=>$participant,
				     });
		    if ($existing_AD eq "FALSE"){
 		        print "WARNING: User $participant nonexisting but part of session $id\n";
                        $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'user_existing'}=$existing_AD;
                        $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'user_existing'}=$existing_AD;
                        next;
		    }
                    if ($exammode_AD ne "---"){
                        # display exam-account
                        $participant=$participant.$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'};
                        
                        # get data again
                        ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
                        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,
                        $deactivation_date_AD,$school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
                        &AD_get_user({ldap=>$ldap,
                                      root_dse=>$root_dse,
                                      root_dns=>$root_dns,
                                      user=>$participant,
                                    });
                    }

                    # calculate smb_dir
                    my $smb_dir=$home_directory_AD;
                    $smb_dir=~s/\\/\//g;
                    my $transfer=$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'TRANSFER_DIR_HOME_'.
                                 $ref_sophomorix_config->{'GLOBAL'}{'LANG'}};
                    $smb_dir="smb:".$smb_dir."/".$transfer;
		    #print "SMB: $smb_dir\n";

                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'givenName'}=$firstname_utf8_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sn'}=$lastname_utf8_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixAdminClass'}=$adminclass_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'user_existing'}=$existing_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixRole'}=$role_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixExamMode'}=$exammode_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixStatus'}=$status_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'homeDirectory'}=$home_directory_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'SMBhomeDirectory'}=$smb_dir;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixSchoolname'}=$school_AD;
                    push @{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} }, $participant; 

                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'givenName'}=$firstname_utf8_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sn'}=$lastname_utf8_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixAdminClass'}=$adminclass_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'user_existing'}=$existing_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixExamMode'}=$exammode_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixStatus'}=$status_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixRole'}=$role_AD;
                    push @{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} }, $participant; 

                    # test membership in managementgroups
                    foreach my $grouptype (@{ $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'} }){
                        # befor testing set FALSE as default
                        $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{"group_".$grouptype}="FALSE";
                        $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}
                                 {'PARTICIPANTS'}{$participant}{"group_".$grouptype}="FALSE";
                        foreach my $group (keys %{$management{'managementgroup'}{$grouptype}}) {
                           if (exists $management{'managementgroup'}{$grouptype}{$group}{'members'}{$participant}){
                                # if in the groups, set TRUE
                                $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{"group_".$grouptype}="TRUE";
                                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}
                                         {'PARTICIPANTS'}{$participant}{"group_".$grouptype}="TRUE";
                            }
                        }
                    }
                }

                # sort some lists and count
		if ( exists $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} ){
                    @{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} } = sort @{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} };
                }
                $sessions{'ID'}{$id}{'PARTICIPANT_COUNT'}=$#{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} }+1;
                if (exists $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'}){
		    @{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} } = 
                        sort @{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} };
                }
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_COUNT'}=
                    $#{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} }+1;

                # save extended information
                #--------------------------------------------------
                if ($id eq $show_session){
                    if($Conf::log_level>=2){
                        print "   * Loading extended data of selected session $id.\n";
                    }
                    # transfer directory of supervisor
                    my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
                        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,
                        $deactivation_date_AD,$school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
                    &AD_get_user({ldap=>$ldap,
                                  root_dse=>$root_dse,
                                  root_dns=>$root_dns,
                                  user=>$sessions{'ID'}{$show_session}{'SUPERVISOR'}{'sAMAccountName'},
                                });

                    &Sophomorix::SophomorixBase::dir_listing_user($sessions{'ID'}{$show_session}{'SUPERVISOR'}{'sAMAccountName'},
                                                                  $sessions{'ID'}{$show_session}{'SUPERVISOR'}{'SMBhomeDirectory'},
                                                                  $smb_admin_pass,
                                                                  \%sessions,
                                                                  $ref_sophomorix_config
                                                                 );

                    # participants
                    foreach my $participant (keys %{$sessions{'ID'}{$id}{'PARTICIPANTS'}}) {
                        # managementgroups

#                        $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'user_existing'}=$existing_AD;
                        if ($sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'user_existing'} eq "FALSE"){
 		            print "WARNING: $participant nonexisting (Skipping  dirlisting and quota)\n";
                            next;
			}

                        # transfer directory of participants 
                        &Sophomorix::SophomorixBase::dir_listing_user(
                                       $participant,
                                       $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'SMBhomeDirectory'},
                                       $smb_admin_pass,
                                       \%sessions,
                                       $ref_sophomorix_config
                                       );
                        # quota
                        &Sophomorix::SophomorixBase::quota_listing_session_participant($participant,
                                                                                       $show_session,
                                                                                       $supervisor,
                                                                                       \%sessions);
                    }
                }         
            } else { #neither all nor the requested session
                # skip this session
                if($Conf::log_level>=2){
                    print "   * Session $id was not requested.\n";
                }            
                next;
            }
        }
    }
    $sessions{'SESSIONCOUNT'}=$session_count;
    @{ $sessions{'SUPERVISOR_LIST'} }=uniq(@{ $sessions{'SUPERVISOR_LIST'} });
    &Sophomorix::SophomorixBase::print_title("$session_count running sessions found");
    return %sessions; 
}



sub AD_get_AD {
    my %AD=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my $users = $arg_ref->{users};
    if (not defined $users){$users="FALSE"};

    my $adminclasses = $arg_ref->{adminclasses};
    if (not defined $adminclasses){$adminclasses="FALSE"};

    my $teacherclasses = $arg_ref->{teacherclasses};
    if (not defined $teacherclasses){$teacherclasses="FALSE"};

    my $administratorclasses = $arg_ref->{administratorclasses};
    if (not defined $administratorclasses){$administratorclasses="FALSE"};

    my $projects = $arg_ref->{projects};
    if (not defined $projects){$projects="FALSE"};

    my $computers = $arg_ref->{computers};
    if (not defined $computers){$computers="FALSE"};

    my $rooms = $arg_ref->{rooms};
    if (not defined $rooms){$rooms="FALSE"};

    my $management = $arg_ref->{management};
    if (not defined $management){$management="FALSE"};

    #my $examaccounts = $arg_ref->{examaccounts};
    #if (not defined $examaccounts){$examaccounts="FALSE"};

    my $dnszones = $arg_ref->{dnszones};
    if (not defined $dnszones){$dnszones="FALSE"};

    my $dnsnodes = $arg_ref->{dnsnodes};
    if (not defined $dnsnodes){
        $dnsnodes="FALSE"
    } else {
        # dnsZones are needed to get dnsNodes
        $dnszones="TRUE";
    }

    # make sure adminclass lists exist, when users are added
    if($users eq "TRUE"){
        $adminclasses="TRUE";
        $teacherclasses="TRUE";
        $projects="TRUE";
    }
    # make sure room lists exist, when computers are added
    if($computers eq "TRUE"){
        $rooms="TRUE";
    }


    ##################################################
    if ($adminclasses eq "TRUE"){
        # sophomorixType adminclass/extraclass from ldap
        my $filter="(& (objectClass=group) (| ".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'EXTRACLASS'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINCLASS'}.")".
           " ) )";
        
        #print "FILTER: $filter\n";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_adminclass = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_adminclass sophomorix adminclasses found in AD");
        $AD{'RESULT'}{'group'}{'class'}{'COUNT'}=$max_adminclass;
        for( my $index = 0 ; $index < $max_adminclass ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            $AD{'objectclass'}{'group'}{$type}{$sam}{'room'}=$sam;
            $AD{'objectclass'}{'group'}{$type}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{$type}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{$type}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
#            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'LISTS'}{$type} }; # make list computer empty to allow sort  
#        @{ $AD{'LISTS'}{$type} } = sort @{ $AD{'LISTS'}{$type} }; 
    }


    ##################################################
    if ($teacherclasses eq "TRUE"){
        # sophomorixType teacherclass from ldap
        my $filter="(&(objectClass=group)(sophomorixType=".
           $ref_sophomorix_config->{'INI'}{'TYPE'}{'TEACHERCLASS'}."))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_teacherclass = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_teacherclass sophomorix teacherclasses found in AD");
        $AD{'RESULT'}{'group'}{'teacherclass'}{'COUNT'}=$max_teacherclass;
        for( my $index = 0 ; $index < $max_teacherclass ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'room'}=$sam;
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
#            push @{ $AD{'LISTS'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'LISTS'}{'teacherclass'} }; # make list computer empty to allow sort  
#        @{ $AD{'LISTS'}{'teacherclass'} } = sort @{ $AD{'LISTS'}{'teacherclass'} }; 
    }

    ##################################################
    if ($administratorclasses eq "TRUE"){
        # sophomorixType teacherclass from ldap
        my $filter="(&(objectClass=group)(|(sophomorixType=".
           $ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINS'}.") (sophomorixType=".
           $ref_sophomorix_config->{'INI'}{'TYPE'}{'ALLADMINS'}.") (sophomorixType=".
           $ref_sophomorix_config->{'INI'}{'TYPE'}{'POWERGROUP'}.")))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_teacherclass = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_teacherclass sophomorix admins found in AD");
        $AD{'RESULT'}{'group'}{'teacherclass'}{'COUNT'}=$max_teacherclass;
        for( my $index = 0 ; $index < $max_teacherclass ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'room'}=$sam;
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'teacherclass'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
#            push @{ $AD{'LISTS'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'LISTS'}{'teacherclass'} }; # make list computer empty to allow sort  
#        @{ $AD{'LISTS'}{'teacherclass'} } = sort @{ $AD{'LISTS'}{'teacherclass'} }; 
    }

    ##################################################
    if ($projects eq "TRUE"){
        # sophomorixType projects from ldap
        my $filter="(&(objectClass=group)(sophomorixType=".
           $ref_sophomorix_config->{'INI'}{'TYPE'}{'PROJECT'}."))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_project = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_project sophomorix projects found in AD");
        $AD{'RESULT'}{'group'}{'project'}{'COUNT'}=$max_project;
        for( my $index = 0 ; $index < $max_project ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            $AD{'objectclass'}{'group'}{'project'}{$sam}{'room'}=$sam;
            $AD{'objectclass'}{'group'}{'project'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'project'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'project'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
#            push @{ $AD{'LISTS'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'LISTS'}{'teacherclass'} }; # make list computer empty to allow sort  
#        @{ $AD{'LISTS'}{'teacherclass'} } = sort @{ $AD{'LISTS'}{'teacherclass'} }; 
    }


    ##################################################
    if ($users eq "TRUE"){
        # sophomorix students,teachers, ... from ldap
        my $filter="(&(objectClass=user)(|(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'STUDENT'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'TEACHER'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'GLOBALADMINISTRATOR'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'SCHOOLADMINISTRATOR'}.")))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixAdminClass',
                                 'givenName',
                                 'sn',
                                 'sophomorixFirstnameASCII',
                                 'sophomorixSurnameASCII',
                                 'sophomorixBirthdate',
                                 'sophomorixStatus',
                                 'sophomorixSchoolname',
                                 'sophomorixSchoolPrefix',
                                 'sophomorixAdminFile',
                                 'sophomorixTolerationDate',
                                 'sophomorixDeactivationDate',
                                 'sophomorixUnid',
                                 'sophomorixRole',
                                 'userAccountControl',
                                ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix students found in AD");
        $AD{'RESULT'}{'user'}{'student'}{'COUNT'}=$max_user;
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $role=$entry->get_value('sophomorixRole');
            my $adminclass=$entry->get_value('sophomorixAdminClass');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixAdminClass'}=$adminclass;
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixFirstnameASCII'}=
                $entry->get_value('sophomorixFirstnameASCII');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixSurnameASCII'}=
                $entry->get_value('sophomorixSurnameASCII');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'givenName'}=
                $entry->get_value('givenName');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sn'}=
                $entry->get_value('sn');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixBirthdate'}=
                $entry->get_value('sophomorixBirthdate');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixStatus'}=
                $entry->get_value('sophomorixStatus');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixSchoolname'}=
                $entry->get_value('sophomorixSchoolname');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixPrefix'}=
                $entry->get_value('sophomorixPrefix');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixAdminFile'}=
                $entry->get_value('sophomorixAdminFile');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixTolerationDate'}=
                $entry->get_value('sophomorixTolerationDate');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixDeactivationDate'}=
                $entry->get_value('sophomorixDeactivationDate');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixUnid'}=
                $entry->get_value('sophomorixUnid');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixRole'}=
                $entry->get_value('sophomorixRole');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'userAccountControl'}=
                $entry->get_value('userAccountControl');

            # calculate identifiers
            my $identifier_ascii=
               $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixSurnameASCII'}
               .";".
               $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixFirstnameASCII'}
               .";".
               $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixBirthdate'};
            $AD{'objectclass'}{'user'}{$role}{$sam}{'IDENTIFIER_ASCII'}=$identifier_ascii;
            my $identifier_utf8=
               $AD{'objectclass'}{'user'}{$role}{$sam}{'sn'}
               .";".
               $AD{'objectclass'}{'user'}{$role}{$sam}{'givenName'}
               .";".
               $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixBirthdate'};
            $AD{'objectclass'}{'user'}{$role}{$sam}{'IDENTIFIER_UTF8'}=$identifier_utf8;

            # new: by sam
            $AD{'sAMAccountName'}{$sam}{'sophomorixAdminClass'}=
                $entry->get_value('sophomorixAdminClass');
            $AD{'sAMAccountName'}{$sam}{'sophomorixFirstnameASCII'}=
                $entry->get_value('sophomorixFirstnameASCII');
            $AD{'sAMAccountName'}{$sam}{'sophomorixSurnameASCII'}=
                $entry->get_value('sophomorixSurnameASCII');
            $AD{'sAMAccountName'}{$sam}{'givenName'}=
                $entry->get_value('givenName');
            $AD{'sAMAccountName'}{$sam}{'sn'}=
                $entry->get_value('sn');
            $AD{'sAMAccountName'}{$sam}{'sophomorixBirthdate'}=
                $entry->get_value('sophomorixBirthdate');
            $AD{'sAMAccountName'}{$sam}{'sophomorixStatus'}=
                $entry->get_value('sophomorixStatus');
            $AD{'sAMAccountName'}{$sam}{'sophomorixSchoolname'}=
                $entry->get_value('sophomorixSchoolname');
            $AD{'sAMAccountName'}{$sam}{'sophomorixPrefix'}=
                $entry->get_value('sophomorixPrefix');
            $AD{'sAMAccountName'}{$sam}{'sophomorixAdminFile'}=
                $entry->get_value('sophomorixAdminFile');
            $AD{'sAMAccountName'}{$sam}{'sophomorixTolerationDate'}=
                $entry->get_value('sophomorixTolerationDate');
            $AD{'sAMAccountName'}{$sam}{'sophomorixDeactivationDate'}=
                $entry->get_value('sophomorixDeactivationDate');
            $AD{'sAMAccountName'}{$sam}{'sophomorixUnid'}=
                $entry->get_value('sophomorixUnid');
            $AD{'sAMAccountName'}{$sam}{'sophomorixRole'}=
                $entry->get_value('sophomorixRole');
            $AD{'sAMAccountName'}{$sam}{'userAccountControl'}=
                $entry->get_value('userAccountControl');
            $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_ASCII'}=$identifier_ascii;
            $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_UTF8'}=$identifier_utf8;

            # lookup
            if ($entry->get_value('sophomorixUnid') ne "---"){
                # no lookup for unid '---'
                $AD{'LOOKUP'}{'user_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=$sam;
                $AD{'LOOKUP'}{'identifier_utf8_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                    $identifier_utf8;
                $AD{'LOOKUP'}{'identifier_ascii_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                    $identifier_ascii;
            }
            $AD{'LOOKUP'}{'user_BY_identifier_ascii'}{$identifier_ascii}=$sam;
            $AD{'LOOKUP'}{'user_BY_identifier_utf8'}{$identifier_utf8}=$sam;
            $AD{'LOOKUP'}{'sophomorixStatus_BY_identifier_ascii'}{$identifier_ascii}=$entry->get_value('sophomorixStatus');
            $AD{'LOOKUP'}{'sophomorixStatus_BY_identifier_utf8'}{$identifier_utf8}=$entry->get_value('sophomorixStatus');
            $AD{'LOOKUP'}{'sophomorixRole_BY_sAMAccountName'}{$sam}=$entry->get_value('sophomorixRole');

            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'users_BY_sophomorixRole'}{$entry->get_value('sophomorixRole')} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}{'users_BY_sophomorixRole'}{$entry->get_value('sophomorixRole')} }, $sam;

            my $type=$AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$adminclass};
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_BY_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_BY_sophomorixType'}{$type} }, $sam;  
        }
        # sorting some lists
#        my $unneeded1=$#{ $AD{'LISTS'}{'student'} }; # make list computer nonempty        
#        @{ $AD{'LISTS'}{'student'} } = sort @{ $AD{'LISTS'}{'student'} }; 
#        my $unneeded2=$#{ $AD{'LISTS'}{'teacher'} }; # make list computer nonempty        
#        @{ $AD{'LISTS'}{'teacher'} } = sort @{ $AD{'LISTS'}{'teacher'} }; 
    }


    ##################################################
    if ($rooms eq "TRUE"){
        # sophomorixType room from ldap
        my $filter="(&(objectClass=group)(sophomorixType=".
           $ref_sophomorix_config->{'INI'}{'TYPE'}{'ROOM'}."))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
#                       filter => '(&(objectClass=group)(sophomorixType=room))',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixStatus',
                                 'sophomorixSchoolname',
                                 'sophomorixType',
                                ]);
        my $max_room = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_room sophomorix Rooms found in AD");
        $AD{'RESULT'}{'group'}{'room'}{'COUNT'}=$max_room;
        for( my $index = 0 ; $index < $max_room ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            $AD{'objectclass'}{'group'}{'room'}{$sam}{'room'}=$sam;
            $AD{'objectclass'}{'group'}{'room'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'room'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'room'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'LISTS'}{'room'} }; # make list computer empty to allow sort  
#        @{ $AD{'LISTS'}{'room'} } = sort @{ $AD{'LISTS'}{'room'} }; 
    }


    ##################################################
    if ($computers eq "TRUE"){
        # sophomorix computers from ldap
        my $filter="(& (objectClass=computer)(sophomorixRole=*) )";
        print "Fixlter: $filter\n";
        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
#                          filter => '(&(objectClass=computer)(sophomorixRole=computer))',
                          filter => $filter,
                          attrs => ['sAMAccountName',
                                    'sophomorixSchoolPrefix',
                                    'sophomorixSchoolname',
                                    'sophomorixAdminFile',
                                    'sophomorixAdminClass',
                                    'sophomorixRole',
                                    'sophomorixDnsNodename',
                                  ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user Computers found in AD");
        $AD{'RESULT'}{'computer'}{'computer'}{'COUNT'}=$max_user;
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $prefix=$entry->get_value('sophomorixSchoolPrefix');
            my $role=$entry->get_value('sophomorixRole');
            my $sn=$entry->get_value('sophomorixSchoolname');
            my $file=$entry->get_value('sophomorixAdminFile');
            $AD{'objectclass'}{'computer'}{'computer'}{$sam}{'sophomorixSchoolPrefix'}=$prefix;
            $AD{'objectclass'}{'computer'}{'computer'}{$sam}{'sophomorixRole'}=$role;
            $AD{'objectclass'}{'computer'}{'computer'}{$sam}{'sophomorixSchoolname'}=$sn;
            $AD{'objectclass'}{'computer'}{'computer'}{$sam}{'sophomorixAdminFile'}=$file;
            $AD{'objectclass'}{'computer'}{'computer'}{$sam}{'sophomorixDnsNodename'}=
                $entry->get_value('sophomorixDnsNodename');
            $AD{'objectclass'}{'computer'}{'computer'}{$sam}{'sophomorixAdminClass'}=
                $entry->get_value('sophomorixAdminClass');
            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'users_BY_sophomorixRole'}{$entry->get_value('sophomorixRole')} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$sn}{'users_BY_sophomorixRole'}{$entry->get_value('sophomorixRole')} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }

            $AD{'LOOKUP'}{'sophomorixDnsNodename_BY_sAMAccountName'}{$sam}=$entry->get_value('sophomorixDnsNodename');
            $AD{'LOOKUP'}{'sAMAccountName_BY_sophomorixDnsNodename'}{$entry->get_value('sophomorixDnsNodename')}=$sam;

            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_BY_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  

            my $type=$AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$entry->get_value('sophomorixAdminClass')};
            if (not defined $type){
    	        print "\nWARNING: Group ".$entry->get_value('sophomorixAdminClass').
                " without type (a device account without a group??)\n\n";
            } else {
                # there is a group for the user
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}{'users_BY_sophomorixType'}{$type} }, 
                $sam;  
            }
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'LISTS'}{'computer'} }; # make list computer empty to allow sort  
        # print "COUNT: $#{ $AD{'LISTS'}{'computer'} }\n";  # -1  
#        @{ $AD{'LISTS'}{'computer'} } = sort @{ $AD{'LISTS'}{'computer'} }; 
        # print "COUNT: $#{ $AD{'LISTS'}{'computer'} }\n";  # -1   
    }


    ##################################################
    if ($management eq "TRUE"){
        # ----------------------------------------
        # sophomorixType internetaccess from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=internetaccess))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_internetaccess = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_internetaccess sophomorix internetaccess groups found in AD");
        $AD{'RESULT'}{'group'}{'internetaccess'}{'COUNT'}=$max_internetaccess;
        for( my $index = 0 ; $index < $max_internetaccess ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$AD{'objectclass'}{'group'}{'internetaccess'}{$sam}{'internetaccess'}=$sam;
            $AD{'objectclass'}{'group'}{'internetaccess'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'internetaccess'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'internetaccess'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            # fetching members
            my @members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"member");
            foreach my $member (@members){
                my ($cn,@rest)=split(/,/,$member);
                my $user=$cn;
                $user=~s/^CN=//;
                #print "$sam: <$user> $cn  --- $member\n";
                $AD{'objectclass'}{'group'}{'internetaccess'}{$sam}{'members'}{$user}=$member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'internetaccess'} }, $member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'internetaccess'} }, $member;
            }
        }
        # sorting some lists
#        my $unneeded1=$#{ $AD{'LISTS'}{'internetaccess'} }; 
#        @{ $AD{'LISTS'}{'internetaccess'} } = sort @{ $AD{'LISTS'}{'internetaccess'} }; 
        # ----------------------------------------
        # sophomorixType wifiaccess from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=wifiaccess))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_wifiaccess = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_wifiaccess sophomorix wifiaccess groups found in AD");
        $AD{'RESULT'}{'group'}{'wifiaccess'}{'COUNT'}=$max_wifiaccess;
        for( my $index = 0 ; $index < $max_wifiaccess ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$AD{'objectclass'}{'group'}{'wifiaccess'}{$sam}{'wifiaccess'}=$sam;
            $AD{'objectclass'}{'group'}{'wifiaccess'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'wifiaccess'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'wifiaccess'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            # fetching members
            my @members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"member");
            foreach my $member (@members){
                my ($cn,@rest)=split(/,/,$member);
                my $user=$cn;
                $user=~s/^CN=//;
                #print "$sam: <$user> $cn  --- $member\n";
                $AD{'objectclass'}{'group'}{'wifiaccess'}{$sam}{'members'}{$user}=$member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'wifiaccess'} }, $member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'wifiaccess'} }, $member;
            }
        }
        # sorting some lists
#        my $unneeded2=$#{ $AD{'LISTS'}{'wifiaccess'} }; 
#        @{ $AD{'LISTS'}{'wifiaccess'} } = sort @{ $AD{'LISTS'}{'wifiaccess'} }; 

        # ----------------------------------------
        # sophomorixType admins from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=admins))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_admins = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_admins sophomorix admins groups found in AD");
        $AD{'RESULT'}{'group'}{'admins'}{'COUNT'}=$max_admins;
        for( my $index = 0 ; $index < $max_admins ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$AD{'objectclass'}{'group'}{'admins'}{$sam}{'admins'}=$sam;
            $AD{'objectclass'}{'group'}{'admins'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'admins'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'admins'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            # fetching members
            my @members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"member");
            foreach my $member (@members){
                my ($cn,@rest)=split(/,/,$member);
                my $user=$cn;
                $user=~s/^CN=//;
                #print "$sam: <$user> $cn  --- $member\n";
                $AD{'objectclass'}{'group'}{'admins'}{$sam}{'members'}{$user}=$member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'admins'} }, $member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'admins'} }, $member;
            }
        }
        # sorting some lists
#        my $unneeded3=$#{ $AD{'LISTS'}{'admins'} }; 
#        @{ $AD{'LISTS'}{'admins'} } = sort @{ $AD{'LISTS'}{'admins'} }; 




        # ----------------------------------------
        # sophomorixType webfilter from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=webfilter))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_webfilter = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_webfilter sophomorix webfilter groups found in AD");
        $AD{'RESULT'}{'group'}{'webfilter'}{'COUNT'}=$max_webfilter;
        for( my $index = 0 ; $index < $max_webfilter ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$AD{'objectclass'}{'group'}{'webfilter'}{$sam}{'webfilter'}=$sam;
            $AD{'objectclass'}{'group'}{'webfilter'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'webfilter'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'webfilter'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            # fetching members
            my @members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"member");
            foreach my $member (@members){
                my ($cn,@rest)=split(/,/,$member);
                my $user=$cn;
                $user=~s/^CN=//;
                #print "$sam: <$user> $cn  --- $member\n";
                $AD{'objectclass'}{'group'}{'webfilter'}{$sam}{'members'}{$user}=$member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'webfilter'} }, $member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'webfilter'} }, $member;
            }
        }




        # ----------------------------------------
        # sophomorixType intranetaccess from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=intranetaccess))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_intranetaccess = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_intranetaccess sophomorix intranetaccess groups found in AD");
        $AD{'RESULT'}{'group'}{'intranetaccess'}{'COUNT'}=$max_intranetaccess;
        for( my $index = 0 ; $index < $max_intranetaccess ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$AD{'objectclass'}{'group'}{'intranetaccess'}{$sam}{'intranetaccess'}=$sam;
            $AD{'objectclass'}{'group'}{'intranetaccess'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'intranetaccess'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'intranetaccess'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            # fetching members
            my @members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"member");
            foreach my $member (@members){
                my ($cn,@rest)=split(/,/,$member);
                my $user=$cn;
                $user=~s/^CN=//;
                #print "$sam: <$user> $cn  --- $member\n";
                $AD{'objectclass'}{'group'}{'intranetaccess'}{$sam}{'members'}{$user}=$member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'intranetaccess'} }, $member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'intranetaccess'} }, $member;
            }
        }





        # ----------------------------------------
        # sophomorixType printing from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=printing))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_printing = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_printing sophomorix printing groups found in AD");
        $AD{'RESULT'}{'group'}{'printing'}{'COUNT'}=$max_printing;
        for( my $index = 0 ; $index < $max_printing ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $school=$entry->get_value('sophomorixSchoolname');
            #$AD{'objectclass'}{'group'}{'printing'}{$sam}{'printing'}=$sam;
            $AD{'objectclass'}{'group'}{'printing'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'printing'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'printing'}{$sam}{'sophomorixSchoolname'}=$school;
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            # fetching members
            my @members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"member");
            foreach my $member (@members){
                my ($cn,@rest)=split(/,/,$member);
                my $user=$cn;
                $user=~s/^CN=//;
                #print "$sam: <$user> $cn  --- $member\n";
                $AD{'objectclass'}{'group'}{'printing'}{$sam}{'members'}{$user}=$member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'printing'} }, $member;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$school}{'printing'} }, $member;
            }
        }





    }


    # ##################################################
    # if ($examaccounts eq "TRUE"){
    #     # sophomorix ExamAccounts from ldap
    #     $mesg = $ldap->search( # perform a search
    #                    base   => $root_dse,
    #                    scope => 'sub',
    #                    filter => '(&(objectClass=user)(sophomorixRole=examaccount))',
    #                    attrs => ['sAMAccountName',
    #                              'sophomorixAdminClass',
    #                              'sophomorixAdminFile',
    #                             ]);
    #     my $max_user = $mesg->count; 
    #     &Sophomorix::SophomorixBase::print_title("$max_user ExamAccounts found in AD");
    #     $AD{'RESULT'}{'user'}{'examaccount'}{'COUNT'}=$max_user;
    #     for( my $index = 0 ; $index < $max_user ; $index++) {
    #         my $entry = $mesg->entry($index);
    #         my $sam=$entry->get_value('sAMAccountName');
    #         my $room=$entry->get_value('sophomorixAdminClass');
    #         my $filename=$entry->get_value('sophomorixAdminFile');
    #         if($Conf::log_level>=2){
    #             print "   * $sam in Room $room\n";
    #         }
    #         $AD{'objectclass'}{'user'}{'examaccount'}{$sam}{'room'}=$room;
    #         $AD{'objectclass'}{'user'}{'examaccount'}{$sam}{'sophomorixAdminClass'}=$room;
    #         $AD{'objectclass'}{'user'}{'examaccount'}{$sam}{'sophomorixAdminFile'}=$filename;
    #     }
    # }


    ##################################################
    if ($dnszones eq "TRUE"){
        ## sophomorix dnsZones and default Zone from ldap
        #my $filter_zone="(&(objectClass=dnsZone)(adminDescription=".
        #                $DevelConf::dns_zone_prefix_string.
        #                "*))";
        # All dnsZones from ldap
        my $filter_zone="(objectClass=dnsZone)";
        my $base_zones="DC=DomainDnsZones,".$root_dse;
        $mesg = $ldap->search( # perform a search
                       base   => $base_zones,
                       scope => 'sub',
                       filter => $filter_zone,
                       attrs => ['name',
                                 'dc',
                                 'dnsZone',
                                 'adminDescription',
                                ]);
        my $max_zone = $mesg->count; 
        my $sopho_max_zone=$max_zone;
        my $other_max_zone=0;
        &Sophomorix::SophomorixBase::print_title(
            "$max_zone dnsZones found");
        for( my $index = 0 ; $index < $max_zone ; $index++) {
            my $entry = $mesg->entry($index);
            my $zone=$entry->get_value('dc');
#            if ($zone eq $root_dns){ 
#                print "Skipping zone: $zone\n"; #skip provisioning DNS Zone
#                next;
#            }
            my $name=$entry->get_value('name');
            my $desc=$entry->get_value('adminDescription');
            if($Conf::log_level>=2){
                print "   * ",$entry->get_value('dc'),"\n";
            }
            if (not defined $desc){$desc=""};
            if ($desc=~ m/^${DevelConf::dns_zone_prefix_string}/ or
                $name eq $root_dns){
                # shophomorix dnsZone or default dnsZone
                $AD{'objectclass'}{'dnsZone'}{$DevelConf::dns_zone_prefix_string}{$zone}{'name'}=$name;
                $AD{'objectclass'}{'dnsZone'}{$DevelConf::dns_zone_prefix_string}{$zone}{'adminDescription'}=$desc;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'sophomorixdnsZone'} }, $zone;
            } else {
                # other dnsZone
		$sopho_max_zone=$sopho_max_zone-1;
                $other_max_zone=$other_max_zone+1;
                $AD{'objectclass'}{'dnsZone'}{'otherdnsZone'}{$zone}{'name'}=$name;
                $AD{'objectclass'}{'dnsZone'}{'otherdnsZone'}{$zone}{'adminDescription'}=$desc;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'otherdnsZone'} }, $zone;
            }
        }
        $AD{'RESULT'}{'dnsZone'}{$DevelConf::dns_zone_prefix_string}{'COUNT'}=$sopho_max_zone;
        $AD{'RESULT'}{'dnsZone'}{'otherdnsZone'}{'COUNT'}=$other_max_zone;
        # sorting some lists
#        my $unneeded1=$#{ $AD{'LISTS'}{'sophomorixdnsZone'} }; 
#        @{ $AD{'LISTS'}{'sophomorixdnsZone'} } = sort @{ $AD{'LISTS'}{'sophomorixdnsZone'} }; 
#        my $unneeded2=$#{ $AD{'LISTS'}{'otherdnsZone'} }; 
#        @{ $AD{'LISTS'}{'otherdnsZone'} } = sort @{ $AD{'LISTS'}{'otherdnsZone'} }; 
    }


    ##################################################
    if ($dnsnodes eq "TRUE"){
        # sophomorix dnsNodes from ldap by dnsZone
        # go through all dnsZones
        foreach my $dns_zone (keys %{ $AD{'objectclass'}{'dnsZone'}{$DevelConf::dns_zone_prefix_string} }) {
            my ($count,$dn_dns_zone,$cn_dns_zone,$info)=
                &AD_object_search($ldap,$root_dse,"dnsZone",$dns_zone);
            my $base_hosts=$dn_dns_zone;
            my $res   = Net::DNS::Resolver->new;
            my $filter_node="(&(objectClass=dnsNode)(adminDescription=".
                             $DevelConf::dns_node_prefix_string.
                            "*))";
            $mesg = $ldap->search( # perform a search
                           base   => $base_hosts,
                           scope => 'sub',
                           filter => $filter_node,
                           attrs => ['dc',
                                     'dnsRecord',
                                     'adminDescription',
                                 ]);
            my $max_node = $mesg->count; 
            &Sophomorix::SophomorixBase::print_title(
               "$max_node sophomorix dnsNodes found in AD");
            for( my $index = 0 ; $index < $max_node ; $index++) {
                my $entry = $mesg->entry($index);
                my $dc=$entry->get_value('dc');
                # get ip from dns, because in AD its binary (last 4 Bytes)

                my $ip=&Sophomorix::SophomorixBase::dns_query_ip($res,$dc);
                if ($ip eq "NXDOMAIN"){
                    next;
                }
                my $record=$entry->get_value('dnsRecord');
                my $desc=$entry->get_value('adminDescription');
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'dnsNode'}=$dc;
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'dnsZone'}=$dns_zone;
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'IPv4'}=$ip;
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'adminDescription'}=$desc;
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'dnsNode'} }, $dc;
                if($Conf::log_level>=2){
                    print "   * $dc\n";
                }
            }
            if (defined $dc){ 
                $AD{'RESULT'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'COUNT'}=$max_node;
	    }
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'LISTS'}{'dnsNode'} }; 
#        @{ $AD{'LISTS'}{'dnsNode'} } = sort @{ $AD{'LISTS'}{'dnsNode'} }; 
    }

    return(\%AD);
}



sub AD_get_AD_for_check {
    my %AD=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # forbidden login names
    $AD{'FORBIDDEN'}{'root'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'linbo'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'opsi'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'container'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'mail'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'webui'}="forbidden by Hand";

    ############################################################
    # SEARCH FOR ALL
    &Sophomorix::SophomorixBase::print_title("Query AD (begin)");
    my $filter="(| (objectClass=user) (objectClass=group) (objectClass=computer) )";
    my $mesg8 = $ldap->search( # perform a search
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attrs => ['sAMAccountName',
                                'sophomorixSchoolname',
                                'sophomorixStatus',
                                'sophomorixUnid',
                                'sophomorixSurnameASCII',
                                'sophomorixFirstnameASCII',
                                'sophomorixBirthdate',
                                'sn',
                                'givenName',
                                'sophomorixSurnameInitial',
                                'sophomorixFirstnameInitial',
                                'sophomorixAdminFile',
                                'sophomorixAdminClass',
                                'sophomorixRole',
                                'sophomorixType',
                                'sophomorixTolerationDate',
                                'sophomorixDeactivationDate',
                                'objectClass',
                               ]);
    my $max = $mesg8->count; 
    for( my $index = 0 ; $index < $max ; $index++) {
       my $entry = $mesg8->entry($index);
       my $sam=$entry->get_value('sAMAccountName');
       #my $objectclass=$entry->get_value('objectClass');
       my $role;
       my $type;
       my $forbidden_warn;
       if (defined $entry->get_value('sophomorixRole')){
           $role=$entry->get_value('sophomorixRole');
           $forbidden_warn="$sam forbidden, $sam is a sophomorix user";
           if ($role eq $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'STUDENT'} or
               $role eq $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'TEACHER'}
              ){
               # save needed stuff             
               $AD{'sAMAccountName'}{$sam}{'sophomorixRole'}=$role;
               $AD{'sAMAccountName'}{$sam}{'sophomorixUnid'}=$entry->get_value('sophomorixUnid');
               $AD{'sAMAccountName'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
               $AD{'sAMAccountName'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
               $AD{'sAMAccountName'}{$sam}{'sophomorixSurnameASCII'}=$entry->get_value('sophomorixSurnameASCII');
               $AD{'sAMAccountName'}{$sam}{'sophomorixFirstnameASCII'}=$entry->get_value('sophomorixFirstnameASCII');
               $AD{'sAMAccountName'}{$sam}{'sophomorixBirthdate'}=$entry->get_value('sophomorixBirthdate');
               $AD{'sAMAccountName'}{$sam}{'sn'}=$entry->get_value('sn');
               $AD{'sAMAccountName'}{$sam}{'givenName'}=$entry->get_value('givenName');
               $AD{'sAMAccountName'}{$sam}{'sophomorixSurnameInitial'}=$entry->get_value('sophomorixSurnameInitial');
               $AD{'sAMAccountName'}{$sam}{'sophomorixFirstnameInitial'}=$entry->get_value('sophomorixFirstnameInitial');
               $AD{'sAMAccountName'}{$sam}{'sophomorixAdminFile'}=$entry->get_value('sophomorixAdminFile');
               $AD{'sAMAccountName'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
               $AD{'sAMAccountName'}{$sam}{'sophomorixTolerationDate'}=$entry->get_value('sophomorixTolerationDate');
               $AD{'sAMAccountName'}{$sam}{'sophomorixDeactivationDate'}=$entry->get_value('sophomorixDeactivationDate');

               my $identifier_ascii=
                   $entry->get_value('sophomorixSurnameASCII').
                   ";".
                   $entry->get_value('sophomorixFirstnameASCII').
                   ";".
                   $entry->get_value('sophomorixBirthdate');
               $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_ASCII'}=$identifier_ascii;

               my $identifier_utf8=
                   $entry->get_value('sn').
                   ";".
                   $entry->get_value('givenName').
                   ";".
                   $entry->get_value('sophomorixBirthdate');
               # wegelassen: IDENTIFIER_UTF8,userAccountControl,sophomorixPrefix
               # $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_UTF8'}=$identifier_utf8;

               # LOOKUP
               $AD{'LOOKUP'}{'user_BY_identifier_utf8'}{$identifier_utf8}=$sam;
               $AD{'LOOKUP'}{'user_BY_identifier_ascii'}{$identifier_ascii}=$sam;
               $AD{'LOOKUP'}{'sophomorixStatus_BY_identifier_ascii'}{$identifier_ascii}=$entry->get_value('sophomorixStatus');
               $AD{'LOOKUP'}{'sophomorixRole_BY_sAMAccountName'}{$sam}=$entry->get_value('sophomorixRole');
               if ($entry->get_value('sophomorixUnid') ne "---"){
                   # no lookup for unid '---'
                   $AD{'LOOKUP'}{'user_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=$sam;
                   # $AD{'LOOKUP'}{'identifier_utf8_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                   #     $identifier_utf8;
                   $AD{'LOOKUP'}{'identifier_ascii_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                       $identifier_ascii;
               }
           }
       } elsif (defined $entry->get_value('sophomorixType')){
           $type=$entry->get_value('sophomorixType');
           $forbidden_warn="$sam forbidden, $sam is a sophomorix group";
       } else {
           $forbidden_warn="$sam forbidden, $sam is a non-sophomorix user";
       }

       $AD{'FORBIDDEN'}{$sam}=$forbidden_warn;
       #print "$forbidden_warn: $sam\n"; 
    }

    &Sophomorix::SophomorixBase::print_title("Query AD (end)");
    return(\%AD);
}



sub AD_get_schema {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my %schema=();
    &Sophomorix::SophomorixBase::print_title("Query AD for schema (start)");
    my $filter="(LDAPDisplayName=*)";
    my $base="CN=Schema,CN=Configuration,".$root_dse;
    my $mesg = $ldap->search( # perform a search
                          base   => $base,
                          scope => 'sub',
                          filter => $filter,
                                   );
    my $max = $mesg->count;
    my $ref_mesg = $mesg->as_struct; # result in Datenstruktur darstellen
    print Dumper \%mesg;
    # set total counter
    $schema{'RESULT'}{'LDAPDisplayName'}{'TOTAL'}{'COUNT'}=$max;
    print "$max attributes found with LDAPDisplayName\n";
    for( my $index = 0 ; $index < $max ; $index++) {
        my $is_sophomorix=0; # from sophomorix schema or not
        my $entry = $mesg->entry($index); 
        my $dn=$entry->dn();
        my $name=$entry->get_value('LDAPDisplayName');
        my $cn=$entry->get_value('cn');
        $schema{'LDAPDisplayName'}{$name}{'DN'}=$dn;
        $schema{'LDAPDisplayName'}{$name}{'CN'}=$cn;
        $schema{'LOOKUP'}{'LDAPDisplayName_by_DN'}{$dn}=$name;

        # save Camelcase names 
        my $lowercase_name=$name;
        $lowercase_name=~tr/A-Z/a-z/; # make lowercase
        $schema{'LOOKUP'}{'CamelCase'}{$lowercase_name}=$name;

        # $type is classSchema or attributeSchema
        my $type="NONE";
        foreach my $objectclass (@{ $ref_mesg->{$dn}{'objectclass'} }) { # objectclass MUST be lowercase(NET::LDAP hash)
            if ($objectclass eq "classSchema" ){
                $type=$objectclass;
            } elsif ($objectclass eq "attributeSchema"){
                $type=$objectclass;
            }
        }

        foreach my $attr (keys %{ $ref_mesg->{$dn} }) {
            # save it in returned data structure
            $schema{'LDAPDisplayName'}{$name}{$attr}=$ref_mesg->{$dn}{$attr};
            # test if its a sophomorix attribute
            if ($attr eq "attributeid" or $attr eq "governsid"){
                my $attribute_id=$ref_mesg->{$dn}{$attr}[0];
                # 1.3.6.1.4.1.47512     is linuxmuster.net
                # 1.3.6.1.4.1.47512.1   is the sophomorix subspace
                if ( $attribute_id=~m/^1.3.6.1.4.1.47512.1/ ){
                    $is_sophomorix=1;
                } 
            }
        }

        # save attribute in LISTS
        push @{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} }, $name;
        if ($is_sophomorix==1){
            push @{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} }, $name;
        } else {
            push @{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} }, $name;
        }
    }

    # sort and count some lists
    my @types=("classSchema","attributeSchema");
    foreach my $type (@types){
        if (exists $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type}){
            @{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} } = 
                sort @{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} };
            $schema{'RESULT'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type}{'COUNT'}=
                $#{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} }+1;
        } else {
            $schema{'RESULT'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type}{'COUNT'}=0;
        }

        if (exists $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type}){
            @{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} } = 
                sort @{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} };
            $schema{'RESULT'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=
            $#{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} }+1;
        } else {
            $schema{'RESULT'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=0;
        }

        if (exists $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type}){ 
            @{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} } = 
                sort @{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} };
            $schema{'RESULT'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=
                $#{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} }+1;
        } else {
	    $schema{'RESULT'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=0;
        }
    }
    &Sophomorix::SophomorixBase::print_title("Query AD for schema (end)");
    return \%schema;
}



sub AD_get_AD_for_device {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my %AD=();
    &Sophomorix::SophomorixBase::print_title("Query AD for device (start)");
    ############################################################
    # sophomorix computers from ldap
    { # BLOCK computer start
        ### create filter
        # finds all computer with any string as sophomorixRole
        my $filter="(& (objectClass=computer) (sophomorixRole=*) )";
        # print "Filter:  $filter\n";

        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['sAMAccountName',
                                    'sophomorixSchoolPrefix',
                                    'sophomorixSchoolname',
                                    'sophomorixAdminFile',
                                    'sophomorixAdminClass',
                                    'sophomorixRole',
                                    'sophomorixDnsNodename',
                                    'comment',
                                    'sophomorixComment',
                                    'sophomorixComputerIP',
                                    'sophomorixComputerMAC',
                                    'sophomorixComputerRoom',
                                    'sophomorixComputerDefaults',
                                   ]);
        my $max_computer = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_computer Computers found in AD");
        # set total counter
        $AD{'RESULT'}{'computer'}{'TOTAL'}{'COUNT'}=$max_computer;
        # set role counters to 0, will be upcounted later
        foreach my $keyname (keys %{$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}}) {
            $AD{'RESULT'}{'computer'}{$keyname}{'COUNT'}=0;
        }
        for( my $index = 0 ; $index < $max_computer ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $prefix=$entry->get_value('sophomorixSchoolPrefix');
            my $role=$entry->get_value('sophomorixRole');
            my $sn=$entry->get_value('sophomorixSchoolname');
            my $file=$entry->get_value('sophomorixAdminFile');
            $AD{'computer'}{$sam}{'sophomorixSchoolPrefix'}=$prefix;

            $AD{'computer'}{$sam}{'sophomorixRole'}=$role;
            # increase role counter 
            $AD{'RESULT'}{'computer'}{$role}{'COUNT'}++;

            $AD{'computer'}{$sam}{'sophomorixSchoolname'}=$sn;
            $AD{'computer'}{$sam}{'sophomorixAdminFile'}=$file;
            $AD{'computer'}{$sam}{'sophomorixDnsNodename'}=$entry->get_value('sophomorixDnsNodename');
            $AD{'computer'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
            $AD{'computer'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
            $AD{'computer'}{$sam}{'comment'}=$entry->get_value('comment');
            $AD{'computer'}{$sam}{'sophomorixComputerIP'}=$entry->get_value('sophomorixComputerIP');
            $AD{'computer'}{$sam}{'sophomorixComputerMAC'}=$entry->get_value('sophomorixComputerMAC');
            $AD{'computer'}{$sam}{'sophomorixComputerRoom'}=$entry->get_value('sophomorixComputerRoom');
            @{ $AD{'computer'}{$sam}{'sophomorixComputerDefaults'} }=$entry->get_value('sophomorixComputerDefaults');

            # lists
            push @{ $AD{'LISTS'}{'COMPUTER_BY_sophomorixSchoolname'}{$sn}{$role} }, $sam; 

            # lookup
            $AD{'LOOKUP'}{'sAMAccountName_BY_sophomorixDnsNodename'}{$entry->get_value('sophomorixDnsNodename')}=$sam;

            #my $type=$AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$entry->get_value('sophomorixAdminClass')};
            #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}
            #           {'users_BY_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  
            #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}{'users_BY_sophomorixType'}{$type} }, $sam;  
        }
    }  # BLOCK computer end
    ############################################################
    # sophomorix rooms/hardwareclasses from ldap
    { # BLOCK group start
        my $filter="(& (objectClass=group) (| ".
                   "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ROOM'}.") ".
                   "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'HWK'}.") ";
        # add defined host group types from sophomorix.ini
        foreach my $type (keys %{ $ref_sophomorix_config->{'LOOKUP'}{'HOST_GROUP_TYPE'} }) {
            $filter=$filter."(sophomorixType=".$type.") ";
        }
        $filter=$filter.") )";

	#print "Filter for device groups: $filter\n";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixStatus',
                                 'sophomorixSchoolname',
                                 'sophomorixType',
                                 'member',
                                 'sophomorixRoomIPs',
                                 'sophomorixRoomMACs',
                                 'sophomorixRoomComputers',
                                 'sophomorixRoomDefaults',
                                ]);
        my $max_group = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_group sophomorix rooms/hardwareclasses found in AD");
        $AD{'RESULT'}{'group'}{'TOTAL'}{'COUNT'}=$max_group;
        $AD{'RESULT'}{'group'}{'room'}{'COUNT'}=0;
        $AD{'RESULT'}{'group'}{'hardwareclass'}{'COUNT'}=0;
        for( my $index = 0 ; $index < $max_group ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');

            $AD{$type}{$sam}{'room'}=$sam;
            $AD{$type}{$sam}{'sophomorixStatus'}=$stat;
            $AD{$type}{$sam}{'sophomorixType'}=$type;
            # increase role counter 
            $AD{'RESULT'}{'group'}{$type}{'COUNT'}++;

            $AD{$type}{$sam}{'sophomorixSchoolname'}=$schoolname;
            $AD{$type}{$sam}{'DN'}=$dn;

            @{ $AD{$type}{$sam}{'sophomorixRoomIPs'} }=$entry->get_value('sophomorixRoomIPs');
            @{ $AD{$type}{$sam}{'sophomorixRoomMACs'} }=$entry->get_value('sophomorixRoomMACs');
            @{ $AD{$type}{$sam}{'sophomorixRoomComputers'} }=$entry->get_value('sophomorixRoomComputers');
            @{ $AD{$type}{$sam}{'sophomorixRoomDefaults'} }=$entry->get_value('sophomorixRoomDefaults');

            # host groups
            if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}{$type}){
                $AD{'host_group'}{$sam}=$type;
            }

            # hardwareclass memberships
            if ($type eq $ref_sophomorix_config->{'INI'}{'TYPE'}{'HWK'}){
                @{ $AD{$type}{$sam}{'member'} }=$entry->get_value('member');
                foreach my $dn (@{ $AD{$type}{$sam}{'member'} }){
                    my @parts=split(",",$dn);
                    my ($unused,$memsam)=split("=",$parts[0]);
                    $AD{$type}{$sam}{'member_sAMAccountName'}{$memsam}="seen";
                }
            }

            # lists
            #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            #$AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$sam}=$type;
        }
    } # BLOCK group end

    ############################################################
    # sophomorix dnzones and default Zone from ldap from ldap
    { # BLOCK dnsZone start
        my $filter="(objectClass=dnsZone)";
        my $base="DC=DomainDnsZones,".$root_dse;
        $mesg = $ldap->search( # perform a search
                       base   => $base,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['name',
                                 'dc',
                                 'dnsZone',
                                 'adminDescription',
                                ]);
        my $max_zone = $mesg->count; 
        $AD{'RESULT'}{'dnsZone'}{'TOTAL'}{'COUNT'}=$max_zone;
        $AD{'RESULT'}{'dnsZone'}{'sophomorix'}{'COUNT'}=0;
        $AD{'RESULT'}{'dnsZone'}{'other'}{'COUNT'}=0;

        &Sophomorix::SophomorixBase::print_title("$max_zone dnsZones found");
        for( my $index = 0 ; $index < $max_zone ; $index++) {
            my $entry = $mesg->entry($index);
            my $zone=$entry->get_value('dc');
            my $name=$entry->get_value('name');
            my $desc=$entry->get_value('adminDescription');
            if($Conf::log_level>=2){
                print "   * ",$entry->get_value('dc'),"\n";
            }
            if (not defined $desc){$desc=""};
            if ($desc=~ m/^${DevelConf::dns_zone_prefix_string}/ or
                $name eq $root_dns){
                # shophomorix dnsZone or default dnsZone
                $AD{'RESULT'}{'dnsZone'}{'sophomorix'}{'COUNT'}++;
                $AD{'dnsZone'}{$DevelConf::dns_zone_prefix_string}{$zone}{'name'}=$name;
                $AD{'dnsZone'}{$DevelConf::dns_zone_prefix_string}{$zone}{'adminDescription'}=$desc;
                #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'sophomorixdnsZone'} }, $zone;
            } else {
                # other dnsZone
                $AD{'RESULT'}{'dnsZone'}{'other'}{'COUNT'}++;
                $AD{'dnsZone'}{'otherdnsZone'}{$zone}{'name'}=$name;
                $AD{'dnsZone'}{'otherdnsZone'}{$zone}{'adminDescription'}=$desc;
                #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'otherdnsZone'} }, $zone;
            }
        }
        #$AD{'RESULT'}{'dnsZone'}{$DevelConf::dns_zone_prefix_string}{'COUNT'}=$sopho_max_zone;
        #$AD{'RESULT'}{'dnsZone'}{'otherdnsZone'}{'COUNT'}=$other_max_zone;
    } # BLOCK dnsZone end

    ############################################################
    # sophomorix dnsNodes from ldap
    { # BLOCK dnsNode start
        # alle NODES suchen
        my $res   = Net::DNS::Resolver->new;
        my $filter="(&(objectClass=dnsNode)(adminDescription=".
                   $DevelConf::dns_node_prefix_string.
                   "*))";
        my $base="DC=DomainDnsZones,".$root_dse;
        my $mesg = $ldap->search( # perform a search
                          base   => $base,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['dc',
                                    'dnsRecord',
                                    'adminDescription',
                                   ]);
        my $max_node = $mesg->count; 
        $AD{'RESULT'}{'dnsNode'}{'TOTAL'}{'COUNT'}=$max_node;
        $AD{'RESULT'}{'dnsNode'}{'sophomorix'}{'COUNT'}=0;
        $AD{'RESULT'}{'dnsNode'}{'other'}{'COUNT'}=0;

        &Sophomorix::SophomorixBase::print_title("$max_node sophomorix dnsNodes found");
        for( my $index = 0 ; $index < $max_node ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn=$entry->dn();
            my $dc=$entry->get_value('dc');
            my $desc=$entry->get_value('adminDescription');
            my $ip=&Sophomorix::SophomorixBase::dns_query_ip($res,$dc);
            if ($desc=~ m/^${DevelConf::dns_node_prefix_string}/ and $ip ne "NXDOMAIN" and $ip ne "NOERROR"){
                #print "$desc $ip\n";
                $AD{'RESULT'}{'dnsNode'}{'sophomorix'}{'COUNT'}++;
                $AD{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'dnsNode'}=$dc;
                # down there the dns zone was calualted
                #$AD{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'dnsZone'}=$dns_zone;
                $AD{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'dnsZone'}=$root_dns;

                $AD{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'IPv4'}=$ip;
                $AD{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'adminDescription'}=
                    $entry->get_value('adminDescription');
                push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'dnsNode'} }, $dc;
            } else {
                $AD{'RESULT'}{'dnsNode'}{'other'}{'COUNT'}++;
                #print "ELSE: $desc $ip\n";
            }
        }
    } # BLOCK dnsNode end
    # sort some room lists
    foreach my $room (keys %{$AD{'room'}}) {
        if($#{ $AD{'room'}{$room}{'sophomorixRoomComputers'} }>0){
           @{ $AD{'room'}{$room}{'sophomorixRoomComputers'} } = 
               sort @{ $AD{'room'}{$room}{'sophomorixRoomComputers'} };
        }
        if($#{ $AD{'room'}{$room}{'sophomorixRoomMACs'} }>0){
           @{ $AD{'room'}{$room}{'sophomorixRoomMACs'} } = 
               sort @{ $AD{'room'}{$room}{'sophomorixRoomMACs'} };
        }
        if($#{ $AD{'room'}{$room}{'sophomorixRoomIPs'} }>0){
           @{ $AD{'room'}{$room}{'sophomorixRoomIPs'} } = 
               sort @{ $AD{'room'}{$room}{'sophomorixRoomIPs'} };
        }
    }
    &Sophomorix::SophomorixBase::print_title("Query AD for device (end)");
    return(\%AD);
}


 
sub AD_get_ui {
    my %ui=();
    my $ref_ui=\%ui;
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $abs_path_ini = $arg_ref->{abs_path_ini};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    ############################################################
    # read default permissions from WEBUI package
    my $path_abs;
    if ($abs_path_ini ne ""){
        $path_abs=$abs_path_ini;
    } else {
        $path_abs=$ref_sophomorix_config->{'INI'}{'WEBUI'}{'INI'};
    }

    &Sophomorix::SophomorixBase::print_title("Reading $path_abs");
    if (-f $path_abs){
        tie %{ $ref_ui->{'CONFIG'}{'WEBUI'} }, 'Config::IniFiles',
            ( -file => $path_abs, 
              -handle_trailing_comment => 1,
            );
    } else {
        print "\n";
        print "ERROR: UI config file not found:\n";
        print "       $path_abs\n";
        print "\n";
        exit;
    }

    # Test config file for double module paths
    foreach my $role (keys %{ $ref_ui->{'CONFIG'}{'WEBUI'} }) {
        my %seen=();
        my @items=&Sophomorix::SophomorixBase::ini_list($ref_ui->{'CONFIG'}{'WEBUI'}{$role}{'WEBUI_PERMISSIONS'});
        foreach my $item (@items){
            $item=~s/\s+$//g;# remove trailing whitespace
            my $mod_path=$item;
            my $setting;
            if ($item=~m/true$/){
                $mod_path=~s/true$//g;# remove true
                $setting="true";
            } elsif ($item=~m/false$/){
                $mod_path=~s/false$//g;# remove false
                $setting="false";
            } else {
                print "File: $path_abs:\n";
                print "   >$item< (contains neither false nor true at the end!\n\n";
                exit 88;
            }

            # remember $mod_path
            $mod_path=~s/\s+$//g;# remove trailing whitespace
            if (exists $seen{$mod_path}){
                print "\nERROR: Module path $mod_path double in role $role\n\n";
                exit 88;
            } else {
                $ref_ui->{'CONFIG'}{'WEBUI_LOOKUP'}{$role}{$mod_path}=$setting;
                $seen{$mod_path}="seen";
            }
 
            # fill LOOKUP
            $ref_ui->{'LOOKUP'}{'MODULES'}{$role}{$mod_path}="OK";
            $ref_ui->{'LOOKUP'}{'MODULES'}{'ALL'}{$mod_path}="OK";
        }
    }

    ############################################################
    # read user data from AD
    &Sophomorix::SophomorixBase::print_title("Query AD (begin)");
    my $filter2="(&(objectClass=user) (| ".
                "(sophomorixRole=student) ".
                "(sophomorixRole=teacher) ".
                "(sophomorixRole=schooladministrator) ".
                "(sophomorixRole=globaladministrator)) )";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter2,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixRole',
                             'displayName',
                             'SophomorixWebuiPermissions',
                             'SophomorixWebuiPermissionsCalculated',
                            ]);
    my $max_user = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_user user found in AD");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
     	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $role=$entry->get_value('sophomorixRole');
        my $schoolname=$entry->get_value('sophomorixSchoolname');
        my @webui = $entry->get_value('sophomorixWebuiPermissions');
        my @webui_calc = $entry->get_value('sophomorixWebuiPermissionsCalculated');

        # saving
        $ui{'UI'}{'USERS'}{$sam}{'dn'}=$dn;
        $ui{'UI'}{'USERS'}{$sam}{'sophomorixSchoolname'}=$schoolname;
        $ui{'UI'}{'USERS'}{$sam}{'sophomorixRole'}=$role;
        $ui{'UI'}{'USERS'}{$sam}{'displayName'}=$entry->get_value('displayName');
        @{ $ui{'UI'}{'USERS'}{$sam}{'sophomorixWebuiPermissions'} } = 
            sort $entry->get_value('sophomorixWebuiPermissions');
        @{ $ui{'UI'}{'USERS'}{$sam}{'sophomorixWebuiPermissionsCalculated'} } = 
            sort $entry->get_value('sophomorixWebuiPermissionsCalculated');
        push @{ $ui{'LISTS'}{'USER_by_sophomorixSchoolname'}{$schoolname} },$sam;
        push @{ $ui{'LISTS'}{'USERS'} },$sam;

        # create CALC hash at every user (copy the package maintainer default)
        foreach my $mod_path (keys %{ $ref_ui->{'CONFIG'}{'WEBUI_LOOKUP'}{$role} }) {
            $ui{'UI'}{'USERS'}{$sam}{'CALC'}{$mod_path}=
                $ref_ui->{'CONFIG'}{'WEBUI_LOOKUP'}{$role}{$mod_path};  
        }

        # override from schooladmin/update CALC hash ???


        # override from sophomorixWebuiPermissions/update CALC hash
        foreach my $item (@{ $ui{'UI'}{'USERS'}{$sam}{'sophomorixWebuiPermissions'} }){
            print "   Analyze sophomorixWebuiPermissions: $item\n";
            $item=~s/\s+$//g;# remove trailing whitespace
            my $setting;
            my $mod_path=$item;
            if ($item=~m/true$/){
                $setting="true";
                $mod_path=~s/true$//g;# remove true
            } elsif ($item=~m/false$/){
                $setting="false";
                $mod_path=~s/false$//g;# remove false
            } else {
                print " sophomorixWebuiPermissions entry $item contains neither false nor true at the end!\n\n";
                exit 88;
            }
            $mod_path=~s/\s+$//g;# remove trailing whitespace
            if (exists $ui{'UI'}{'USERS'}{$sam}{'CALC'}{$mod_path}){
                # override
                $ref_ui->{'UI'}{'USERS'}{$sam}{'CALC'}{$mod_path}=$setting;
            } else {
                print " sophomorixWebuiPermissions does not mach a configured module path\n\n";
                exit 88;
            }
        }

        # create CALC*LISTs from CALC hash
        @{ $ui{'UI'}{'USERS'}{$sam}{'CALCLIST'} }=();
        @{ $ui{'UI'}{'USERS'}{$sam}{'CALCTRUELIST'} }=();
        @{ $ui{'UI'}{'USERS'}{$sam}{'CALCFALSELIST'} }=();
        foreach my $mod_path (keys %{ $ref_ui->{'UI'}{'USERS'}{$sam}{'CALC'} }) {
            my $item=$mod_path." ".$ref_ui->{'UI'}{'USERS'}{$sam}{'CALC'}{$mod_path};
            push @{ $ui{'UI'}{'USERS'}{$sam}{'CALCLIST'} },$item;
            if ($ref_ui->{'UI'}{'USERS'}{$sam}{'CALC'}{$mod_path} eq "true"){
                push @{ $ui{'UI'}{'USERS'}{$sam}{'CALCTRUELIST'} },$item;
            } elsif ($ref_ui->{'UI'}{'USERS'}{$sam}{'CALC'}{$mod_path} eq "false"){
                push @{ $ui{'UI'}{'USERS'}{$sam}{'CALCFALSELIST'} },$item;
            }
        }

        # always update for now ????
        push @{ $ui{'LISTS_UPDATE'}{'USER_by_sophomorixSchoolname'}{$schoolname} },$sam;
        push @{ $ui{'LISTS_UPDATE'}{'USERS'} },$sam;
    }
    &Sophomorix::SophomorixBase::print_title("Query AD (end)");
    return(\%ui);
}


 
sub AD_get_ui_old {
    my %ui=();
    my $ref_ui=\%ui;
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    ############################################################
    # read new permissions defaults from all packages
    &Sophomorix::SophomorixBase::print_title("Query AD (begin)");
    foreach my $ui (keys %{ $ref_sophomorix_config->{'INI'}{'UI'} }) {
        # reading package config for each UI into CONFIG as is (i.e. role.student, ...., TRUE and FALSE Entries)
        my $path_abs=$ref_sophomorix_config->{'INI'}{'UI'}{$ui};
        if (-f $path_abs){
            tie %{ $ref_ui->{'CONFIG'}{$ui} }, 'Config::IniFiles',
                ( -file => $path_abs, 
                  -handle_trailing_comment => 1,
                );
            # create CONFIG_PACKAGE entries (only correct role and TRUE entries from CONFIG)
            foreach my $module (keys %{ $ref_ui->{'CONFIG'}{$ui} }) {
                foreach my $keyname (keys %{ $ref_ui->{'CONFIG'}{$ui}{$module} }) {
                    if ($keyname eq "TRUE_ENTRY"){
                        # this is a known option, which could be processed
                    } elsif ($keyname=~m/^role\./) {
                        my ($key,$role)=split(/\./,$keyname);
                        if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_USER'}{$role}) {
                            # OK, role is a correct role
                            if ($ref_ui->{'CONFIG'}{$ui}{$module}{'role.'.$role} eq "TRUE"){
                                # save the true modules in: ui->module->role=TRUE
                                $ref_ui->{'CONFIG_PACKAGE'}{$ui}{$module}{$role}="TRUE";
	  		    }
                        } else {
                            print "\nERROR: $role is not a sophomorixRole (UI: $ui, module: $module)\n\n";
                            exit;
                        }

                    } else {
                        # ignore these options
                        print "Skipping keyname $keyname (UI: $ui, Module: $module)\n";
                    }
                }
            } 
        } else {
            print "\n";
            print "ERROR: UI config file not found:\n";
            print "       $path_abs\n";
            print "\n";
            exit;
        }
    }

    # test module-names in  <school.>school.ini (for all ui and all roles)
    foreach my $ui (keys %{ $ref_sophomorix_config->{'INI'}{'UI'} }) {
        # Test if configured school modules are correct (ui is tested already ba scgool.conf.master)
        foreach my $school (@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }){
            foreach my $role (keys %{ $ref_sophomorix_config->{'LOOKUP'}{'ROLES_USER'} }) {
                foreach my $module (@{ $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI_LIST'}{$ui}{'MODULE_LIST'} }){
                    if (exists $ref_ui->{'CONFIG'}{$ui}{$module}){
                        # This is an existing ui and an existing module
                    } else {
                        print "\n";
                        print "ERROR: In UI $ui is no module $module available:\n";
                        print "       Check config of school $school\n";
                        print "\n";
                        exit;
                    }
                }
            }
        }
    }


    my $filter2="(&(objectClass=user) (| ".
                "(sophomorixRole=student) ".
                "(sophomorixRole=teacher) ".
                "(sophomorixRole=schooladministrator) ".
                "(sophomorixRole=globaladministrator)) )";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter2,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixRole',
                             'displayName',
                             'SophomorixWebuiPermissions',
                             'SophomorixWebuiPermissionsCalculated',
                            ]);
    my $max_user = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_user user found in AD");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $role=$entry->get_value('sophomorixRole');
        my $schoolname=$entry->get_value('sophomorixSchoolname');
        my @webui = $entry->get_value('sophomorixWebuiPermissions');
        my @webui_calc = $entry->get_value('sophomorixWebuiPermissionsCalculated');

        # saving
        $ui{'UI'}{'USERS'}{$sam}{'dn'}=$dn;
        $ui{'UI'}{'USERS'}{$sam}{'sophomorixSchoolname'}=$schoolname;
        $ui{'UI'}{'USERS'}{$sam}{'sophomorixRole'}=$role;
        $ui{'UI'}{'USERS'}{$sam}{'displayName'}=$entry->get_value('displayName');
        @{ $ui{'UI'}{'USERS'}{$sam}{'sophomorixWebuiPermissions'} } = 
             sort $entry->get_value('sophomorixWebuiPermissions');
        @{ $ui{'UI'}{'USERS'}{$sam}{'sophomorixWebuiPermissionsCalculated'} } = 
             sort $entry->get_value('sophomorixWebuiPermissionsCalculated');
        push @{ $ui{'LISTS'}{'USER_by_sophomorixSchoolname'}{$schoolname} },$sam;
        push @{ $ui{'LISTS'}{'USERS'} },$sam;

        # read sophomorixWebuiPermissions
        foreach my $multi_attr (@webui){
	    my ($ui,$module,$switch)=split(/:/,$multi_attr);
            # test ui
            if (not exists $ref_sophomorix_config->{'INI'}{'UI'}{$ui}){
                print "\n";
                print "WARNING: \"$ui\" is not an UI\n";
                print "         sophomorixWebuiPermissions: \"$multi_attr\"\n";
                print "         at user $sam in school $schoolname\n";
                print "         The entry will be ignored\n";
                print "         You can delete the entry with:\n";
                print "         sophomorix-user --user $sam --remove-webui-permissions \"$multi_attr\"\n";
                print "\n";
                next;
            }
            # test modulemane
            if (not exists $ref_ui->{'CONFIG'}{$ui}{$module}){
                print "\n";
                print "WARNING: \"$module\" is not an module of UI \"$ui\"\n";
                print "         sophomorixWebuiPermissions: \"$multi_attr\"\n";
                print "         at user $sam in school $schoolname\n\n";
                print "         The entry will be ignored\n";
                print "         You can delete the entry with:\n";
                print "         sophomorix-user --user $sam --remove-webui-permissions \"$multi_attr\"\n";
                print "\n";
                next;
            }
            # test switch, if ok save setting
            if ($switch eq "TRUE"){
	        $ui{'UI'}{'USERS'}{$sam}{'UI'}{$ui}{'TRUE'}{$module}="TRUE";
            } elsif ($switch eq "FALSE"){
	        $ui{'UI'}{'USERS'}{$sam}{'UI'}{$ui}{'FALSE'}{$module}="FALSE";
            } else {
                print "\n";
                print "WARNING: switch \"$switch\" must be \"TRUE\" or \"FALSE\"\n";
                print "         sophomorixWebuiPermissions: \"$multi_attr\"\n";
                print "         at user $sam in school $schoolname\n\n";
                print "         The entry will be ignored\n";
                print "         You can delete the entry with:\n";
                print "         sophomorix-user --user $sam --remove-webui-permissions \"$multi_attr\"\n";
                print "\n";
                next;
            }
        }

        # calculating modules to show
        foreach my $ui (keys %{ $ref_sophomorix_config->{'INI'}{'UI'} }) {
            foreach my $module (keys %{ $ref_ui->{'CONFIG'}{$ui} }) {
                my $set_switch="FALSE"; # in case role is never mentioned
                my @reason=();
                # check package default
                if (exists $ref_ui->{'CONFIG_PACKAGE'}{$ui}{$module}{$role}){
                    # only TRUE modules in this hash
                    $set_switch="TRUE";
                    push @reason,"PACKAGE_DEFAULT=TRUE";
                }

                # school setting for role
                # TRUE
                if (exists $ref_sophomorix_config->{'ROLES'}{$schoolname}{$role}{'UI'}{$ui}{'TRUE'}{$module}){
                    $set_switch="TRUE";
                    push @reason,"SCHOOL_DEFAULT($role)=TRUE";
                }
                # FALSE wins over TRUE
                if (exists $ref_sophomorix_config->{'ROLES'}{$schoolname}{$role}{'UI'}{$ui}{'FALSE'}{$module}){
                    $set_switch="FALSE";
                    push @reason,"SCHOOL_DEFAULT($role)=FALSE";
                }

                # user setting
                # TRUE
                if (exists $ui{'UI'}{'USERS'}{$sam}{'UI'}{$ui}{'TRUE'}{$module}){
                    $set_switch="TRUE";
                    push @reason,"USER=TRUE";
                }
                # FALSE wins over TRUE
                if (exists $ui{'UI'}{'USERS'}{$sam}{'UI'}{$ui}{'FALSE'}{$module}){
                    $set_switch="FALSE";
                    push @reason,"USER=FALSE";
                }
                my $reasonlist=join(", ",@reason);
                $ui{'UI'}{'USERS'}{$sam}{'UI'}{$ui}{'CALC'}{$module}{'SWITCH'}=$set_switch;
                $ui{'UI'}{'USERS'}{$sam}{'UI'}{$ui}{'CALC'}{$module}{'REASON'}=$reasonlist;
                # create list for SophomorixWebuiPermissionsCalculated
                if ($set_switch eq "TRUE"){
                    $ui{'UI'}{'USERS'}{$sam}{'UI'}{$ui}{'CALCTRUE'}{$module}{'REASON'}=$reasonlist;
                    if ($ref_sophomorix_config->{'INI'}{'UI_CONFIG'}{'CALCULATED_PREFIX'} eq "TRUE"){
                        my $item=$ui.":".$ref_ui->{'CONFIG'}{$ui}{$module}{'TRUE_ENTRY'};                 
                        push @{ $ui{'UI'}{'USERS'}{$sam}{'CALCTRUELIST'} },$item;
                        $ui{'UI'}{'USERS'}{$sam}{'CALC_TRUE_ENTRIES'}{$item}="new";
                    } else {
                        my $tem=$ref_ui->{'CONFIG'}{$ui}{$module}{'TRUE_ENTRY'};
                        push @{ $ui{'UI'}{'USERS'}{$sam}{'CALCTRUELIST'} },$item;
                        $ui{'UI'}{'USERS'}{$sam}{'CALC_TRUE_ENTRIES'}{$item}="new";
                    }
                }
            }
        }

        # calculate if SophomorixWebuiPermissionsCalculated must be updated
        $ui{'UI'}{'USERS'}{$sam}{'UI_UPDATE'}="TRUE"; # first set to true
        if ( $#{ $ui{'UI'}{'USERS'}{$sam}{'CALCTRUELIST'} }==$#webui_calc ){
            my $count_true=0;
            foreach my $item (@webui_calc){
                if (exists $ui{'UI'}{'USERS'}{$sam}{'CALC_TRUE_ENTRIES'}{$item}){
                    # This attribute is there
                    $count_true++;
                }
            }
            my $num=$#webui_calc+1;
            if ($count_true==$num){
                # num entries equal num matches: No update
                $ui{'UI'}{'USERS'}{$sam}{'UI_UPDATE'}="FALSE";
            }
        }

        # create update user lists
        if ($ui{'UI'}{'USERS'}{$sam}{'UI_UPDATE'} eq "TRUE"){
            push @{ $ui{'LISTS_UPDATE'}{'USER_by_sophomorixSchoolname'}{$schoolname} },$sam;
            push @{ $ui{'LISTS_UPDATE'}{'USERS'} },$sam;
        }
    }
    &Sophomorix::SophomorixBase::print_title("Query AD (end)");
    return(\%ui);
}



sub AD_get_quota {
    my %quota=();
    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'SHARES'}=0;
    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERS'}=0;
    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERMAILQUOTA'}=0;
    # LISTS of %quota
    # LISTS->USER_by_SHARE-><share>->@users  # list which users have quota on the share
    # LISTS->USER_by_SCHOOL-><school>->@users  # list which users have quota on this school
    # LISTS->CLASS_by_SHARE-><share>->@users  # list which classes have quota on the share
    # LISTS->CLASS_by_SCHOOL-><school>->@users  # list which classes have quota on this school
    # LISTS->GROUPS_by_SHARE-><share>->@users  # list which groups have quota on the share
    # LISTS->GROUPS_by_SCHOOL-><school>->@users  # list which groups have quota on this school
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smbcquotas = $arg_ref->{smbcquotas};
    my $user_opt = $arg_ref->{user};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # create userlist for smbcquotas query
    my %smbcquotas_users=();
    if ($user_opt ne ""){
        my @smbcquotas_users=split(/,/,$user_opt);
        foreach my $user (@smbcquotas_users){
            $smbcquotas_users{$user}="query";
        }
    }

    # USER quota (sophomorix user)
    my $filter2="(&(objectClass=user) (| (sophomorixRole=student) (sophomorixRole=teacher) ) )";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter2,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixRole',
                             'sophomorixAdminFile',
                             'mail',
                             'displayName',
                             'sophomorixSurnameASCII',
                             'sophomorixFirstnameASCII',
                             'memberOf',
                             'sophomorixQuota',
                             'sophomorixMailQuota',
                             'sophomorixMailQuotaCalculated',
                             'sophomorixCloudQuotaCalculated',
                            ]);
    my $max_user = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_user user found in AD");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $role=$entry->get_value('sophomorixRole');
        my $file=$entry->get_value('sophomorixAdminFile');
        my $school=$entry->get_value('sophomorixSchoolname');
	my $mailquota = $entry->get_value('sophomorixMailQuota');
	my @quota = $entry->get_value('sophomorixQuota');
	my @memberof = $entry->get_value('memberOf');
	push @{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$school} }, $sam; 
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'DN_by_sAMAccountName'}{$sam}=$dn;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'DN_by_sAMAccountName'}{$sam}=$dn;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_sophomorixSchoolname'}{$school}{$sam}=$dn;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sophomorixSchoolname_by_sAMAccountName'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixRole'}=$role;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixAdminFile'}=$file;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixCloudQuotaCalculated'}=$entry->get_value('sophomorixCloudQuotaCalculated');

        # get SHAREDEFAULT for this role
        $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$school}{'SHAREDEFAULT'}=
            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'QUOTA_DEFAULT_SCHOOL'};
        $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}}{'SHAREDEFAULT'}=
            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'QUOTA_DEFAULT_GLOBAL'};
        # get MAILQUOTA SCHOOLDEFAULT for this role
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAILQUOTA'}{'SCHOOLDEFAULT'}=
            $ref_sophomorix_config->{'ROLES' }{$school}{$role}{'MAILQUOTA_DEFAULT'};

        # save mail adress/alias
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'MAILLISTMEMBER'}="FALSE"; # may be set to TRUE later
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'mail'}=$entry->get_value('mail');
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'displayName'}=$entry->get_value('displayName');
        ($quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'ALIASNAME'},
         $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'ALIASNAME_LONG'})=
            &Sophomorix::SophomorixBase::alias_from_name($entry->get_value('sophomorixSurnameASCII'),
                                                         $entry->get_value('sophomorixFirstnameASCII'),
                                                         $root_dns,
                                                         $ref_sophomorix_config); 
        # save USER mailquota
        if (defined $entry->get_value('sophomorixMailQuotaCalculated')){
            $quota{'QUOTA'}{'USERS'}{$sam}{'MAILQUOTA'}{'OLDCALC'}=$entry->get_value('sophomorixMailQuotaCalculated');
	} else {
            $quota{'QUOTA'}{'USERS'}{$sam}{'MAILQUOTA'}{'OLDCALC'}="";
        }
        my ($mailquota_value,$mailquota_comment)=split(/:/,$mailquota);
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixMailQuota'}{'VALUE'}=$mailquota_value;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixMailQuota'}{'COMMENT'}=$mailquota_comment;
        if ($mailquota_value ne "---" or $mailquota_comment ne "---"){
  	    push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixMailQuota'} }, $mailquota;
        }                

        # save USER quota
        foreach my $quota (@quota){
	    my ($share,$value,$oldcalc,$quotastatus,$comment)=split(/:/,$quota);
	    # remember quota
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'sophomorixQuota'}=$value;
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'OLDCALC'}=$oldcalc;
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'QUOTASTATUS'}=$quotastatus;
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'COMMENT'}=$comment;
	    # remember share for later listing
	    push @{ $quota{'QUOTA'}{'USERS'}{$sam}{'SHARELIST'} }, $share;
            # remember on which share have which users quota settings
	    push @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share}}, $sam;
            # remember nondefault quota
            if ($value ne "---" or $comment ne "---"){
    		push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixQuota'} }, $quota;
            }                
        }
        if (exists $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAddQuota'} ){
            # sort list if its there (otherwise empty list is created)
            @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAddQuota'} }= sort
	        @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAddQuota'} };
        }
    } # end USER quota


    # CLASS quota 
    # look for groups with primary membership
    # use the name CLASS in the hash for ADMINCLASS|TEACHERCLASS
    my $filter="(&".
	" (objectClass=group)".
	       "(| ".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINCLASS'}.")".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'TEACHERCLASS'}.")".
               "))";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixType',
                             'member',
                             'memberOf',
                             'mail',
                             'sophomorixQuota',
                             'sophomorixMailQuota',
                             'sophomorixMailList',
                             'sophomorixMailAlias',
                            ]);
    my $max_adminclass = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_adminclass sophomorix adminclasses found in AD");
    for( my $index = 0 ; $index < $max_adminclass ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $type=$entry->get_value('sophomorixType');
        my $school=$entry->get_value('sophomorixSchoolname');
	my $mailquota = $entry->get_value('sophomorixMailQuota');
	my $maillist = $entry->get_value('sophomorixMailList');
	my $mailalias = $entry->get_value('sophomorixMailAlias');
	my @quota = $entry->get_value('sophomorixQuota');
	my @member = $entry->get_value('member');
	my @memberof = $entry->get_value('memberOf');
        $quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'DN_by_sAMAccountName'}{$sam}=$dn;

        # save stuff about classes
  	$quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixType'}=$type;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'mail'}=$entry->get_value('mail');
	push @{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$school} }, $sam; 

        # save maillist stuff about classes
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailList'}=$maillist;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailAlias'}=$mailalias;
        if ($maillist eq "TRUE"){
            $quota{'MAILLIST'}{$sam}{'mail'}=$entry->get_value('mail');
            push @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} },$sam;
            $quota{'QUOTA'}{'LOOKUP'}{'MAILLISTS_by_SCHOOL'}{$school}{$sam}{'EXISTS'}="TRUE";
        }

        # mailquota
        my ($mailquota_value,$mailquota_comment)=split(/:/,$mailquota);
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailQuota'}{'VALUE'}=$mailquota_value;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailQuota'}{'COMMENT'}=$mailquota_comment;
        if ($mailquota_value ne "---" or $mailquota_comment ne "---"){
    	    push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixAddQuota'} }, $quota;
        }                

        # quota
	foreach my $quota (@quota){
	    my ($share,$value,$comment)=split(/:/,$quota);
            $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixQuota'}{$share}{'VALUE'}=$value;
            $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixQuota'}{$share}{'COMMENT'}=$comment;
            # remember nondefault quota
            if ($value ne "---" or $comment ne "---"){
    		push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'} }, $quota;
            }                
	    push @{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} }, $sam; 
        }
        if (exists $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'} ){
            # sort list if its there (otherwise empty list is created)
            @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'} }= sort
	        @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'} };
        }

        foreach my $member (@member){
	    my $sam_user;
	    if ( not exists $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member}){
		# if member ist not a user, skip
                next;
	    } else {
		$sam_user=$quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member};
                $quota{'QUOTA'}{'LOOKUP'}{'MEMBERS_by_CLASS'}{$sam}{$sam_user}=$member;
	    }
            # save data about class at user
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sAMAccountName'}=$sam;
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixType'}=$type;

            # save member in maillist if requested
            if ($quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailList'} eq "TRUE"){
                push @{ $quota{'MAILLIST'}{$sam}{LIST} },$quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'mail'};
                # set maillist membership at user
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLISTMEMBER'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'}{$sam}=$entry->get_value('mail');
            }

            # save alias=TRUE at user if class requests alias
            if ($quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailAlias'} eq "TRUE"){
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="TRUE";
            } else {
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="FALSE";
            }

            # save mailquota for class at user
            my ($mailquota_value,$mailquota_comment)=split(/:/,$mailquota);
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'}=$mailquota_value;
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixMailQuota'}{'COMMENT'}=$mailquota_comment;

	    # save quota for class at user
	    foreach my $quota (@quota){
	        my ($share,$value,$comment)=split(/:/,$quota);
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixQuota'}{$share}{'VALUE'}=$value;
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixQuota'}{$share}{'COMMENT'}=$value;
		# remember share for later listing
		push @{ $quota{'QUOTA'}{'USERS'}{$sam_user}{'SHARELIST'} }, $share;
                # remember on which share have which users quota settings
		push @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share}}, $sam_user;  
	    }
	}
    } # end CLASS

    # GROUP quota 
    my $filter3="(&".
	" (objectClass=group) (| ".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'PROJECT'}.")".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'GROUP'}.")".
               " ) )";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter3,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixType',
                             'member',
                             'memberOf',
                             'mail',
                             'sophomorixAddQuota',
                             'sophomorixAddMailQuota',
                             'sophomorixMailList',
                             'sophomorixMailAlias',
                            ]);
    my $max_group = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_group sophomorix projects/sophomorix-groups found in AD");
    # walk through all GROUPS
    # create GROUPS LOOKUP table
    for( my $index = 0 ; $index < $max_group ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $school=$entry->get_value('sophomorixSchoolname');
	my @member = $entry->get_value('member');
        $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'DN_by_sAMAccountName'}{$sam}=$dn;
	push @{ $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'MEMBER'}{$sam} }, @member;
    }

    # walk through all GROUPS
    # this time, update user quota
    for( my $index = 0 ; $index < $max_group ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $type=$entry->get_value('sophomorixType');
        my $school=$entry->get_value('sophomorixSchoolname');
	my $addmailquota = $entry->get_value('sophomorixAddMailQuota');
	my $maillist = $entry->get_value('sophomorixMailList');
	my $mailalias = $entry->get_value('sophomorixMailAlias');
	my @addquota = $entry->get_value('sophomorixAddQuota');
	my @member = $entry->get_value('member');
	my @memberof = $entry->get_value('memberOf');

	my $count=0;

        # save stuff about GROUPS
  	$quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixType'}=$type;
	push @{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$school} }, $sam; 

        # save maillist stuff about GROUPS
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailList'}=$maillist;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailAlias'}=$mailalias;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'mail'}=$entry->get_value('mail');
        if ($maillist eq "TRUE"){
            $quota{'MAILLIST'}{$sam}{'mail'}=$entry->get_value('mail');
            push @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} },$sam;
            $quota{'QUOTA'}{'LOOKUP'}{'MAILLISTS_by_SCHOOL'}{$school}{$sam}{'EXISTS'}="TRUE";
        }

        # addmailquota
        my ($addmailquota_value,$addmailquota_comment)=split(/:/,$addmailquota);
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'VALUE'}=$addmailquota_value;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'COMMENT'}=$addmailquota_comment;
        # remember nondefault mailquota
        if ($addmailquota_value ne "---" or $addmailquota_comment ne "---"){
  	    push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'} }, $addmailquota;
        }                

        # addquota
	foreach my $addquota (@addquota){
	    my ($share,$value,$comment)=split(/:/,$addquota);
            $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'VALUE'}=$value;
            $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'COMMENT'}=$comment;
            # remember nondefault quota
            if ($value ne "---" or $comment ne "---"){
  	        push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'} }, $addquota;
            }                
	    push @{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} }, $sam; 
        }
        if (exists $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'} ){
            # sort list if its there (otherwise empty list is created)
            @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'} }= sort
	        @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'} };
        }

	my $count_initial_member=$#member+1;
	# @addquota contains addquota info of the group
        foreach my $member (@member){
	    if (exists $seen{$member}){
		print "skipping (seen already): $member\n";
                next;
	    } else {
                $seen{$member}="seen";
	    }
	    $count++;
	    
	    # walk through all members: (user,class,groups)
	    if (exists $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member}){
                ########################################
                # member is a user
                my $sam_user=$quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member};
                #print "$sam_user is a member-USER of group $sam\n";
                # save data about GROUP at user
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixType'}=$type;
                if ($count>$count_initial_member){
                    # appended memberships		
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'REASON'}{'GROUP'}="TRUE";
                } else {
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'REASON'}{'USER'}="TRUE";
                }

                # save member in maillist if requested 
                if ($quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailList'} eq "TRUE"){
                    push @{ $quota{'MAILLIST'}{$sam}{LIST} },$quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'mail'};
                    # set maillist membership at user
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLISTMEMBER'}="TRUE";
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'}{$sam}=$entry->get_value('mail');
                }

                # save alias=TRUE at user if class requests alias
                if ($quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailAlias'} eq "TRUE"){
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="TRUE";
                } else {
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="FALSE";
                }

                # save mailquota info at user
                my ($addmailquota_value,$addmailquota_comment)=split(/:/,$addmailquota);
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'VALUE'}=$addmailquota_value;
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'COMMENT'}=$addmailquota_comment;

	        # save quota info at user
	        foreach my $addquota (@addquota){
	            my ($share,$value,$comment)=split(/:/,$addquota);
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'VALUE'}=$value;
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'COMMENT'}=$comment;
		    # remember share for later listing
		    push @{ $quota{'QUOTA'}{'USERS'}{$sam_user}{'SHARELIST'} }, $share;
	        }
	    } elsif (exists $quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'sAMAccountName_by_DN'}{$member}){
                ########################################		
                # member is a class (adminclass,teacherclass)
                my $sam_class=$quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'sAMAccountName_by_DN'}{$member};
                #print "$sam_class is a member-CLASS of group $sam\n";
		# save quota info at each user of member-CLASS
		foreach my $user (keys %{ $quota{'QUOTA'}{'LOOKUP'}{'MEMBERS_by_CLASS'}{$sam_class} }) {
                    $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixType'}=$type;
                    if ($count>$count_initial_member){
                        # appended memberships		
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'REASON'}{'GROUP'}="TRUE";
                    } else {
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'REASON'}{'CLASS'}="TRUE";
                    }

                    # save mailquota info at user
                    my ($addmailquota_value,$addmailquota_comment)=split(/:/,$addmailquota);
                    $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'VALUE'}=$addmailquota_value;
                    $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'COMMENT'}=$addmailquota_comment;

	            # save quota info at user
	            foreach my $addquota (@addquota){
	                my ($share,$value,$comment)=split(/:/,$addquota);
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'VALUE'}=$value;
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'COMMENT'}=$comment;
		        # remember share for later listing
		        push @{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }, $share;
                        # remember on which share have which users quota settings
	    	        push @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share}}, $user;                
	            }
		}
	    } elsif (exists $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'sAMAccountName_by_DN'}{$member}){
		########################################
		# member is a GROUP
                my $sam_group=$quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'sAMAccountName_by_DN'}{$member};
                #print "$sam_group is a member-GROUP of GROUP $sam\n";
		# append the members of the group so that this foreach-loop will analyse it, too
	        push @member, @{ $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'MEMBER'}{$sam_group} };
	    }
	}
    } # end GROUP quota


    ############################################################
    # update share info in %quota
    my %updated_user=();
    foreach my $user (keys %{ $quota{'QUOTA'}{'USERS'} }) {
        # uniquefi and sort sharelist
	@{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }= 
            uniq(@{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} });
	@{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }= 
            sort @{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} };

        # create alphabetical group list (is unique alredy)
        foreach my $group (keys %{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'} }) {
            push @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'}}, $group; 
        }
        if (exists $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'}){
	    @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }= 
                sort @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} };
	}

        ############################################################
        # sum up AddMailQuota from GROUPS for each share
        my $mailcalc=1;
        my $mail_group_sum=0;
        my $mail_group_string="---";
         foreach my $group ( @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
             if (exists $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'}){
                 if ($quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'} ne "---"){
                     my $add=$quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'};
                     $mail_group_sum=$mail_group_sum+$add;
                     if ($mail_group_string eq "---"){
                         $mail_group_string=$add;
                     } else {
                         $mail_group_string=$mail_group_string."+".$add;
                     }
                 }
             }
        }
        $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'GROUPSTRING'}=$mail_group_string;
        $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'GROUPSUM'}=$mail_group_sum;

        ############################################################
        # add everything up (mailquota)
        if ($quota{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'} eq "---"){
            # start with nothing as quota
            my $base=$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NOQUOTA'};
            if ($quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'} ne "---"){
                $base=$quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'};
            } elsif (exists $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'SCHOOLDEFAULT'}){
                $base=$quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'SCHOOLDEFAULT'};
            }
            $mailcalc=$base+$mail_group_sum;
        } else {
            $mailcalc=$quota{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'}
        }
        # add addmailquota
        $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}=$mailcalc;

        # check for updates
        if (not defined $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}){
            # nothing set
            $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}="TRUE";
            $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'REASON'}{'Not set: sophomorixMailQuotaCalculated'}="TRUE";
        } else {
            # sophomorixMailQuotaCalculated defined
            if ($mailcalc ne $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}){
               # new caluladed value
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'REASON'}{'Not set: sophomorixMailQuotaCalculated'}="TRUE";
            }
        }
        # update user counter
        if (defined $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} and
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
            $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERMAILQUOTA'}++;
	}
        # FALSE if not set to TRUE
        if (not exists $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}){
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}="FALSE";
        }


        ############################################################
        # sum up AddQuota from GROUPS for each share
        my $calc=1;
        foreach my $share ( @{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }) {
            my $group_sum=0;
            my $group_string="---";
            my $quota_user;
  	    if (defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'sophomorixQuota'}){
	         $quota_user=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'sophomorixQuota'};
	    } else {
                $quota_user="---";
	    }
            my $quota_class; # for this share
	    if (defined $quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixQuota'}{$share}{'VALUE'}){
	        $quota_class=$quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixQuota'}{$share}{'VALUE'};
	    } else {
                $quota_class="---";
            }
            # save the quota values of a GROUP for later use
            foreach my $group ( @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
                if (exists $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'}){
                    if ($quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'} ne "---"){
                        my $add=$quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'};
                        $group_sum=$group_sum+$add;
                        if ($group_string eq "---"){
                            $group_string=$add;
                        } else {
                            $group_string=$group_string."+".$add;
                        }
                    }
                }
            } # end group

            $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'GROUPSTRING'}=$group_string;
            $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'GROUPSUM'}=$group_sum;

            ############################################################
            # add everything up (quota)
            if ($quota_user eq "---"){
                # start with nothing as quota
                my $base=$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NOQUOTA'};
                # check for class quota
                if ($quota_class ne "---"){
                    $base=$quota_class;
	        } elsif (exists $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'SHAREDEFAULT'}) {
                    $base=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'SHAREDEFAULT'};
                }
                # add addquota
                $calc=$base+$group_sum;
            } else {
                # override with quota from user attribute
                $calc=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'sophomorixQuota'};
            }
            # update CALC
            $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'CALC'}=$calc;
            # update sophomorixCloudQuotaCalculated
            if ($share eq $quota{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'}){
                my $role=$quota{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};
                my $school=$quota{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'};
                my $percentage=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'CLOUDQUOTA_PERCENTAGE'};
                my $cloudquota_calc=int($calc*$percentage/100);
                $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'PERCENTAGE'}=$percentage;
                $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC'}=$cloudquota_calc." MB";
                $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC_MB'}=$cloudquota_calc;
            }

            # add --- for undefined values
            if (not defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'OLDCALC'}){
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'OLDCALC'}="---";
            }
            if (not defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}){
		$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}="---";
            }

            # some shortnames for vars
            $oldcalc=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'OLDCALC'};
            $quotastatus=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'};

            # check for updates
            if ($quotastatus=~/[^0-9]/){
                # nonumbers
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'REASON'}{'NonNumbers in QUOTASTATUS'}="TRUE";
            }

            if ($calc ne $oldcalc){
                # new caluladed value
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'REASON'}{'CALC differs from OLDCALC'}="TRUE";
            }

            if ($oldcalc eq "---"){
                # no oldcalc set
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'REASON'}{'OLDCALC is ---'}="TRUE";
            }

            # check update of sophomorixCloudQuotaCalculated
            if ($share eq $quota{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'}){
                if ($quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC'} ne 
                    $quota{'QUOTA'}{'USERS'}{$user}{'sophomorixCloudQuotaCalculated'}){
                    $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'ACTION'}{'UPDATE'}="TRUE";
                } else {
                    $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'ACTION'}{'UPDATE'}="FALSE";
                }
            }

            # increase share counter
            if (defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} and
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} eq "TRUE"){
                if ( not exists $updated_user{$user} ){
                    # update user counter only once for a user
                    $updated_user{$user}="updated";
                    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERS'}++;
                }
                $quota{'QUOTA'}{'UPDATE_COUNTER'}{'SHARES'}++;
            }

            # FALSE if not set to TRUE
            if (not exists $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}){
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="FALSE";
            }

            # use smbcquotas
            if ($smbcquotas==1){
		if ( exists $smbcquotas_users{$user} or
                     $user_opt eq ""
                   ){
                    # Add the smbcquotas result to the JSON object
                    ($quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED_KiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT_KiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT_KiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED_MiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT_MiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT_MiB'},
                   )=&AD_smbcquotas_queryuser(
                        $root_dns,
                        $smb_admin_pass,
                        $user,
                        $share,
			$ref_sophomorix_config);
	        }
            }
	} # end share
    } # end user
    
    # uniquify and sort sharelist at all users
    foreach my $share (keys %{ $quota{'LISTS'}{'USER_by_SHARE'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} });
	@{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} }= 
            sort @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'USER_by_SCHOOL'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} });
	@{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} }= 
            sort @{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'CLASS_by_SCHOOL'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} });
	@{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} }= 
            sort @{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'CLASS_by_SHARE'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} });
	@{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} }= 
            sort @{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} });
	@{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} }= 
            sort @{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'GROUPS_by_SHARE'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} });
	@{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} }= 
            sort @{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} };
    }
    # sort maillist stuff
    foreach my $school (keys %{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'} }) {
        @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} } = sort @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} };
        foreach my $maillist (keys %{ $quota{'MAILLIST'} } ){
            if ($#{$quota{'MAILLIST'}{$maillist}{'LIST'} } >0){
	        @{ $quota{'MAILLIST'}{$maillist}{'LIST'} } = sort @{ $quota{'MAILLIST'}{$maillist}{'LIST'} };
            }
        }
    }

    return(\%quota);
}



sub AD_get_full_groupdata {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $grouplist = $arg_ref->{grouplist};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my @grouplist=split(/,/,$grouplist);
    my $filter;
    if ($#grouplist==0){
        $filter="(& (sophomorixType=*) (sAMAccountName=".$grouplist[0]."))"; 
    } else {
        $filter="(& (sophomorixType=*) (|";
        foreach my $group (@grouplist){
           $filter=$filter." (sAMAccountName=".$group.")";

        } 
        $filter=$filter." ))";
    }

    #print "$filter\n";
    my %groups=();
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                       );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');
        push @{ $groups{'LISTS'}{'GROUPS'} }, $sam;

        $groups{'GROUPS'}{$sam}{'dn'}=$entry->dn();
        $groups{'GROUPS'}{$sam}{'sAMAccountName'}=$entry->get_value('sAMAccountName');
        $groups{'GROUPS'}{$sam}{'cn'}=$entry->get_value('cn');
        $groups{'GROUPS'}{$sam}{'description'}=$entry->get_value('description');
        $groups{'GROUPS'}{$sam}{'gidNumber'}=$entry->get_value('gidNumber');
        $groups{'GROUPS'}{$sam}{'displayName'}=$entry->get_value('displayName');
        $groups{'GROUPS'}{$sam}{'mail'}=$entry->get_value('mail');
        @{ $groups{'GROUPS'}{$sam}{'memberOf'} } = sort $entry->get_value('memberOf');
        @{ $groups{'GROUPS'}{$sam}{'member'} } = sort $entry->get_value('member');

        $groups{'GROUPS'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
        $groups{'GROUPS'}{$sam}{'sophomorixType'}=$entry->get_value('sophomorixType');
        $groups{'GROUPS'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
        $groups{'GROUPS'}{$sam}{'sophomorixCreationDate'}=$entry->get_value('sophomorixCreationDate');
        $groups{'GROUPS'}{$sam}{'sophomorixJoinable'}=$entry->get_value('sophomorixJoinable');
        $groups{'GROUPS'}{$sam}{'sophomorixHidden'}=$entry->get_value('sophomorixHidden');
        $groups{'GROUPS'}{$sam}{'sophomorixMaxMembers'}=$entry->get_value('sophomorixMaxMembers');
        $groups{'GROUPS'}{$sam}{'sophomorixMailList'}=$entry->get_value('sophomorixMailList');
        $groups{'GROUPS'}{$sam}{'sophomorixMailAlias'}=$entry->get_value('sophomorixMailAlias');
        $groups{'GROUPS'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
        $groups{'GROUPS'}{$sam}{'sophomorixMailQuota'}=$entry->get_value('sophomorixMailQuota');
        $groups{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}=$entry->get_value('sophomorixAddMailQuota');

        @{ $groups{'GROUPS'}{$sam}{'sophomorixQuota'} } = sort $entry->get_value('sophomorixQuota');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixAddQuota'} } = sort $entry->get_value('sophomorixAddQuota');

        @{ $groups{'GROUPS'}{$sam}{'sophomorixAdmins'} } = sort $entry->get_value('sophomorixAdmins');
        $groups{'GROUPS'}{$sam}{'sophomorixAdmins_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixAdmins'} }+1;

        @{ $groups{'GROUPS'}{$sam}{'sophomorixMembers'} } = sort $entry->get_value('sophomorixMembers');
        $groups{'GROUPS'}{$sam}{'sophomorixMembers_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixMembers'} }+1;

        @{ $groups{'GROUPS'}{$sam}{'sophomorixAdminGroups'} } = sort $entry->get_value('sophomorixAdminGroups');
        $groups{'GROUPS'}{$sam}{'sophomorixAdminGroups_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixAdminGroups'} }+1;

        @{ $groups{'GROUPS'}{$sam}{'sophomorixMemberGroups'} } = sort $entry->get_value('sophomorixMemberGroups');
        $groups{'GROUPS'}{$sam}{'sophomorixMemberGroups_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixMemberGroups'} }+1;
    }
    $groups{'COUNTER'}{'TOTAL'}=$max;
    if ($max>0){
        @{ $groups{'LISTS'}{'GROUPS'} } = sort @{ $groups{'LISTS'}{'GROUPS'} };
    }    
    if ($max==0){
        print "0 groups found\n";
    }
    return \%groups;
}



sub AD_get_full_userdata {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $userlist = $arg_ref->{userlist};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my @userlist=split(/,/,$userlist); # list of parameters, could be 'beck*'
    my $filter;
    my %users=();

    if ($#userlist==0){
        $filter="(& (sophomorixRole=*) (sAMAccountName=".$userlist[0]."))"; 
    } else {
        $filter="(& (sophomorixRole=*) (|";
        foreach my $user (@userlist){
            $filter=$filter." (sAMAccountName=".$user.")";
        } 
        $filter=$filter." ))";
    }
    #print "$filter\n";
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                       );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');

        # this is the userlist of all users found, i.e. 'becker,beckerle'
        push @{ $users{'LISTS'}{'USERS'} }, $sam;

        $users{'USERS'}{$sam}{'dn'}=$entry->dn();
        $users{'USERS'}{$sam}{'sAMAccountName'}=$entry->get_value('sAMAccountName');
        $users{'USERS'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
        $users{'USERS'}{$sam}{'sophomorixRole'}=$entry->get_value('sophomorixRole');
        $users{'USERS'}{$sam}{'sophomorixUserToken'}=$entry->get_value('sophomorixUserToken');
        $users{'USERS'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
        $users{'USERS'}{$sam}{'sophomorixCreationDate'}=$entry->get_value('sophomorixCreationDate');
        $users{'USERS'}{$sam}{'sophomorixTolerationDate'}=$entry->get_value('sophomorixTolerationDate');
        $users{'USERS'}{$sam}{'sophomorixDeactivationDate'}=$entry->get_value('sophomorixDeactivationDate');
        $users{'USERS'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
        $users{'USERS'}{$sam}{'sophomorixExitAdminClass'}=$entry->get_value('sophomorixExitAdminClass');
        $users{'USERS'}{$sam}{'sophomorixFirstPassword'}=$entry->get_value('sophomorixFirstPassword');
        $users{'USERS'}{$sam}{'sophomorixFirstnameASCII'}=$entry->get_value('sophomorixFirstnameASCII');
        $users{'USERS'}{$sam}{'sophomorixSurnameASCII'}=$entry->get_value('sophomorixSurnameASCII');

        $users{'USERS'}{$sam}{'sophomorixFirstnameInitial'}=$entry->get_value('sophomorixFirstnameInitial');
        $users{'USERS'}{$sam}{'sophomorixSurnameInitial'}=$entry->get_value('sophomorixSurnameInitial');

        $users{'USERS'}{$sam}{'sophomorixBirthdate'}=$entry->get_value('sophomorixBirthdate');
        $users{'USERS'}{$sam}{'sophomorixUnid'}=$entry->get_value('sophomorixUnid');
        @{ $users{'USERS'}{$sam}{'sophomorixWebuiPermissions'} } = 
             sort $entry->get_value('sophomorixWebuiPermissions');
        @{ $users{'USERS'}{$sam}{'sophomorixWebuiPermissionsCalculated'} } = 
             sort $entry->get_value('sophomorixWebuiPermissionsCalculated');

        $users{'USERS'}{$sam}{'sn'}=$entry->get_value('sn');
        $users{'USERS'}{$sam}{'givenName'}=$entry->get_value('givenName');
        $users{'USERS'}{$sam}{'cn'}=$entry->get_value('cn');
        $users{'USERS'}{$sam}{'displayName'}=$entry->get_value('displayName');
        $users{'USERS'}{$sam}{'userAccountControl'}=$entry->get_value('userAccountControl');
        $users{'USERS'}{$sam}{'mail'}=$entry->get_value('mail');
        $users{'USERS'}{$sam}{'sophomorixSchoolPrefix'}=$entry->get_value('sophomorixSchoolPrefix');
        $users{'USERS'}{$sam}{'sophomorixAdminFile'}=$entry->get_value('sophomorixAdminFile');
        $users{'USERS'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
        $users{'USERS'}{$sam}{'sophomorixExamMode'}=$entry->get_value('sophomorixExamMode');
        $users{'USERS'}{$sam}{'sophomorixCloudQuotaCalculated'}=$entry->get_value('sophomorixCloudQuotaCalculated');
        $users{'USERS'}{$sam}{'sophomorixMailQuotaCalculated'}=$entry->get_value('sophomorixMailQuotaCalculated');
        $users{'USERS'}{$sam}{'sophomorixMailQuota'}=$entry->get_value('sophomorixMailQuota');
        @{ $users{'USERS'}{$sam}{'memberOf'} } = sort $entry->get_value('memberOf');
        @{ $users{'USERS'}{$sam}{'sophomorixQuota'} } = sort $entry->get_value('sophomorixQuota');

        # Intrinsic attributes
        $users{'USERS'}{$sam}{'sophomorixIntrinsic1'}=$entry->get_value('sophomorixIntrinsic1');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic2'}=$entry->get_value('sophomorixIntrinsic2');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic3'}=$entry->get_value('sophomorixIntrinsic3');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic4'}=$entry->get_value('sophomorixIntrinsic4');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic5'}=$entry->get_value('sophomorixIntrinsic5');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti1'} } = sort $entry->get_value('sophomorixIntrinsicMulti1');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti2'} } = sort $entry->get_value('sophomorixIntrinsicMulti2');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti3'} } = sort $entry->get_value('sophomorixIntrinsicMulti3');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti4'} } = sort $entry->get_value('sophomorixIntrinsicMulti4');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti5'} } = sort $entry->get_value('sophomorixIntrinsicMulti5');

        # custom attributes
        $users{'USERS'}{$sam}{'sophomorixCustom1'}=$entry->get_value('sophomorixCustom1');
        $users{'USERS'}{$sam}{'sophomorixCustom2'}=$entry->get_value('sophomorixCustom2');
        $users{'USERS'}{$sam}{'sophomorixCustom3'}=$entry->get_value('sophomorixCustom3');
        $users{'USERS'}{$sam}{'sophomorixCustom4'}=$entry->get_value('sophomorixCustom4');
        $users{'USERS'}{$sam}{'sophomorixCustom5'}=$entry->get_value('sophomorixCustom5');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti1'} } = sort $entry->get_value('sophomorixCustomMulti1');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti2'} } = sort $entry->get_value('sophomorixCustomMulti2');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti3'} } = sort $entry->get_value('sophomorixCustomMulti3');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti4'} } = sort $entry->get_value('sophomorixCustomMulti4');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti5'} } = sort $entry->get_value('sophomorixCustomMulti5');

        # samba
        $users{'USERS'}{$sam}{'homeDirectory'}=$entry->get_value('homeDirectory');
        $users{'USERS'}{$sam}{'homeDrive'}=$entry->get_value('homeDrive');
        $users{'USERS'}{$sam}{'accountExpires'}=$entry->get_value('accountExpires');
        $users{'USERS'}{$sam}{'badPasswordTime'}=$entry->get_value('badPasswordTime');
        $users{'USERS'}{$sam}{'badPwdCount'}=$entry->get_value('badPwdCount');
        $users{'USERS'}{$sam}{'codePage'}=$entry->get_value('codePage');
        $users{'USERS'}{$sam}{'countryCode'}=$entry->get_value('countryCode');
        $users{'USERS'}{$sam}{'lastLogoff'}=$entry->get_value('lastLogoff');
        $users{'USERS'}{$sam}{'lastLogon'}=$entry->get_value('lastLogon');
        $users{'USERS'}{$sam}{'logonCount'}=$entry->get_value('logonCount');
        $users{'USERS'}{$sam}{'objectSid'}=$entry->get_value('objectSid');
        $users{'USERS'}{$sam}{'objectGUID'}=$entry->get_value('objectGUID');
        $users{'USERS'}{$sam}{'pwdLastSet'}=$entry->get_value('pwdLastSet');
        $users{'USERS'}{$sam}{'sAMAccountType'}=$entry->get_value('sAMAccountType');
        $users{'USERS'}{$sam}{'userPrincipalName'}=$entry->get_value('userPrincipalName');
        $users{'USERS'}{$sam}{'uSNChanged'}=$entry->get_value('uSNChanged');
        $users{'USERS'}{$sam}{'uSNCreated'}=$entry->get_value('uSNCreated');
        # unix
        $users{'USERS'}{$sam}{'uidNumber'}=$entry->get_value('uidNumber');
        $users{'USERS'}{$sam}{'unixHomeDirectory'}=$entry->get_value('unixHomeDirectory');
        $users{'USERS'}{$sam}{'primaryGroupID'}=$entry->get_value('primaryGroupID');
        # password from file
        if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_ALLADMINS'}{$entry->get_value('sophomorixRole')}){
            # check for password file
            my $pwf="FALSE";
            my $password="Password was not saved on the server!";
            my $pwd_file=$ref_sophomorix_config->{'INI'}{'PATHS'}{'SECRET_PWD'}."/".$sam;
            if (-e $pwd_file){
                $pwf="TRUE";
                $password=`cat $pwd_file`;
            }
            $users{'USERS'}{$sam}{'PWDFile'}=$pwd_file;
            $users{'USERS'}{$sam}{'PWDFileExists'}=$pwf;
            $users{'USERS'}{$sam}{'PASSWORD'}=$password;
        }
        
    }
    $users{'COUNTER'}{'TOTAL'}=$max;
    if ($max>0){
        @{ $users{'LISTS'}{'USERS'} } = sort @{ $users{'LISTS'}{'USERS'} };
    }    

    # read logfiles for each user that was found
    foreach my $user (@{ $users{'LISTS'}{'USERS'} }){
        my $anything_found=0;
        my $log_add=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	    $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_ADD'};
        my $log_update=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	    $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_UPDATE'};
        my $log_kill=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	    $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_KILL'};
        # ADD
        if (-f $log_add){
            open(ADD,"<$log_add");
            while (<ADD>) {
                my ($add,$epoch,$date,$school,$login,$last,$first,$group,$role,$unid) = split(/::/);
                if ($login eq $user){
                    $anything_found++;
                    $users{'LOOKUP'}{'LOGUSERS'}{$user}{'FOUND'}="TRUE";
                    if (not exists $users{'USERS'}{$user}{'sAMAccountName'}){
                        push @{ $users{'LISTS'}{'DELETED_USERS'} }, $user;
                    }
                    my $human_date=&Sophomorix::SophomorixBase::ymdhms_to_date($date);
                    my $logline="ADD:  $human_date  $login ($last, $first) in $group as $role";
                    push @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} },$epoch ;
                    $users{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}=$logline;
                }
            }
            close(ADD);
        }

        # KILL
        if (-f $log_kill){
            open(KILL,"<$log_kill");
            while (<KILL>) {
                my ($kill,$epoch,$date,$school,$login,$last,$first,$group,$role,$unid,$info) = split(/::/);
                if ($login eq $user){
                    $anything_found++;
                    $users{'LOOKUP'}{'LOGUSERS'}{$user}{'FOUND'}="TRUE";
                    if (not exists $users{'USERS'}{$user}{'sAMAccountName'}){
                        push @{ $users{'LISTS'}{'DELETED_USERS'} }, $user;
                    }
                    my $human_date=&Sophomorix::SophomorixBase::ymdhms_to_date($date);
                    my $logline;
                    if ($info eq "MIGRATED"){
                        $logline="KILL: $human_date  $login ($last, $first), MIGRATED";
                    } else {
                        $logline="KILL: $human_date  $login ($last, $first) in $group as $role";
                    }
                    push @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} },$epoch ;
                    $users{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}=$logline;
                }
            }
            close(KILL);
        }
        if ($anything_found==0 and not exists $users{'USERS'}{$user}){
            push @{ $users{'LISTS'}{'UNKNOWN_USERS'} }, $user;
        }
        # order epoch entries
        if ($#{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }>0){
	    @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }=sort @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} };
            $users{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'}=$#{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }+1;
        } else {
            $users{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'}=$#{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }+1;
        }
    }

    if ($max==0){
        print "0 users found in AD\n";
    }
    @{ $users{'LISTS'}{'DELETED_USERS'} } = uniq(@{ $users{'LISTS'}{'DELETED_USERS'} });
    return \%users;
}



sub AD_get_full_devicedata {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $devicelist = $arg_ref->{devicelist};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my @devicelist=split(/,/,$devicelist); # list of parameters, could be 'j1010*'
    my %devices=();

    ### create filter
    my $filter=&_create_filter_alldevices(\@devicelist,$ref_sophomorix_config);
    # print "Filter: $filter\n";

    # search
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                       );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');
        # this is the devicelist of all devices found, i.e. 'j1010p01' 'j1010p01' ... 
        push @{ $devices{'LISTS'}{'DEVICES'} }, $sam;

        $devices{'DEVICES'}{$sam}{'dn'}=$entry->dn();
        $devices{'DEVICES'}{$sam}{'sAMAccountName'}=$entry->get_value('sAMAccountName');
        $devices{'DEVICES'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
        $devices{'DEVICES'}{$sam}{'sophomorixRole'}=$entry->get_value('sophomorixRole');
        $devices{'DEVICES'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
        $devices{'DEVICES'}{$sam}{'sophomorixCreationDate'}=$entry->get_value('sophomorixCreationDate');
        $devices{'DEVICES'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
        $devices{'DEVICES'}{$sam}{'cn'}=$entry->get_value('cn');
        $devices{'DEVICES'}{$sam}{'name'}=$entry->get_value('name');
        $devices{'DEVICES'}{$sam}{'displayName'}=$entry->get_value('displayName');
        $devices{'DEVICES'}{$sam}{'userAccountControl'}=$entry->get_value('userAccountControl');
        @{ $devices{'DEVICES'}{$sam}{'servicePrincipalName'} } = sort $entry->get_value('servicePrincipalName');

        #$devices{'DEVICES'}{$sam}{'mail'}=$entry->get_value('mail');
        $devices{'DEVICES'}{$sam}{'sophomorixSchoolPrefix'}=$entry->get_value('sophomorixSchoolPrefix');
        $devices{'DEVICES'}{$sam}{'sophomorixAdminFile'}=$entry->get_value('sophomorixAdminFile');
        $devices{'DEVICES'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
        $devices{'DEVICES'}{$sam}{'sophomorixDnsNodename'}=$entry->get_value('sophomorixDnsNodename');
        $devices{'DEVICES'}{$sam}{'dNSHostName'}=$entry->get_value('dNSHostName');
        @{ $devices{'DEVICES'}{$sam}{'memberOf'} } = sort $entry->get_value('memberOf');

        # samba
        #$devices{'DEVICES'}{$sam}{'homeDirectory'}=$entry->get_value('homeDirectory');
        #$devices{'DEVICES'}{$sam}{'homeDrive'}=$entry->get_value('homeDrive');
        $devices{'DEVICES'}{$sam}{'accountExpires'}=$entry->get_value('accountExpires');
        $devices{'DEVICES'}{$sam}{'badPasswordTime'}=$entry->get_value('badPasswordTime');
        $devices{'DEVICES'}{$sam}{'badPwdCount'}=$entry->get_value('badPwdCount');
        $devices{'DEVICES'}{$sam}{'codePage'}=$entry->get_value('codePage');
        $devices{'DEVICES'}{$sam}{'countryCode'}=$entry->get_value('countryCode');
        $devices{'DEVICES'}{$sam}{'lastLogoff'}=$entry->get_value('lastLogoff');
        $devices{'DEVICES'}{$sam}{'lastLogon'}=$entry->get_value('lastLogon');
        $devices{'DEVICES'}{$sam}{'logonCount'}=$entry->get_value('logonCount');
        $devices{'DEVICES'}{$sam}{'objectSid'}=$entry->get_value('objectSid');
        $devices{'DEVICES'}{$sam}{'objectGUID'}=$entry->get_value('objectGUID');
        $devices{'DEVICES'}{$sam}{'pwdLastSet'}=$entry->get_value('pwdLastSet');
        $devices{'DEVICES'}{$sam}{'sAMAccountType'}=$entry->get_value('sAMAccountType');
        #$devices{'DEVICES'}{$sam}{'userPrincipalName'}=$entry->get_value('userPrincipalName');
        $devices{'DEVICES'}{$sam}{'uSNChanged'}=$entry->get_value('uSNChanged');
        $devices{'DEVICES'}{$sam}{'uSNCreated'}=$entry->get_value('uSNCreated');
        # unix
        $devices{'DEVICES'}{$sam}{'primaryGroupID'}=$entry->get_value('primaryGroupID');

        ############################################################
        # searching DNS node
        my $base="CN=MicrosoftDNS,DC=DomainDnsZones,".$root_dse;
        #my $base="DC=DomainDnsZones,".$root_dse;
        my $filter="(& (objectClass=dnsNode) ".
                   "(cn=".$devices{'DEVICES'}{$sam}{'sophomorixDnsNodename'}.") ".
                   "(name=".$devices{'DEVICES'}{$sam}{'sophomorixDnsNodename'}.")".
                   " )";
        # print "dnsNode filter: $filter\n";
        # print "dnsNode searchbase: $base\n";
        my $mesg = $ldap->search(
                          base   => $base,
                          scope => 'sub',
                          filter => $filter,
                         );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        my $max_dns = $mesg->count;
        if ($max_dns==1){
            my $entry = $mesg->entry(0);
            $devices{'DEVICES'}{$sam}{'dnsNode'}{'dn'}=$entry->dn();
            $devices{'DEVICES'}{$sam}{'dnsNode'}{'cn'}=$entry->get_value('cn');
            $devices{'DEVICES'}{$sam}{'dnsNode'}{'name'}=$entry->get_value('name');
            $devices{'DEVICES'}{$sam}{'dnsNode'}{'adminDescription'}=$entry->get_value('adminDescription');
            $devices{'DEVICES'}{$sam}{'dnsNode'}{'dnsRecord'}=$entry->get_value('dnsRecord');
        } else {
            print "ERROR: $max_dns dnsNodes found\n";
        }
    }
    $devices{'COUNTER'}{'TOTAL'}=$max;
    if ($max==0){
        print "0 devices found in AD\n";
        print "\n";
    }
    # more ?????

    return \%devices;
}



sub AD_get_groups_v {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %groups=();
    foreach my $school (@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }){
        # set back school counters
        $groups{'COUNTER'}{$school}{'by_type'}{'project'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'adminclass'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'extraclass'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'teacherclass'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'class'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'sophomorix-group'}=0;
    }

    ############################################################
    # create lookup dn -> role
    ############################################################
    my $user_filter="(objectClass=user)"; 
    # print "Filter: $user_filter\n";
    my $mesg0 = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $user_filter,
                      attr => ['sAMAccountName',
                               'dn',
                               'sophomorixRole',
                              ]);
    &AD_debug_logdump($mesg0,2,(caller(0))[3]);
    my $max_user = $mesg0->count;
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg0->entry($index);
        $groups{'LOOKUP'}{'sophomorixRole_by_DN'}{$entry->dn()}=$entry->get_value('sophomorixRole');
    }

    ##################################################
    # search for all sophomorix groups
    # Setting the filters
    my $filter="(objectClass=group)"; 
    # print "Filter: $filter\n";
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['sAMAccountName',
                               'cn',
                               'displayName',
                               'description',
                               'sophomorixType',
                               'sophomorixHidden',
                               'sophomorixStatus',
                               'sophomorixQuota',
                               'sophomorixMailQuota',
                               'sophomorixAddQuota',
                               'sophomorixAddMailQuota',
                               'sophomorixMailAlias',
                               'sophomorixMailList',
                               'sophomorixJoinable',
                               'sophomorixMaxMembers',
                               'sophomorixSchoolname',
                               'member',
                              ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    ##################################################
    # walk through all results
    # save results in lists
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $type=$entry->get_value('sophomorixType');
        my $status=$entry->get_value('sophomorixStatus');
        my $schoolname=$entry->get_value('sophomorixSchoolname');
        if (not defined $type or not defined $status){
            # non sophomorix group
            $groups{'COUNTER'}{'OTHER'}++;
            $groups{'GROUPS_by_sophomorixType'}{'OTHER'}{$sam}=$dn;
            $groups{'GROUPS'}{$sam}{'DN'}=$dn;
       } else {
            # sophomorix group
            $groups{'COUNTER'}{$schoolname}{'TOTAL'}++;
            $groups{'COUNTER'}{$schoolname}{'status_by_type'}{$type}{$status}++;
            $groups{'COUNTER'}{$schoolname}{'by_type'}{$type}++;
            push @{ $groups{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$schoolname}{$type} },$sam;
            if ($type eq "adminclass" or $type eq "teacherclass" or $type eq "extraclass"){
                $groups{'COUNTER'}{$schoolname}{'by_type'}{'class'}++;
                push @{ $groups{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$schoolname}{'class'} },$sam;
            }
            $groups{'GROUPS'}{$sam}{'DN'}=$dn;
            $groups{'GROUPS'}{$sam}{'sophomorixStatus'}=$status;
            $groups{'GROUPS'}{$sam}{'displayName'}=$entry->get_value('displayName');
            $groups{'GROUPS'}{$sam}{'sophomorixMailQuota'}=$entry->get_value('sophomorixMailQuota');
            $groups{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}=$entry->get_value('sophomorixAddMailQuota');
            @{ $groups{'GROUPS'}{$sam}{'sophomorixQuota'} }=$entry->get_value('sophomorixQuota');
            @{ $groups{'GROUPS'}{$sam}{'sophomorixAddQuota'} }=$entry->get_value('sophomorixAddQuota');
            $groups{'GROUPS'}{$sam}{'sophomorixMaxMembers'}=$entry->get_value('sophomorixMaxMembers');
            $groups{'GROUPS'}{$sam}{'sophomorixHidden'}=$entry->get_value('sophomorixHidden');
            $groups{'GROUPS'}{$sam}{'sophomorixMailAlias'}=$entry->get_value('sophomorixMailAlias');
            $groups{'GROUPS'}{$sam}{'sophomorixMailList'}=$entry->get_value('sophomorixMailList');
            $groups{'GROUPS'}{$sam}{'sophomorixJoinable'}=$entry->get_value('sophomorixJoinable');
            $groups{'GROUPS'}{$sam}{'description'}=$entry->get_value('description');
            # count members
            @{ $groups{'GROUPS'}{$sam}{'member'}{'TOTAL'} }=$entry->get_value('member');
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'TOTAL'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'TOTAL'} }+1;
            # sort members into role ????
            # query all users
            # create lookup dn --> role
            foreach my $mem_dn (@{ $groups{'GROUPS'}{$sam}{'member'}{'TOTAL'} }){
                my $role;
                if ( defined $groups{'LOOKUP'}{'sophomorixRole_by_DN'}{$mem_dn} ){
                    $role=$groups{'LOOKUP'}{'sophomorixRole_by_DN'}{$mem_dn};
                } else {
                    $role="OTHER";
                }
                push @{ $groups{'GROUPS'}{$sam}{'member'}{$role} },$mem_dn;
            }
            # count the entries for certain roles
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'student'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'student'} }+1;
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'teacher'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'teacher'} }+1;
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'OTHER'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'OTHER'} }+1;
#            $groups{'GROUPS'}{$sam}{''}=$entry->get_value('');
#            $groups{'GROUPS'}{$sam}{''}=$entry->get_value('');
        }
    }
    return \%groups;
}



sub AD_get_users_v {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $admins_only = $arg_ref->{admins_only};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if (not defined $admins_only){
	$admins_only="FALSE";
    }

    my %users=();
    # set back global counters
    $users{'COUNTER'}{'global'}{'by_role'}{'globaladministrator'}=0;
    $users{'COUNTER'}{'global'}{'by_role'}{'globalbinduser'}=0;
    foreach my $school (@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }){
        # set back school counters
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'P'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'P'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'U'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'U'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'A'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'A'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'E'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'E'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'S'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'S'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'T'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'T'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'D'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'D'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'L'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'L'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'F'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'F'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'R'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'R'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'K'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'K'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'student'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'teacher'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'schooladministrator'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'computer'}=0;
        $users{'COUNTER'}{$school}{'TOTAL'}=0;
    }

    ##################################################
    # search for all users and computers
    # Setting the filters
    my $filter;
    if ($admins_only eq "TRUE"){
        $filter="(&(objectClass=user) (| ".
                "(sophomorixRole=schoolbinduser) ".
                "(sophomorixRole=globalbinduser) ".
                "(sophomorixRole=schooladministrator) ".
                "(sophomorixRole=globaladministrator)) )";
    } else {
        $filter="( |(objectClass=user) (objectClass=computer) )"; 
    }
    # print "Filter: $filter\n";
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['sAMAccountName',
                               'cn',
                               'displayName',
                               'sophomorixRole',
                               'sophomorixStatus',
                               'sophomorixSchoolname',
                               'sophomorixComment',
                               'sophomorixAdminClass',
                              ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;

    ##################################################
    # walk through all users/computers
    # save results in lists
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $role=$entry->get_value('sophomorixRole');
        my $status=$entry->get_value('sophomorixStatus');
        my $schoolname=$entry->get_value('sophomorixSchoolname');
        if (not defined $role or not defined $status){
            # non sophomorix user
            $users{'COUNTER'}{'OTHER'}++;
            $users{'USERS_by_sophomorixRole'}{'OTHER'}{$sam}=$dn;
            $users{'USERS'}{$sam}{'DN'}=$dn;
            push @{ $users{'LISTS'}{'USER_by_SCHOOL'}{'OTHER'}{'OTHER'} },$sam;
        } else {
            # sophomorix user
            $users{'COUNTER'}{$schoolname}{'TOTAL'}++;
            $users{'COUNTER'}{$schoolname}{'status_by_role'}{$role}{$status}++;
            $users{'COUNTER'}{$schoolname}{'by_role'}{$role}++;
            $users{'USERS'}{$sam}{'DN'}=$dn;
            $users{'USERS'}{$sam}{'sophomorixStatus'}=$status;
            $users{'USERS'}{$sam}{'displayName'}=$entry->get_value('displayName');
            $users{'USERS'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
            $users{'USERS'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
            push @{ $users{'LISTS'}{'USER_by_sophomorixSchoolname'}{$schoolname}{$role} },$sam;
            # if its an administrator
            if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_ALLADMINS'}{$role}){
                # check for password file
                my $pwf="FALSE";
                my $pwd_file=$ref_sophomorix_config->{'INI'}{'PATHS'}{'SECRET_PWD'}."/".$sam;
                if (-e $pwd_file){
                    $pwf="TRUE";
                }
                $users{'USERS'}{$sam}{'PWDFileExists'}=$pwf;
            }
        }
    }
    return \%users;
}



sub AD_get_shares_v {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %shares=();

    # helper lists
    my @other=();   # other shares
    my @schools=(); # schools

    # add all schools to lists
    foreach my $school ( @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} } ) {
        $shares{'SHARES'}{$school}{'TYPE'}="SCHOOL";
        push @schools, $school;
    }

    # add all shares to lists
    foreach my $share ( @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} } ) {
        if (exists $ref_sophomorix_config->{'SCHOOLS'}{$share} ) {
            # school
            $shares{'SHARES'}{$share}{'TYPE'}="SCHOOL";
            push @schools, $share;
        } elsif ($share eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
            # push not in a list, prepended later
            $shares{'SHARES'}{$share}{'TYPE'}="GLOBAL";
        } else {
            # other
            $shares{'SHARES'}{$share}{'TYPE'}="OTHER_SHARE";
            push @other, $share;
        }
    }

    # uniquifi the schools
    @schools = uniq(@schools);
    @schools = sort @schools;

    # create list: global,schools,other shares
    my @shares=($ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},@schools,@other);

    foreach my $share ( @shares ) {
        push @{ $shares{'LISTS'}{'SHARES'} },$share;


        # files
        if ($shares{'SHARES'}{$share}{'TYPE'} eq "SCHOOL"){
            # SCHOOL
            push @{ $shares{'LISTS'}{'SCHOOLS'} },$share;
            # add some stuff
            $shares{'SHARES'}{$share}{'OU_TOP'}=$ref_sophomorix_config->{'SCHOOLS'}{$share}{'OU_TOP'};
            @{ $shares{'SHARES'}{$share}{'FILELIST'} }=@{ $ref_sophomorix_config->{'SCHOOLS'}{$share}{'FILELIST'} };
            foreach my $file ( @{ $shares{'SHARES'}{$share}{'FILELIST'} } ){
                if (-e $file ){
                    $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTS'}="TRUE";
                    $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTSDISPLAY'}="*";
                } else {
                    $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTS'}="FALSE";
                   $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTSDISPLAY'}="-";
                } 
            }
        } elsif ($shares{'SHARES'}{$share}{'TYPE'} eq "OTHER_SHARE"){
            push @{ $shares{'LISTS'}{'OTHER_SHARES'} },$share;
        } elsif ($shares{'SHARES'}{$share}{'TYPE'} eq "GLOBAL"){
            push @{ $shares{'LISTS'}{'GLOBAL'} },$share;
        }


        # TESTS
        # SMB-SHARE
        if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}){
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTS'}="TRUE";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTSDISPLAY'}="OK";
        } else {
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTS'}="FALSE";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTSDISPLAY'}="NONEXISTING";
        }
        # MSDFS entry
        if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs root'}){
            my $msdfs=$ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs root'};
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFS'}=$msdfs;
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFSDISPLAY'}="???";
	} else {
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFSDISPLAY'}="NOT OK";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFS'}="not configured. probably yes";

        }
        # test aquota.user file on share
        &AD_smbclient_testfile($root_dns,$smb_admin_pass,$share,"aquota.user",$ref_sophomorix_config,\%shares);
        # test quota
        if ( $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTS'} eq "TRUE"){
            &AD_smbcquotas_testshare($root_dns,$smb_admin_pass,$share,$ref_sophomorix_config,\%shares);
        } else {
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'}="FALSE";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'}="NO SHARE";
        }
    }
    
    # sort some shares
    @{ $shares{'LISTS'}{'OTHER_SHARES'} } = sort @{ $shares{'LISTS'}{'OTHER_SHARES'} };
    @{ $shares{'LISTS'}{'GLOBAL'} } = sort @{ $shares{'LISTS'}{'GLOBAL'} };
    @{ $shares{'LISTS'}{'SHARES'} } = sort @{ $shares{'LISTS'}{'SHARES'} };
    @{ $shares{'LISTS'}{'SCHOOLS'} } = sort @{ $shares{'LISTS'}{'SCHOOLS'} };

    return \%shares;
}



sub AD_get_printdata {
    my %AD_printdata=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $users = $arg_ref->{users};
    if (not defined $users){$users="FALSE"};

    if ($users eq "TRUE"){
        # sophomorix students,teachers from ldap
        my $filter="(&(objectClass=user)(sophomorixSchoolname=".
           $school.")(|(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'STUDENT'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'TEACHER'}.")))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixAdminClass',
                                 'givenName',
                                 'sn',
                                 'sophomorixFirstnameASCII',
                                 'sophomorixSurnameASCII',
                                 'sophomorixSchoolname',
                                 'sophomorixRole',
                                 'sophomorixCreationDate',
                                 'sophomorixFirstPassword',
                                 'uidNumber',
                                ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix users found for password printout");
        $AD_printdata{'RESULT'}{'user'}{'student'}{'COUNT'}=$max_user;
        my %seen_classes=();
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $line=$entry->get_value('sn').";".
                     $entry->get_value('givenName').";".
                     $entry->get_value('sAMAccountName').";".
                     $entry->get_value('sophomorixFirstPassword').";".
                     $entry->get_value('sophomorixSchoolname').";".
                     $entry->get_value('sophomorixAdminClass').";".
                     $entry->get_value('sophomorixSurnameASCII').";".
                     $entry->get_value('sophomorixFirstnameASCII').";".
                     $entry->get_value('sophomorixRole').";".
                     $entry->get_value('sophomorixCreationDate').";".
                     $entry->get_value('uidNumber').";";
            if (not exists $seen_classes{$entry->get_value('sophomorixAdminClass')}){
                push @{ $AD_printdata{'LIST_BY_sophomorixSchoolname_sophomorixAdminClass'}
		                      {$entry->get_value('sophomorixSchoolname')} },$entry->get_value('sophomorixAdminClass');
                $seen_classes{$entry->get_value('sophomorixAdminClass')}="seen";
		$seen_classes{'ONE'}="seen";
            }
            push @{ $AD_printdata{'LIST_BY_sophomorixAdminClass'}
                                  {$entry->get_value('sophomorixAdminClass')} }, 
                                  $line; 
            push @{ $AD_printdata{'LIST_BY_sophomorixSchoolname'}
                                  {$entry->get_value('sophomorixSchoolname')} }, 
                                  $line; 
            push @{ $AD_printdata{'LIST_BY_sophomorixCreationDate'}{$entry->get_value('sophomorixCreationDate')} }, 
                                  $line;
            # lookup creation
            $AD_printdata{'LOOKUP_BY_sAMAccountName'}{$entry->get_value('sAMAccountName')}=$line;
            $AD_printdata{'LOOKUP_BY_sophomorixAdminClass'}{$entry->get_value('sophomorixAdminClass')}="exists";
        }
    }

    # create list for --back-in-time
    foreach my $date ( keys %{ $AD_printdata{'LIST_BY_sophomorixCreationDate'} } ){
        push @{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} },$date;
    }
    # sort list for --back-in-time (reverse order)
    if ( $#{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} }>0){
        @{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} } = 
            sort{$b cmp $a} @{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} }
    }
    # counter for history
    $AD_printdata{'RESULT'}{'HISTORY'}{'TOTAL'}=$#{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} }+1;
    $AD_printdata{'RESULT'}{'BACK_IN_TIME_MAX'}=$#{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} };
    return(\%AD_printdata);
}



sub AD_class_fetch {
    my ($ldap,$root_dse,$class,$school,$class_type,$ref_sophomorix_config) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. class7a
    my $school_AD="";
    my $class_search="";  # the option i.e. 'class7*'
    if (defined $school){
        $class_search=&AD_get_name_tokened($class,$school,$class_type);
    } else {
        $class_search=&AD_get_name_tokened($class,"---",$class_type);
    }

    my $filter="(& (objectClass=group) "."(cn=".$class_search.") ".
       "(| ".
       "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINCLASS'}.")".
       "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'TEACHERCLASS'}.")".
       "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'EXTRACLASS'}.")".
       " ) )";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                         );
    my $max_class = $mesg->count; 
    for( my $index = 0 ; $index < $max_class ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
        $sam_account=$entry->get_value('sAMAccountName');
	$school_AD = $entry->get_value('sophomorixSchoolname');
    }
    return ($dn,$max_class,$school_AD);
}



sub AD_group_fetch {
    my ($ldap,$root_dse,$group) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. p_abt3
    my $school_AD="";

    my $filter="(&(objectClass=group)(sophomorixType=sophomorix-group)(sAMAccountName=".$group."))";
    print "Filter: $filter\n";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                         );
    my $max_group = $mesg->count; 
    for( my $index = 0 ; $index < $max_group ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
	$school_AD = $entry->get_value('sophomorixSchoolname');
    }
    print "$dn\n";
    return ($dn,$max_group,$school_AD);
}



sub AD_project_fetch {
    my ($ldap,$root_dse,$pro,$school,$info) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. p_abt3
    my $school_AD="";
    my $project="";     # the option i.e. 'p_abt*'
    # projects from ldap
    if (defined $school){
        $project=&AD_get_name_tokened($pro,$school,"project");
    } else {
        $project=&AD_get_name_tokened($pro,"---","project");
    }

    my $filter="(&(objectClass=group)(sophomorixType=project)(cn=".$project."))";
    #print "Filter: $filter\n";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                         );
    my $max_pro = $mesg->count; 
    for( my $index = 0 ; $index < $max_pro ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
        $sam_account=$entry->get_value('sAMAccountName');
	$school_AD = $entry->get_value('sophomorixSchoolname');
    }
    return ($dn,$max_pro,$school_AD);
}



sub AD_dn_fetch_multivalue {
    # get multivalue attribute with dn
    my ($ldap,$root_dse,$dn,$attr_name) = @_;
    my $filter="cn=*";
    my $mesg = $ldap-> search( # perform a search
                       base   => $dn,
                       scope => 'base',
                       filter => $filter,
	               );
    my $entry = $mesg->entry(0);
    my @results = sort $entry->get_value($attr_name);
    return @results;
}



sub AD_group_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $dn = $arg_ref->{dn};
    my $type = $arg_ref->{type};
    my $description = $arg_ref->{description};
    my $quota = $arg_ref->{quota};
    my $mailquota = $arg_ref->{mailquota};
    my $addquota = $arg_ref->{addquota};
    my $addmailquota = $arg_ref->{addmailquota};
    my $mailalias = $arg_ref->{mailalias};
    my $maillist = $arg_ref->{maillist};
    my $status = $arg_ref->{status};
    my $join = $arg_ref->{join};
    my $hide = $arg_ref->{hide};
    my $school = $arg_ref->{school};
    my $maxmembers = $arg_ref->{maxmembers};
    my $members = $arg_ref->{members};
    my $admins = $arg_ref->{admins};
    my $membergroups = $arg_ref->{membergroups};
    my $admingroups = $arg_ref->{admingroups};
    my $creationdate = $arg_ref->{creationdate};
    my $gidnumber = $arg_ref->{gidnumber};
    my $ref_room_ips = $arg_ref->{sophomorixRoomIPs};
    my $ref_room_macs = $arg_ref->{sophomorixRoomMACs};
    my $ref_room_computers = $arg_ref->{sophomorixRoomComputers};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $sync_members=0;
    
    print "\n";
    &Sophomorix::SophomorixBase::print_title("Updating $dn (start)");
    # description   
    if (defined $description){
        print "   * Setting Description to '$description'\n";
        my $mesg = $ldap->modify($dn,replace => {Description => $description}); 
    }

    # quota OR addquota
    my $quota_attr="";
    my $multiquota=""; # containes quota or addquota
    if (defined $quota){
        $quota_attr="sophomorixQuota";
	$multiquota=$quota;
    }
    if (defined $addquota){
        $quota_attr="sophomorixAddQuota";
	$multiquota=$addquota;
    }
    if (defined $quota and defined $addquota){
	print "\nwrong use of function AD_group_update: quota and addquota at the same time\n\n";
        exit;
    }
    
    if (defined $quota or defined $addquota){
        my %quota_new=(); # save old quota and override with new quota
        my @quota_new=(); # option for ldap modify   
        my @sharelist=(); # list of shares, later uniqified and sorted   
        # work on OLD Quota
        my @quota_old = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,$quota_attr);
        foreach my $quota_old (@quota_old){
            my ($share,$value,$comment)=split(/:/,$quota_old);
	    # save old values in quota_new
            $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;
            $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
	    push @sharelist, $share;
        }

        # work on NEW Quota, given by option
	my @schoolquota=split(/,/,$multiquota);
	foreach my $schoolquota (@schoolquota){
	    my ($share,$value,$comment)=split(/:/,$schoolquota);
	    if (not exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}){
                print "\nERROR: SMB-share $share does not exist!\n\n";
		exit;
	    }
            if ($value=~/[^0-9]/ and $value ne "---"){
                print "\nERROR: Quota value $value does not consist ",
                      "of numerals 0-9 or is \"---\"\n\n";
		exit;
	    }
            # overriding quota_new
    	    $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;
            if (not defined $comment){
                $comment="---";
            }
    	    $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
   	    push @sharelist, $share;
	}
        # debug
        #print "OLD: @quota_old\n";
	# print Dumper(%quota_new);
	# print "Sharelist: @sharelist\n";
	
        # prepare ldap modify list
	@sharelist = uniq(@sharelist);
	@sharelist = sort(@sharelist);
	foreach my $share (@sharelist){
            if ($quota_new{'QUOTA'}{$share}{'VALUE'} eq "---" and 
                $share ne $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'} and
                $share ne $school){
                # do nothing
	    } else {
		push @quota_new, $share.":".$quota_new{'QUOTA'}{$share}{'VALUE'}.
                                        ":".$quota_new{'QUOTA'}{$share}{'COMMENT'}.
                                        ":";


	    }
	}
	print "   * Setting $quota_attr to: @quota_new\n";
        my $mesg = $ldap->modify($dn,replace => { $quota_attr => \@quota_new }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    
    # mailquota   
    if (defined $mailquota){
        my ($value,$comment)=split(/:/,$mailquota);
        if (not defined $comment){
            $comment="---";
        }
        my $mailquota_new=$value.":".$comment.":";
        print "   * Setting sophomorixMailquota to $mailquota_new\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMailquota => $mailquota_new}); 
    }
    # addmailquota   
    if (defined $addmailquota){
        my ($value,$comment)=split(/:/,$addmailquota);
        if (not defined $comment){
            $comment="---";
        }
        my $addmailquota_new=$value.":".$comment.":";
        print "   * Setting sophomorixAddmailquota to $addmailquota_new\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixAddmailquota => $addmailquota_new}); 
    }
    # mailalias   
    if (defined $mailalias){
        if($mailalias==0){$mailalias="FALSE"}else{$mailalias="TRUE"};
        print "   * Setting sophomorixMailalias to $mailalias\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMailalias => $mailalias}); 
    }
    # maillist   
    if (defined $maillist){
        if($maillist==0){$maillist="FALSE"}else{$maillist="TRUE"};
        print "   * Setting sophomorixMaillist to $maillist\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMaillist => $maillist}); 
    }
    # status   
    if (defined $status){
        print "   * Setting sophomorixStatus to $status\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixStatus => $status}); 
    }
    # joinable
    if (defined $join){
        if($join==0){$join="FALSE"}else{$join="TRUE"};
        print "   * Setting sophomorixJoinable to $join\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixJoinable => $join}); 
    }
    # hide
    if (defined $hide){
        if($hide==0){$hide="FALSE"}else{$hide="TRUE"};
        print "   * Setting sophomorixHidden to $hide\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixHidden => $hide}); 
    }
    # maxmembers   
    if (defined $maxmembers){
        print "   * Setting sophomorixMaxMembers to $maxmembers\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMaxMembers => $maxmembers}); 
    }
    # creationdate   
    if (defined $creationdate){
        print "   * Setting sophomorixCreationDate to $creationdate\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixCreationDate => $creationdate}); 
    }
    # gidnumber   
    if (defined $gidnumber){
        print "   * Setting gidNumber to $gidnumber\n";
        my $mesg = $ldap->modify($dn,replace => {gidNumber => $gidnumber}); 
    }
    # members   
    if (defined $members){
        my @members=split(/,/,$members);
        @members = reverse @members;
        @members = &_keep_object_class_only($ldap,$root_dse,"user",@members);
        print "   * Setting sophomorixMembers to: @members\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixMembers' => \@members }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # admins
    if (defined $admins){
        my @admins=split(/,/,$admins);
        @admins = reverse @admins;
        @admins = &_keep_object_class_only($ldap,$root_dse,"user",@admins);
        print "   * Setting sophomorixAdmins to: @admins\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixAdmins' => \@admins }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # membergroups   
    if (defined $membergroups){
        my @membergroups=split(/,/,$membergroups);
        @membergroups = reverse @membergroups;
        @membergroups = &_keep_object_class_only($ldap,$root_dse,"group",@membergroups);
        print "   * Setting sophomorixMemberGroups to: @membergroups\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixMemberGroups' => \@membergroups }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # admingroups
    if (defined $admingroups){
        my @admingroups=split(/,/,$admingroups);
        @admingroups = reverse @admingroups;
        @admingroups = &_keep_object_class_only($ldap,$root_dse,"group",@admingroups);
        print "   * Setting sophomorixAdmingroups to: @admingroups\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixAdmingroups' => \@admingroups }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }

    # room stuff
    if (defined $ref_room_ips){
        print "   * Setting sophomorixRoomIPs to: @{ $ref_room_ips }\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixRoomIPs' => $ref_room_ips }); 
    }

    if (defined $ref_room_macs){
        print "   * Setting sophomorixRoomMACs to: @{ $ref_room_macs }\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixRoomMACs' => $ref_room_macs }); 
    }

    if (defined $ref_room_computers){
        print "   * Setting sophomorixRoomComputers to: @{ $ref_room_computers }\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixRoomComputers' => $ref_room_computers }); 
    }

    # sync memberships if necessary
    if ($sync_members>0){
        &AD_project_sync_members($ldap,$root_dse,$dn,$ref_sophomorix_config);
    }
    &Sophomorix::SophomorixBase::print_title("Updating $dn (end)");
    print "\n";
 }



sub AD_project_sync_members {
    my ($ldap,$root_dse,$dn,$ref_sophomorix_config) = @_;
    print "\n";
    &Sophomorix::SophomorixBase::print_title("Sync member: $dn (start)");
    my $filter="cn=*";
    my $mesg = $ldap-> search( # perform a search
                       base   => $dn,
                       scope => 'base',
                       filter => $filter,
                             );
    my $max_pro = $mesg->count;
    if ($max_pro==1){
        my $entry = $mesg->entry(0);
        my $cn = $entry->get_value('cn');
        print "     * $max_pro single project found: $cn\n";

        ##################################################
        # fetch target memberships
        my %target=();
        my @admins = sort $entry->get_value('sophomorixAdmins');
        foreach my $admin (@admins){
            $target{$admin}="admin";
        }
        my @members = sort $entry->get_value('sophomorixMembers');
        foreach my $member (@members){
            $target{$member}="member";
        }
        my @admingroups = sort $entry->get_value('sophomorixAdminGroups');
        foreach my $admingroup (@admingroups){
            $target{$admingroup}="admingroup";
        }
        my @membergroups = sort $entry->get_value('sophomorixMemberGroups');
        foreach my $membergroup (@membergroups){
            $target{$membergroup}="membergroup";
        }
        # print target memberships
        if($Conf::log_level>=3){
            print "   * Target memberships:\n";
            foreach my $key (keys %target) {
                my $value = $target{$key};
                printf "      %-15s -> %-20s\n",$key,$value;
            }
        }

        ##################################################
        # fetch actual memberships
        my %actual=();
        my @ac_members = sort $entry->get_value('member');
        foreach my $member (@ac_members){
            # retrieving object class
            my $filter="cn=*";
            my $mesg2 = $ldap-> search( # perform a search
                                base   => $member,
                                scope => 'base',
                                filter => $filter,
                                      );
            my $max_pro = $mesg2->count;
            my $entry = $mesg2->entry(0);
            my $cn = $entry->get_value('cn');
            my @object_classes = $entry->get_value('objectClass');
            foreach my $object_class (@object_classes){
                if ($object_class eq "group"){
                    $actual{$cn}="group";
                    last;
                } elsif ($object_class eq "user"){
                    $actual{$cn}="user";
                    last;
                }
            }
        }
        # print actual memberships
        if($Conf::log_level>=3){
            print "   * Actual memberships:\n";
            foreach my $key (keys %actual) {
                my $value = $actual{$key};
                printf "      %-15s -> %-20s\n",$key,$value;
            }
        }

        ##################################################
        # sync memberships
        # Deleting
        foreach my $key (keys %actual) {
            my $value = $actual{$key};
            if (exists $target{$key}){
                # OK
            } else {
                #print "Deleting $actual{$key} $key as member from $cn\n";
                if ($actual{$key} eq "user"){
                    &AD_group_removemember({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $cn,
                                            removemember => $key,
                                            sophomorix_config=>$ref_sophomorix_config,
                                          });   
                } elsif ($actual{$key} eq "group"){
                    &AD_group_removemember({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $cn,
                                            removegroup => $key,
                                            sophomorix_config=>$ref_sophomorix_config,
                                          });   
                }
            }
        }

        # Adding
        foreach my $key (keys %target) {
            my $value = $target{$key};
            if (exists $actual{$key}){
                # OK
            } else {
                my $type="";
                if ($target{$key} eq "admin" or $target{$key} eq "member"){
                    #print "Adding user $key as member to $cn\n";
                    &AD_group_addmember({ldap => $ldap,
                                         root_dse => $root_dse, 
                                         group => $cn,
                                         addmember => $key,
                                        }); 
                } elsif ($target{$key} eq "admingroup" or $target{$key} eq "membergroup"){
                    #print "Adding group $key as member to $cn\n";
                    &AD_group_addmember({ldap => $ldap,
                                         root_dse => $root_dse, 
                                         group => $cn,
                                         addgroup => $key,
                                        }); 
                }
            }
        }
    } else {
        print "ERROR: Sync failed: $max_pro projects found\n";
    }
    &Sophomorix::SophomorixBase::print_title("Sync member: $dn (end)");
    print "\n";
}



sub AD_group_list {
    # show==0 return list of project dn's
    my ($ldap,$root_dse,$type,$show) = @_;
    my $filter;
    if ($type eq "project"){
        $filter="(&(objectClass=group)(sophomorixType=project))";
    } elsif ($type eq "sophomorix-group"){
        $filter="(&(objectClass=group)(sophomorixType=sophomorix-group))";
    } elsif ($type eq "adminclass"){
        $filter="(&(objectClass=group)(sophomorixType=adminclass))";
    }
    my $sort = Net::LDAP::Control::Sort->new(order => "sAMAccountName");
    if($Conf::log_level>=2){
        print "Filter: $filter\n";
    }
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   control => [ $sort ]
                         );
    my $max_pro = $mesg->count;
    my @projects_dn=();
    for( my $index = 0 ; $index < $max_pro ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
        push @projects_dn,$dn;   
    }
    @projects_dn = sort @projects_dn;
    return @projects_dn;
}



sub AD_object_move {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $dn = $arg_ref->{dn};
    my $target_branch = $arg_ref->{target_branch};
    my $rdn = $arg_ref->{rdn};

    &Sophomorix::SophomorixBase::print_title("Move object in tree:");
    print "   * DN:     $dn\n";
    print "   * Target: $target_branch\n";

    # create target branch
    my $result = $ldap->add($target_branch,attr => ['objectClass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result,2,(caller(0))[3]);
    # move object
    $result = $ldap->moddn ( $dn,
                        newrdn => $rdn,
                        deleteoldrdn => '1',
                        newsuperior => $target_branch
                               );
    &AD_debug_logdump($result,2,(caller(0))[3]);
}



sub AD_group_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $group = $arg_ref->{group};
    my $group_basename = $arg_ref->{group_basename};
    my $description = $arg_ref->{description};
    my $school = $arg_ref->{school};
    my $type = $arg_ref->{type};
    my $status = $arg_ref->{status};
    my $joinable = $arg_ref->{joinable};
    my $gidnumber_wish = $arg_ref->{gidnumber_wish};
    my $dn_wish = $arg_ref->{dn_wish};
    my $cn = $arg_ref->{cn};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $file = $arg_ref->{file};
    my $sub_ou = $arg_ref->{sub_ou};
    my $ref_room_ips = $arg_ref->{sophomorixRoomIPs};
    my $ref_room_macs = $arg_ref->{sophomorixRoomMACs};
    my $ref_room_computers = $arg_ref->{sophomorixRoomComputers};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if (not defined $joinable){
        $joinable="FALSE";    
    }
    if (not defined $cn){
        $cn=$group;    
    }
    if (not defined $file){
        $file="none";    
    }

    print "\n";
    &Sophomorix::SophomorixBase::print_title("Creating group $group of type $type (begin):");

    $school=&AD_get_schoolname($school);

    my $group_ou;
    if (defined $sub_ou){
        $group_ou=$sub_ou;
    } elsif ($file eq "none"){
        $group_ou=$ref_sophomorix_config->{'INI'}{'OU'}{'AD_management_ou'};
    } else {
        if (exists $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'GROUP_OU'}){
            $group_ou=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'GROUP_OU'};
        } elsif (exists $ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$file}{'GROUP_OU'}){
            $group_ou=$ref_sophomorix_config->{'FILES'}{'CLASS_FILE'}{$file}{'GROUP_OU'};
        }
    }
    $group_ou=~s/\@\@FIELD_1\@\@/$group_basename/g; 
    my $target_branch = $group_ou.",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    my $dn="CN=".$group.",".$target_branch;
    my $mail = $group."\@".$root_dns;

    if (defined $dn_wish){
        # override DN
        $dn=$dn_wish;
        # override target so it fits to dn
        my ($unused,@used)=split(/,/,$dn);
        $target_branch=join(",",@used);
    }

    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count==0){
        # adding the group
        if (not defined $gidnumber_wish or $gidnumber_wish eq "---"){
            $gidnumber_wish=&next_free_gidnumber_get($ldap,$root_dse);
        }
        print "   DN:              $dn\n";
        print "   Target:          $target_branch\n";
        print "   Group:           $group\n";
        print "   Unix-gidNumber:  $gidnumber_wish\n";
        print "   Type:            $type\n";
        print "   Joinable:        $joinable\n";
        print "   Creationdate:    $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}\n";
        print "   Description:     $description\n";
        print "   File:            $file\n";
        print "   School:          $school\n";

        # make sure target ou exists
        my $target = $ldap->add($target_branch,attr => ['objectClass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($target,2,(caller(0))[3]);
        # Create object
	if ($type eq "project"){
            my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $cn,
                                    description => $description,
                                    sAMAccountName => $group,
                                    mail => $mail,
                                    sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                                    sophomorixType => $type, 
                                    sophomorixSchoolname => $school, 
                                    sophomorixStatus => $status,
                                    sophomorixAddQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                                        "$school:---:---:"],
                                    sophomorixAddMailQuota => ["---:---:"],
                                    sophomorixQuota => "---",
                                    sophomorixMailQuota => "---",
                                    sophomorixMaxMembers => "0",
                                    sophomorixMailAlias => "FALSE",
                                    sophomorixMailList => "FALSE",
                                    sophomorixJoinable => $joinable,
                                    sophomorixHidden => "FALSE",
                                    gidNumber => $gidnumber_wish,
                                    objectclass => ['top',
                                                      'group' ],
                                ]
                            );
            &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq "adminclass" or $type eq "teacherclass" or $type eq "extraclass"){
            my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $cn,
                                    description => $description,
                                    sAMAccountName => $group,
                                    mail => $mail,
                                    sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                                    sophomorixType => $type, 
                                    sophomorixSchoolname => $school, 
                                    sophomorixStatus => $status,
                                    sophomorixAddQuota => ["---"],
                                    sophomorixAddMailQuota => "---",
                                    sophomorixQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                                        "$school:---:---:"],
                                    sophomorixMailQuota => "---:---:",
                                    sophomorixMaxMembers => "0",
                                    sophomorixMailAlias => "FALSE",
                                    sophomorixMailList => "FALSE",
                                    sophomorixJoinable => $joinable,
                                    sophomorixHidden => "FALSE",
                                    gidNumber => $gidnumber_wish,
                                    objectclass => ['top',
                                                      'group' ],
                                ]
                            );
           &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq "sophomorix-group"){
            my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $cn,
                                    description => $description,
                                    sAMAccountName => $group,
                                    mail => $mail,
                                    sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                                    sophomorixType => $type, 
                                    sophomorixSchoolname => $school, 
                                    sophomorixStatus => $status,
                                    sophomorixAddQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                                        "$school:---:---:"],
                                    sophomorixAddMailQuota => ["---:---:"],
                                    sophomorixQuota => "---",
                                    sophomorixMailQuota => "---",
                                    sophomorixMaxMembers => "0",
                                    sophomorixMailAlias => "FALSE",
                                    sophomorixMailList => "FALSE",
                                    sophomorixJoinable => $joinable,
                                    sophomorixHidden => "FALSE",
                                    gidNumber => $gidnumber_wish,
                                    objectclass => ['top',
                                                      'group' ],
                                ]
                            );
            &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq "hardwareclass"){
            my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $cn,
                                    description => $description,
                                    sAMAccountName => $group,
                                    mail => $mail,
                                    sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                                    sophomorixType => $type, 
                                    sophomorixSchoolname => $school, 
                                    sophomorixStatus => $status,
                                    sophomorixAddQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                                        "$school:---:---:"],
                                    sophomorixAddMailQuota => ["---:---:"],
                                    sophomorixQuota => "---",
                                    sophomorixMailQuota => "---",
                                    sophomorixMaxMembers => "0",
                                    sophomorixMailAlias => "FALSE",
                                    sophomorixMailList => "FALSE",
                                    sophomorixJoinable => $joinable,
                                    sophomorixHidden => "FALSE",
                                    gidNumber => $gidnumber_wish,
                                    objectclass => ['top',
                                                      'group' ],
                                ]
                            );
            &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq "room"){
            my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $cn,
                                    description => $description,
                                    sAMAccountName => $group,
                                    mail => $mail,
                                    sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                                    sophomorixType => $type, 
                                    sophomorixSchoolname => $school, 
                                    sophomorixStatus => $status,
                                    sophomorixAddQuota => ["---"],
                                    sophomorixAddMailQuota => "---",
                                    sophomorixQuota => ["---"],
                                    sophomorixMailQuota => "---",
                                    sophomorixMaxMembers => "0",
                                    sophomorixMailAlias => "FALSE",
                                    sophomorixMailList => "FALSE",
                                    sophomorixJoinable => $joinable,
                                    sophomorixHidden => "FALSE",
                                    gidNumber => $gidnumber_wish,
                                    sophomorixRoomIPs => $ref_room_ips,
                                    sophomorixRoomMACs => $ref_room_macs,
                                    sophomorixRoomComputers => $ref_room_computers,
                                    objectclass => ['top',
                                                      'group' ],
                                ]
                            );
           &AD_debug_logdump($result,2,(caller(0))[3]);
        } else {
            my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $cn,
                                    description => $description,
                                    sAMAccountName => $group,
                                    mail => $mail,
                                    sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                                    sophomorixType => $type, 
                                    sophomorixSchoolname => $school, 
                                    sophomorixStatus => $status,
                                    sophomorixAddQuota => ["---"],
                                    sophomorixAddMailQuota => "---",
                                    sophomorixQuota => ["---"],
                                    sophomorixMailQuota => "---",
                                    sophomorixMaxMembers => "0",
                                    sophomorixMailAlias => "FALSE",
                                    sophomorixMailList => "FALSE",
                                    sophomorixJoinable => $joinable,
                                    sophomorixHidden => "FALSE",
                                    gidNumber => $gidnumber_wish,
                                    objectclass => ['top',
                                                      'group' ],
                                ]
                            );
           &AD_debug_logdump($result,2,(caller(0))[3]);
	}
    } else {
        print "   * Group $group exists already ($count results)\n";
    }

    if ($type eq "adminclass" or $type eq "extraclass"){
        # a group like 7a, 7b
        #print "Student class of the school: $group\n";
        my $token_students=&AD_get_name_tokened($DevelConf::student,$school,"adminclass");
  
        if ($token_students ne $group){ # do not add group to itself
            # add the group to <token>-students
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $token_students,
                                 addgroup => $group,
                               });
        }
        # add group <token>-students to all-students
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'INI'}{'VARS'}{'HIERARCHY_PREFIX'}."-".$DevelConf::student,
                             addgroup => $token_students,
                           });
        if ($type eq "adminclass"){
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.adminclass",
                                   school=>$school,
                                   adminclass=>$group,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        } elsif ($type eq "extraclass") {
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.extraclass",
                                   school=>$school,
                                   adminclass=>$group,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        }
    } elsif ($type eq "teacherclass"){
        # add <token>-teachers to all-teachers
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'INI'}{'VARS'}{'HIERARCHY_PREFIX'}."-".$DevelConf::teacher,
                             addgroup => $group,
                           });
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.teacherclass",
                               school=>$school,
                               teacherclass=>$group,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($type eq "room"){
        #my $token_examaccounts=&AD_get_name_tokened($DevelConf::examaccount,$school,"examaccount");
        ## add the room to <token>-examaccounts
        #&AD_group_addmember({ldap => $ldap,
        #                     root_dse => $root_dse, 
        #                     group => $token_examaccounts,
        #                     addgroup => $group,
        #                   });
        ## add group <token>-examaccounts to all-examaccounts
        #&AD_group_addmember({ldap => $ldap,
        #                     root_dse => $root_dse, 
        #                     group => $ref_sophomorix_config->{'INI'}{'VARS'}{'HIERARCHY_PREFIX'}."-".$DevelConf::examaccount,
        #                     addgroup => $token_examaccounts,
        #                   });
    } elsif ($type eq "project"){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.project",
                               school=>$school,
                               project=>$group,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($type eq "hardwareclass"){
        # nothing to do so far
    }
    &Sophomorix::SophomorixBase::print_title("Creating group $group of type $type (end)");
    print "\n";
    return;
}



sub AD_group_addmember {
    # requires token-group as groupname
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $group = $arg_ref->{group};
    my $adduser = $arg_ref->{addmember};
    my $addgroup = $arg_ref->{addgroup};
    my ($count_group,$dn_exist_group,$cn_exist_group,$type)=&AD_object_search($ldap,$root_dse,"group",$group);

    &Sophomorix::SophomorixBase::print_title("Adding member to $group:");
    if ($count_group==0){
        # group does not exist -> exit with warning
        print "   * WARNING: Group $group nonexisting ($count_group results)\n";
        return;
    } elsif ($count_group==1){
        print "   * Group $group exists ($count_group results)\n";

    }

    if (defined $adduser){
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$adduser);
        if ($count > 0){
            print "   * User $adduser exists ($count results)\n";
            print "   * Adding user $adduser to group $group\n";
            my $mesg = $ldap->modify( $dn_exist_group,
     	         	      add => {
                                  member => $dn_exist,
                                     }
                                    );
            &AD_debug_logdump($mesg,2,(caller(0))[3]);
            #my $command="samba-tool group addmembers ". $group." ".$adduser;
            #print "   # $command\n";
            #system($command);
            return;
	} else {
            # user does not exist -> exit with warning
            print "   * WARNING: User $adduser nonexisting ($count results)\n";
            return;
        }
    } elsif (defined $addgroup){
        print "   * Adding group $addgroup to $group\n";
        my ($count_group,$dn_exist_addgroup,$cn_exist_addgroup)=&AD_object_search($ldap,$root_dse,"group",$addgroup);
        if ($count_group > 0){
            print "   * Group $addgroup exists ($count_group results)\n";
            my $mesg = $ldap->modify( $dn_exist_group,
     	  	                  add => {
                                  member => $dn_exist_addgroup,
                                  }
                              );
            &AD_debug_logdump($mesg,2,(caller(0))[3]);
            return;
        }
    } else {
        return;
    }
}



sub AD_group_addmember_management {
    # requires token-group as groupname
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $group = $arg_ref->{group};
    my $addmember = $arg_ref->{addmember};

    # testing if user can be added
    # ?????? missing

    &AD_group_addmember({ldap => $ldap,
                         root_dse => $root_dse, 
                         group => $group,
                         addmember => $addmember,
                            }); 
}



sub AD_group_removemember {
    # requires token-group as groupname
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $group = $arg_ref->{group};
    my $removeuser = $arg_ref->{removemember};
    my $removegroup = $arg_ref->{removegroup};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    &Sophomorix::SophomorixBase::print_title("Removing member from $group:");

    my ($count_group,$dn_exist_group,$cn_exist_group)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count_group==0){
        # group does not exist -> create group
        print "   * WARNING: Group $group nonexisting ($count_group results)\n";
        return;
    }

    if (defined $removeuser){
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$removeuser);
        if ($count > 0){
            print "   * User $removeuser exists ($count results)\n";
            print "   * Removing user $removeuser from group $group\n";
            my $mesg = $ldap->modify( $dn_exist_group,
	  	                  delete => {
                                  member => $dn_exist,
                                  }
                              );
            #my $command="samba-tool group removemembers ". $group." ".$removeuser;
            #print "   # $command\n";
            #system($command);
            return;
        } else {
            # user does not exist -> exit with warning
            print "   * WARNING: User $removeuser nonexisting ($count results)\n";
            return;
        }
    } elsif (defined $removegroup){
        if (not exists $ref_sophomorix_config->{'INI'}{'SYNC_MEMBER'}{'KEEPGROUP_LOOKUP'}{$removegroup}){
            print "   * Removing group $removegroup from $group\n";
            my ($count_group,$dn_exist_removegroup,$cn_exist_removegroup)=&AD_object_search($ldap,$root_dse,"group",$removegroup);
            if ($count_group > 0){
                print "   * Group $removegroup exists ($count_group results)\n";
                my $mesg = $ldap->modify( $dn_exist_group,
     	                          delete => {
                                  member => $dn_exist_removegroup,
                                });
                &AD_debug_logdump($mesg,2,(caller(0))[3]);
                return;
            }
	} else {
            print "   * NOT Removing group $removegroup from $group (sophomorix.ini: SYNC_MEMBER -> KEEPGROUP)\n";
        }
    } else {
        return;
    }
}





sub AD_debug_logdump {
    # dumping ldap message object in loglevels
    my ($message,$level,$text) = @_;
    my $return=-1;
    my $string=$message->error;
    if ($string=~/.*: Success/ or $string eq "Success"){
        # ok
        $return=1;
    } elsif ($string=~/Entry .* already exists/){
        $return=2;
        # not so bad, just display it
        #print "         * OK: $string\n";
    } elsif ($string=~/Attribute member already exists for target/){
        # not so bad, just display it
        #print "         * OK: $string\n";
        $return=3;
    } else {
        # bad error
        $return=0;
        print "\nERROR in $text:\n";
        print "   $string\n\n";
        if($Conf::log_level>=$level){
            if ( $message->code) { # 0: no error
                print "   Debug info from server($text):\n";
                print Dumper(\$message);
            }
        }
    }
    return $return;
}



sub AD_login_test {
    # return 0: success
    # return -1: nor firstpassword found
    # return >0: Error code of smbclient command
    my ($ldap,$root_dse,$dn)=@_;
    my $filter="(cn=*)";
    my $mesg = $ldap->search(
                      base   => $dn,
                      scope => 'base',
                      filter => $filter,
                      attr => ['sophomorixFirstPassword',
                               'sophomorixExamMode',
                               'sophomorixStatus',
                               'userAccountControl']
                            );
    my $entry = $mesg->entry(0);
    my $firstpassword = $entry->get_value('sophomorixFirstPassword');
    my $exammode = $entry->get_value('sophomorixExamMode');
    my $status = $entry->get_value('sophomorixStatus');
    my $user_account_control = $entry->get_value('userAccountControl');
    my $sam_account = $entry->get_value('sAMAccountName');

    if ($firstpassword eq "---" and -e "/etc/linuxmuster/.secret/$sam_account"){
        print "   * Trying to fetch password from .secret/$sam_account\n";
        $firstpassword = `cat /etc/linuxmuster/.secret/$sam_account`;
    }
    if (not defined $firstpassword){
        return -1;
    }

    # smbclient test
    #my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
    #            " -L localhost --user=$sam_account%'$firstpassword' > /dev/null 2>&1 ";
    #print "   # $command\n";
    #my $result=system($command);


    if ($firstpassword eq "---"){
        print "   * $sam_account($status,$user_account_control,$exammode):".
              " No password test possible (sophomorixFirstpassword: $firstpassword)\n";
        return 2;
    } elsif ( $exammode ne "---"){
        print "   * $sam_account($status,$user_account_control,$exammode):".
              " No password test possible (user should be in ExamMode/disabled)\n";
        return 2;
    } else {
        # pam login
        my $command="wbinfo --pam-logon=$sam_account%'$firstpassword' > /dev/null 2>&1 ";
        print "   # $sam_account: $command\n";
        my $result=system($command);
        return $result;

        # kerberos login
        # my $command="wbinfo --krb5auth=$sam_account%'$firstpassword'' > /dev/null 2>&1 ";
        # print "   # $command\n";
        # my $result=system($command);
    }
}



sub AD_examuser_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $subdir = $arg_ref->{subdir};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    &Sophomorix::SophomorixBase::print_title("Creating examuser for user: $participant (start)");
    # get data from (non-exam-)user
    my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,$deactivation_date_AD,
        $school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
        &AD_get_user({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      user=>$participant,
                    });
    my $display_name = $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_DISPLAYNAME_PREFIX'}." ".
                       $firstname_utf8_AD." ".$lastname_utf8_AD;
    my $examuser=$participant.$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'};
 
    my $uni_password;
    if ($ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'FIRSTPASSWORD_COPY'} eq "TRUE"){
        $uni_password=&_unipwd_from_plainpwd($firstpassword_AD);
    } else {
        $uni_password=&_unipwd_from_plainpwd($DevelConf::student_password_default);
    }

    my $prefix=$school_AD;
    if ($school_AD eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }
    if (not defined $uidnumber_wish or $uidnumber_wish eq "---"){
        $uidnumber_wish=&next_free_uidnumber_get($ldap,$root_dse);
    }
    my $user_principal_name = $examuser."\@".$root_dns;
    my $mail = $examuser."\@".$root_dns;

    # create OU for session
    my $dn_session;
    if ($subdir eq ""){
        # no sub_ou
        $dn_session=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_OU'}.
                    ",OU=".$school_AD.",OU=SCHOOLS,".$root_dse;
    } else {
        # use subdir as sub_ou 
        $dn_session="OU=".$subdir.",".$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_OU'}.
                    ",OU=".$school_AD.",OU=SCHOOLS,".$root_dse;
    }

    $ldap->add($dn_session,attr => ['objectClass' => ['top', 'organizationalUnit']]);
    my $dn="CN=".$examuser.",".$dn_session;

    my $file="---";
    my $unid="---";
    my $status=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_STATUS'};
    my $tolerationdate=$DevelConf::default_date;
    my $deactivationdate=$DevelConf::default_date;
    my ($homedirectory,$unix_home,$unc,$smb_rel_path)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school_AD,
                                                       $subdir, # groupname is the subdir
                                                       $examuser,
                                                       $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_ROLE'},
                                                       $ref_sophomorix_config);


        print "   DN:                 $dn\n";
        print "   DN(Parent):         $dn_session\n";
        print "   Surname(UTF8):      $lastname_utf8_AD\n";
        print "   Firstname(UTF8):    $firstname_utf8_AD\n";
        print "   School:             $school_AD\n"; # Organisatinal Unit
        print "   Role(User):         $role_AD\n";
        print "   Status:             $status\n";
        print "   Login (check OK):   $examuser\n";
        # sophomorix stuff
        print "   Creationdate:       $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}\n";
        print "   Tolerationdate:     $tolerationdate\n";
        print "   Deactivationdate:   $deactivationdate\n";
        print "   Unid:               $unid\n";
        print "   File:               $file\n";
        print "   Firstpassword:      $firstpassword_AD\n";
        print "   Examuser:           $exammode_AD\n";
        print "   homeDirectory:      $homedirectory\n";
        print "   unixHomeDirectory:  $unix_home\n";

        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_PREFIX_EN'}.
                                         " $examuser ($firstname_utf8_AD $lastname_utf8_AD)".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_PREFIX_DE'}.
                                         " $examuser ($firstname_utf8_AD $lastname_utf8_AD) ".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_POSTFIX_DE'};
            $json_progress{'STEP'}=$user_count;
            $json_progress{'FINAL_STEP'}=$max_user_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }

    my $result = $ldap->add( $dn,
                   attr => [
                   sAMAccountName => $examuser,
                   givenName => $firstname_utf8_AD,
                   sn => $lastname_utf8_AD,
                   displayName => [$display_name],
                   userPrincipalName => $user_principal_name,
                   mail => $mail,
                   unicodePwd => $uni_password,
                   homeDrive => "H:",
                   homeDirectory => $homedirectory,
                   unixHomeDirectory => $unix_home,
                   sophomorixExitAdminClass => "unknown", 
                   sophomorixUnid => $unid,
                   sophomorixStatus => $status,
                   sophomorixAdminClass => "---",    
                   sophomorixAdminFile => $file,    
                   sophomorixFirstPassword => $firstpassword_AD, 
                   sophomorixFirstnameASCII => "---",
                   sophomorixSurnameASCII  => "---",
                   sophomorixBirthdate  => "01.01.1970",
                   sophomorixRole => "examuser",
                   sophomorixSchoolPrefix => $prefix,
                   sophomorixSchoolname => $school_AD,
                   sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                   sophomorixTolerationDate => $tolerationdate, 
                   sophomorixDeactivationDate => $deactivationdate, 
                   sophomorixComment => "created by sophomorix", 
                   sophomorixExamMode => $exammode_AD, 
                   userAccountControl => $DevelConf::default_user_account_control,
                   uidNumber => $uidnumber_wish,

                   objectclass => ['top', 'person',
                                     'organizationalPerson',
                                     'user' ],
                           ]
                           );
    &AD_debug_logdump($result,2,(caller(0))[3]);
    &AD_repdir_using_file({root_dns=>$root_dns,
                           repdir_file=>"repdir.examuser_home",
                           school=>$school_AD,
                           subdir=>$subdir,
                           student_home=>$examuser,
                           smb_admin_pass=>$smb_admin_pass,
                           sophomorix_config=>$ref_sophomorix_config,
                           sophomorix_result=>$ref_sophomorix_result,
                         });
    &Sophomorix::SophomorixBase::print_title("Creating examuser for user: $participant (end)");
}



sub AD_examuser_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    &Sophomorix::SophomorixBase::print_title("Killing examuser of user: $participant");
    my $examuser=$participant.$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'};
    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$examuser);

    if ($participant=~/$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'}$/){
        print "WARNING: you must use the account name for --participant",
              " (without $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'})\n";
        return;
    } elsif ($count==0){
        print "ERROR: Cannot kill nonexisting examuser $examuser\n";
        return;
    } elsif ($count > 0){
        my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
            $home_directory_AD,$user_account_control_AD,$toleration_date_AD,$deactivation_date_AD,
            $school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
            &AD_get_user({ldap=>$ldap,
                          root_dse=>$root_dse,
                          root_dns=>$root_dns,
                          user=>$examuser,
                        });
        $home_directory_AD=~s/\\/\//g;
        my $smb_home="smb:".$home_directory_AD;

        if ($role_AD ne "examuser"){
            print "Not deleting $examuser beause its role is not examuser";
            return;
	}
        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_PREFIX_EN'}.
                                         " $participant".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_PREFIX_DE'}.
                                         " $participant".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_POSTFIX_DE'};
            $json_progress{'STEP'}=$user_count;
            $json_progress{'FINAL_STEP'}=$max_user_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }

        # deleting user
        my $command="samba-tool user delete ". $examuser;
        print "   # $command\n";
        system($command);

        # deleting home
        my $smb = new Filesys::SmbClient(username  => $DevelConf::sophomorix_file_admin,
                                         password  => $smb_admin_pass,
                                         debug     => 0);
        #print "Deleting: $smb_home\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
        my $return=$smb->rmdir_recurse($smb_home);
        if($return==1){
            print "OK: Deleted with succes $smb_home\n";
        } else {
            print "ERROR: rmdir_recurse $smb_home $!\n";
        }

        # deleting subdir if empty and not examusers
        my $subdir=$smb_home;
        $subdir=~s/\/$//; # make sure trailing / are gone 
        $subdir=~s/\/$examuser$//; # remove <user>-exam
        if ($subdir=~m/$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{USER_SUB_DIR}$/){
            # examusers still needed
            print "Not deleting $subdir (still needed)\n";
        } else {
            # deleting subdir
            my $return=$smb->rmdir($subdir);
            if($return==1){
                print "OK: Deleted empty dir: $subdir\n";
            } else {
                print "Not deleted: $subdir ($!)\n";
            }
        }

        return;
    } else {
        print "   * User $examuser nonexisting ($count results)\n";
        return;
    }
}



sub AD_smbclient_testfile {
    # tests if a file exists on a share
    my ($root_dns,$smb_admin_pass,$share,$testfile,$ref_sophomorix_config,$ref_schools)=@_;
    my $file_exists=0;
    my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
        " -U ".$DevelConf::sophomorix_file_admin."%'".$smb_admin_pass."'".
        " //$root_dns/$share -c 'ls'";
    my $stdout=`$smbclient_command 2> /dev/null`;
    my $return=${^CHILD_ERROR_NATIVE}; # return of value of last command
    my @lines=split(/\n/,$stdout);
    foreach my $line (@lines){
        my ($unused,$file,@unused)=split(/\s+/,$line);
	if (defined $file){
	    if ($file eq $testfile){
		$file_exists=1;
		last;
	    }
	}
    }
    
    if ($file_exists==1){
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSER'}="TRUE";
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSERDISPLAY'}="OK";
    }  else {
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSER'}="FALSE";
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSERDISPLAY'}="NONEXISTING";
    }
}



sub AD_smbcquotas_queryuser {
    my ($root_dns,$smb_admin_pass,$user,$share,$ref_sophomorix_config)=@_;
    print "Querying smbcquotas of user $user on share $share\n";
    my $smbcquotas_command=
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
        " ".$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS_PROTOCOL_OPT'}.
        " -U ".$DevelConf::sophomorix_file_admin."%'".
        $smb_admin_pass."'".
        " -u $user //$root_dns/$share";
    my $string=`$smbcquotas_command`;
    chomp($string);
    $string=~s/ //g; # remove whitespace
    my ($userstring,$quota)=split(/:/,$string);
    my ($used,$soft,$hard)=split(/\//,$quota);

    # used
    my $used_kib;
    $used_kib=$used/1024;
    $used_mib=round(10*$used_kib/1024)/10; # MiB rounded to one decimal

    # soft
    my $soft_kib;
    my $soft_mib;
    if ($soft eq "NOLIMIT"){
        $soft="-1"; 
        $soft_kib="-1"; 
        $soft_mib="-1"; 
    } else {
        $soft_kib=$soft/1024;
        $soft_mib=round(10*$soft_kib/1024)/10; # MiB rounded to one decimal
    }

    # hard
    my $hard_kib;
    my $hard_mib;
    if ($hard eq "NOLIMIT"){
        $hard="-1"; 
        $hard_kib="-1"; 
        $hard_mib="-1"; 
    } else {
        $hard_kib=$hard/1024;
        $hard_mib=round(10*$hard_kib/1024)/10; # MiB rounded to one decimal
    }

    if($Conf::log_level>=3){
        print "$smbcquotas_command\n";
        print "   USER: <$userstring>\n";
        print "   USED: <$used> <$used_kib>KiB\n";
        print "   SOFT: <$soft> <$soft_kib>KiB\n";
        print "   HARD: <$hard> <$hard_kib>KiB\n";
    }
    return($used,$soft,$hard,$used_kib,$soft_kib,$hard_kib,$used_mib,$soft_mib,$hard_mib);
}



sub AD_smbcquotas_testshare {
    my ($root_dns,$smb_admin_pass,$share,$ref_sophomorix_config,$ref_schools)=@_;
    my $smbcquotas_command=
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
        " ".$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS_PROTOCOL_OPT'}.
        " -U ".$DevelConf::sophomorix_file_admin."%'".
        $smb_admin_pass."'".
        " -F //$root_dns/$share";
        #print "$smbcquotas_command\n";
        my $return_quota=system("$smbcquotas_command > /dev/null");
        if ($return_quota==0){
            $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'}="TRUE";
            $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'}="OK";
	}  else {
            $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'}="FALSE";
            $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'}="NOT OK";
	}
}



sub next_free_uidnumber_set {
    my ($ldap,$root_dse,$uidnumber) = @_;
    # test for numbers ??? 0-9
    if (not defined $uidnumber){
       $uidnumber="10000";
    }
    #print "* setting uidNumber to file/ldap: $uidnumber\n";
    system("echo $uidnumber > $DevelConf::next_free_uidnumber_file");
}



sub next_free_uidnumber_get {
    # _prop : proposed number
    my ($ldap,$root_dse) = @_;
    my $uidnumber_free;
    if (not -e $DevelConf::next_free_uidnumber_file){
        &next_free_uidnumber_set($ldap,$root_dse,"10000");
    }
    my $uidnumber_prop= `cat $DevelConf::next_free_uidnumber_file`;
    chomp($uidnumber_prop);
    #print "* getting uidNumber from file/ldap: $uidnumber_prop\n";
    my $count=1;
    until ($count==0){
        #print "   * Testing uidNumber <$uidnumber_prop>\n";
        my $filter="(&(objectClass=user) (uidNumber=".$uidnumber_prop."))"; 
        #print "      * Filter: $filter\n";
        my $mesg = $ldap->search(
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attr => ['cn']
                            );
        $count = $mesg->count;
        #print "      * Hits: $count\n";
        if ($count>0){
            $uidnumber_prop++;
        } else {
            $uidnumber_free=$uidnumber_prop;
        }
    }
    &Sophomorix::SophomorixBase::print_title("Next Free uidNumber is: $uidnumber_free");
    my $uidnumber_free_next=$uidnumber_free+1;
    &next_free_uidnumber_set($ldap,$root_dse,$uidnumber_free_next);
    return $uidnumber_free;
}



sub next_free_gidnumber_set {
    my ($ldap,$root_dse,$gidnumber) = @_;
    # test for numbers ??? 0-9
    if (not defined $gidnumber){
       $gidnumber="10000";
    }
    #print "* setting gidnumber to file/ldap: $gidnumber\n";
    system("echo $gidnumber > $DevelConf::next_free_gidnumber_file");
}



sub next_free_gidnumber_get {
    # _prop : proposed number
    my ($ldap,$root_dse) = @_;
    my $gidnumber_free;
    if (not -e $DevelConf::next_free_gidnumber_file){
        &next_free_gidnumber_set($ldap,$root_dse,"10000");
    }
    my $gidnumber_prop= `cat $DevelConf::next_free_gidnumber_file`;
    chomp($gidnumber_prop);
    #print "* getting gidNumber from file/ldap: $gidnumber_prop\n";
    my $count=1;
    until ($count==0){
        #print "   * Testing gidNumber <$gidnumber_prop>\n";
        my $filter="(&(objectClass=user) (gidnumber=".$gidnumber_prop."))"; 
        #print "      * Filter: $filter\n";
           my $mesg = $ldap->search(
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attr => ['cn']
                            );
        $count = $mesg->count;
        #print "      * Hits: $count\n";
        if ($count>0){
            $gidnumber_prop++;
        } else {
            $gidnumber_free=$gidnumber_prop;
        }
    }
    &Sophomorix::SophomorixBase::print_title("Next Free gidNumber is: $gidnumber_free");
    my $gidnumber_free_next=$gidnumber_free+1;
    &next_free_gidnumber_set($ldap,$root_dse,$gidnumber_free_next);
    return $gidnumber_free;
}



sub _uac_disable_user {
    my ($uac)=@_;
    # bit 2 to set must be 1, OR
    my $set_disable_bit = 0b0000_0000_0000_0000_0000_0000_0000_0010;
    my $res = $uac | $set_disable_bit;
    return $res;
}



sub _uac_enable_user {
    my ($uac)=@_;
    # bit 2 to set must be 0, AND
    my $set_enable_bit =  0b1111_1111_1111_1111_1111_1111_1111_1101;
    my $res = $uac & $set_enable_bit;
    return $res;
}



sub _keep_object_class_only {
    # keep only items with objectClass $type_to_keep in @keep_list
    my $ldap = shift;
    my $root_dse = shift;
    my $type_to_keep = shift; 
    my @list = @_;
    my @keep_list=();
    foreach my $item (@list){
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,$type_to_keep,$item);
        if ($count==1){ #its a user/group
            push @keep_list, $item;
        } else {
            print "   * WARNING: $item is not of objectClass $type_to_keep (Skipping $item)\n";
        }
    } 
    return @keep_list;
}



sub _project_info_prefix {
    my ($ldap,$root_dse,$type,@list)=@_;
    my @list_prefixed=();
    # finding status of user/group
    # ? nonexisting
    # - existing
    foreach my $item (@list){
        #print "$type: $item\n"; 
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,$type,$item);
        if ($count==0){
            push @list_prefixed,"?".$item;
        } elsif ($count==1){
            push @list_prefixed,"-".$item;
        } else {
            push @list_prefixed,"???".$item;
        }
    }
    return @list_prefixed;
}



sub _unipwd_from_plainpwd{
    # create string for unicodePwd in AD from $sophomorix_first_password 
    my ($sophomorix_first_password) = @_;
    # build the conversion map from your local character set to Unicode 
    my $charmap = Unicode::Map8->new('latin1')  or  die;
    # surround the PW with double quotes and convert it to UTF-16
    my $uni_password = $charmap->tou('"'.$sophomorix_first_password.'"')->byteswap()->utf16();
    return $uni_password;
}



sub _create_filter_alldevices {
    my ($ref_devicelist,$ref_sophomorix_config)=@_;
    my $objectclass_filter="(objectClass=computer)";
    my $role_filter="(|";
    foreach my $keyname (keys %{$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}}) {
        $role_filter=$role_filter."(sophomorixRole=".$keyname.")";
    }
    $role_filter=$role_filter.")";
    my $sam_filter;
    if ($ref_devicelist eq ""){
        # no list given
        $sam_filter="";
    } elsif ($#{ $ref_devicelist }==0){
        $sam_filter="(sAMAccountName=".${ $ref_devicelist }[0].")"; 
    } else {
        $sam_filter="(|";
        foreach my $device ( @{ $ref_devicelist } ){
            $sam_filter=$sam_filter."(sAMAccountName=".$device.")";
        } 
        $sam_filter=$sam_filter.")";
    }
    $filter="(& ".$objectclass_filter." ".$role_filter." ".$sam_filter." )";
    return $filter;
}



# END OF FILE
# Return true=1
1;
