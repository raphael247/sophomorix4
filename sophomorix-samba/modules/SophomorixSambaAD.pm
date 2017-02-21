#!/usr/bin/perl -w
# This perl module SophomorixSambaAD is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linuxmuster.net

package Sophomorix::SophomorixSambaAD;
require Exporter;
#use File::Basename;
#use Time::Local;
#use Time::localtime;
#use Quota;
#use Sys::Filesystem ();
use Unicode::Map8;
use Unicode::String qw(utf16);
use Net::LDAP;
use Net::LDAP::Control::Sort;
use List::MoreUtils qw(uniq);
use File::Basename;
#use Sophomorix::SophomorixBase;
use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 

@ISA = qw(Exporter);

@EXPORT_OK = qw( );
@EXPORT = qw(
            AD_get_passwd
            AD_bind_admin
            AD_unbind_admin
            AD_get_sessions
            AD_session_manage
            AD_session_set_exam
            AD_session_unset_exam
            AD_user_create
            AD_user_update
            AD_get_user
            AD_computer_create
            AD_user_move
            AD_user_kill
            AD_computer_kill
            AD_group_create
            AD_group_kill
            AD_group_addmember
            AD_group_addmember_management
            AD_group_removemember
            AD_group_update
            AD_group_list
            AD_get_schoolname
            AD_get_name_tokened
            get_forbidden_logins
            AD_ou_create
            AD_school_add
            AD_object_search
            AD_get_AD
            AD_class_fetch
            AD_project_fetch
            AD_dn_fetch_multivalue
            AD_project_sync_members
            AD_admin_list
            AD_object_move
            AD_debug_logdump
            AD_login_test
            AD_dns_get
            AD_dns_create
            AD_dns_zonecreate
            AD_dns_kill
            AD_dns_zonekill
            AD_repdir_using_file
            next_free_uidnumber_set
            next_free_uidnumber_get
            next_free_gidnumber_set
            next_free_gidnumber_get
            );

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
    if (not -e $DevelConf::secret_file_sophomorix_admin){
        print "\nERROR: Connection to AD failed: No password found!\n\n";
        print "sophomorix connects to AD with the user $DevelConf::sophomorix_admin:\n";
        print "  A) Make sure $DevelConf::sophomorix_admin exists:\n";
        print "     samba-tool user create $DevelConf::sophomorix_admin %Muster!% \n";
        print "     (Replace Muster! according to: samba-tool domain passwordsettings show)\n";
        print "  B) Store the Password of $DevelConf::sophomorix_admin (without newline character) in:\n";
        print "     $DevelConf::secret_file_sophomorix_admin\n";
        print "\n";
        exit;
    }

    my ($smb_pwd)=&AD_get_passwd($DevelConf::sophomorix_admin,$DevelConf::secret_file_sophomorix_admin);
    my $host="ldaps://localhost";
    # check connection to Samba4 AD
    if($Conf::log_level>=3){
        print "   Checking Samba4 AD connection ...\n";
    }

    #my $ldap = Net::LDAP->new('ldaps://localhost')  or  die "$@";
    my $ldap = Net::LDAP->new($host)  or  
         &Sophomorix::SophomorixBase::log_script_exit(
                            "No connection to Samba4 AD!",
         1,1,0,@arguments);

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
    my $sophomorix_admin_dn="CN=".$DevelConf::sophomorix_admin.",CN=Users,".$root_dse;
    if($Conf::log_level>=2){
        print "Binding with $sophomorix_admin_dn\n";
    }
    my $mesg = $ldap->bind($sophomorix_admin_dn, password => $smb_pwd);
    # show errors from bind
    &AD_debug_logdump($mesg,2,(caller(0))[3]);

    # Testing if sophomorix schema is present
    # ldbsearch -H ldap://localhost -UAdministrator%Muster! -b cn=Schema,cn=Configuration,DC=linuxmuster,DC=local cn=Sophomorix-User
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
    my $smb_pwd = $arg_ref->{smb_pwd};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_zone = $arg_ref->{dns_zone};
    my $dns_node = $arg_ref->{dns_node};
    my $dns_ipv4 = $arg_ref->{dns_ipv4};
    my $dns_type = $arg_ref->{dns_type};
    my $dns_admin_description = $arg_ref->{dns_admin_description};
    my $dns_cn = $arg_ref->{dns_cn};
    my $filename = $arg_ref->{filename};
#    my $dns_line = $arg_ref->{dns_line};

    # extract host from line (may become obsolete) ?????????????????ß
#    if (defined $dns_line and not defined $dns_node){
#        my @items = split(/;/,$dns_line);
#        $dns_node=$items[1];
#        $dns_ipv4=$items[4];
#    }

    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title(
              "Creating dnsNode: $dns_node");
    } 

    # set defaults if not defined
    if (not defined $filename){
        $filename="---";
    }
     if (not defined $dns_admin_description){
        $dns_admin_description=$DevelConf::dns_node_prefix_string." from ".$filename;
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
    if (not defined $dns_zone){
        $dns_zone=&AD_dns_get($root_dse);
    }
    
    # adding dnsNode with samba-tool
    my $command="  samba-tool dns add $dns_server $dns_zone $dns_node $dns_type $dns_ipv4".
                " --password='$smb_pwd' -U $DevelConf::sophomorix_admin";
    print "$command\n";
    system($command);

    # adding comments to recognize the dnsNode as created by sophomorix
    my ($count,$dn_exist_dnshost,$cn_exist_dnshost)=&AD_object_search($ldap,$root_dse,"dnsNode",$dns_node);
    print "   * Adding Comments to dnsNode $dns_node\n";

    if ($count > 0){
             print "   * dnsNode $dns_node exists ($count results)\n";
             my $mesg = $ldap->modify( $dn_exist_dnshost, add => {
                                       adminDescription => $dns_admin_description,
                                       cn => $dns_cn,
                                      });
             &AD_debug_logdump($mesg,2,(caller(0))[3]);
             return;
         }
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

    # adding dnsNode with samba-tool
    my $command="  samba-tool dns zonecreate $dns_server $dns_zone --password='$smb_pwd' -U $DevelConf::sophomorix_admin";
    print "$command\n";
    system($command);

    # adding comments to recognize the dnsZone as created by sophomorix
    my ($count,$dn_exist_dnszone,$cn_exist_dnszone)=&AD_object_search($ldap,$root_dse,"dnsZone",$dns_zone);
    print "   * Adding Comments to dnsZone $dns_zone\n";

    if ($count > 0){
             print "   * dnsZone $dns_zone exists ($count results)\n";
             my $mesg = $ldap->modify($dn_exist_dnszone, add => {
                                      adminDescription => $dns_admin_description,
                                      cn => $dns_cn,
                                     });
             &AD_debug_logdump($mesg,2,(caller(0))[3]);
             return;
         }
}



sub AD_dns_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
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

    my $command="samba-tool dns delete $dns_server $dns_zone $dns_node $dns_type $dns_ipv4 --password='$smb_pwd' -U $DevelConf::sophomorix_admin";
    print "     * $command\n";
    system($command);
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

    my $command="samba-tool dns zonedelete $dns_server $dns_zone --password='$smb_pwd' -U $DevelConf::sophomorix_admin";
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
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    # optional options
    my $school = $arg_ref->{school};

    my $repdir_file_base = basename($repdir_file);
    my $entry_num=0; # was $num
    my $line_num=0;
    &Sophomorix::SophomorixBase::print_title("Repairing from file: $repdir_file_base");

    # option school
    my @schools=("");
    if (defined $school){
        @schools=($school);
    }

    # reading repdir file
    open(REPDIRFILE, "<$repdir_file")|| die "ERROR: $repdir_file $!";
    while (<REPDIRFILE>) {
        $line_num++;
        my $group_type="";
        my $groupvar_count=0;
        chomp();   
        if ($_ eq ""){next;} # next on empty line
        if(/^\#/){next;} # next on comments

        $entry_num++;
        if (/\@\@SCHOOL\@\@/ and not defined $school) {
            @schools = @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
        }

        if (/\@\@ADMINCLASS\@\@/) {
            $group_type="adminclass";
            $groupvar_count++;
        }
        if (/\@\@TEACHERCLASS\@\@/) {
            $group_type="teacherclass";
            $groupvar_count++;
        }
        if (/\@\@PROJECT\@\@/) {
            $group_type="project";
            $groupvar_count++;
        }
        if (/\@\@MANAGEMENT\@\@/) {
            $group_type="admins";
            $groupvar_count++;
        }

        my ($os,$path_with_var, $owner, $groupowner, $permission,$ntacl) = split(/::/);

        # replacing $vars in path
        my @old_dirs=split(/\//,$path_with_var);
        my @new_dirs=();
        foreach my $dir (@old_dirs){
            $dir=">".$dir."<"; # add the ><, so that no substrings will be replaced
            # /var
            $dir=~s/>\$path_log</${DevelConf::path_log}/;
            $dir=~s/>\$path_log_user</${DevelConf::path_log_user}/;
            # /home
            $dir=~s/>\$homedir_all_schools</${DevelConf::homedir_all_schools}/;
            $dir=~s/>\$homedir_global</${DevelConf::homedir_global}/;
            # other
            $dir=~s/>\$directory_students</${DevelConf::directory_students}/;
            $dir=~s/>\$directory_projects</${DevelConf::directory_projects}/;
            $dir=~s/>\$directory_management</${DevelConf::directory_management}/;
            # remove <,>
            $dir=~s/^>//g;
            $dir=~s/<$//g;
	    push @new_dirs,$dir;
        }
        $path_with_var=join("/",@new_dirs);

        print "------------------------------------------------------------\n";
        print "$entry_num) Line $line_num:  $_:\n";
        if($Conf::log_level>=3){
            print "   Type:     $os\n";
            print "   Path:     $path_with_var\n";
            print "   Owner:    $owner\n";
            print "   Group:    $groupowner\n";
            print "   Perm:     $permission\n";
            print "   NT-ACL:   $ntacl\n";
            print "   Schools:  @schools\n";
        }

        ########################################
        # school loop start             
        foreach my $school (@schools){
            my $path=$path_with_var;
            my $path_smb=$path_with_var;
            $path=~s/\@\@SCHOOL\@\@/$school/;
            $path_smb=~s/\@\@SCHOOL\@\@\///;
            if($Conf::log_level>=3){
                print "   Determining path for school $school:\n";
                print "      * Path after school: $path (smb: $path_smb)\n";
            }
            # determining groups to walk through
            my @groups;
            if ($groupvar_count==0){
                # no vars found -> one single loop
                @groups=("");
            } else {
                # vars found
                if(defined $ref_AD->{'lists'}{'by_school'}{$school}{'groups_by_type'}{$group_type}){
                    # there is a group list -> use it
                    @groups=@{ $ref_AD->{'lists'}{'by_school'}{$school}{'groups_by_type'}{$group_type} };
                } else {
                    # there is no group list -> avoid the even a single loop 
                    @groups=();
	        }
#                if(defined $AD{'lists'}{'by_school'}{$school}{'groups_by_type'}{$group_type}){
#                    # there is a group list -> use it
#                    @groups=@{ $AD{'lists'}{'by_school'}{$school}{'groups_by_type'}{$group_type} };
#                } else {
#                    # there is no group list -> avoid the even a single loop 
#                    @groups=();
#	        }
            }
            ########################################
            # group loop start
            foreach my $group (@groups){
                my $group_basename=$group;

                # calculating group basename without prefix
                $group_basename=~s/^${school}-//;
                print "working with group $group >$group_basename< ...\n";

                my $path_after_group=$path;
                $path_after_group=~s/\@\@ADMINCLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@TEACHERCLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@PROJECT\@\@/$group_basename/;
                $path_after_group=~s/\@\@MANAGEMENT\@\@/management/;
                my $path_after_group_smb=$path_smb;
                $path_after_group_smb=~s/\@\@ADMINCLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@TEACHERCLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@PROJECT\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@MANAGEMENT\@\@/management/;
                if($Conf::log_level>=3){      
                    print "      * Path after group:  $path_after_group (smb: $path_after_group_smb)\n";
                }

                ########################################
                # user loop start
                my @users=("");
                if ($path_after_group=~/\@\@USER\@\@/) {
#                    if (defined $AD{'lists'}{'by_school'}{$school}{'users_by_group'}{$group}){
#                        @users = @{ $AD{'lists'}{'by_school'}{$school}{'users_by_group'}{$group} };
                    if (defined $ref_AD->{'lists'}{'by_school'}{$school}{'users_by_group'}{$group}){
                        @users = @{ $ref_AD->{'lists'}{'by_school'}{$school}{'users_by_group'}{$group} };
                    } else {
                        print "\n";
                        print "##### No users in $group #####\n";
                        # empty list means do nothing in next loop
                        @users=();
                    }
                }
                foreach my $user (@users){
                    my $path_after_user=$path_after_group;
                    $path_after_user=~s/\@\@USER\@\@/$user/;
                    my $path_after_user_smb=$path_after_group_smb;
                    $path_after_user_smb=~s/\@\@USER\@\@/$user/;
                    if($Conf::log_level>=3){      
                        print "      * Path after user:   $path_after_user (smb: $path_after_user_smb)\n";
	            }
                    if ($os eq "SMB"){
                        # smbclient
                        my $smbclient_command="smbclient -U Administrator%'Muster!'".
                                              " //$root_dns/$school -c 'mkdir $path_after_user_smb'";
                        print "\n";
                        print "##### User: $user #####\n";
                        print "$smbclient_command\n";
                        system($smbclient_command);

                        # smbcacls
                        &Sophomorix::SophomorixBase::NTACL_set_file({root_dns=>$root_dns,
                                                                     school=>$school,
                                                                     ntacl=>$ntacl,
                                                                     smbpath=>$path_after_user_smb,
                                                                   });
                   } elsif ($os eq "LINUX"){
                        mkdir $path_after_user;
                        my $chown_command="chown ".$owner.".".$groupowner." ".$path_after_user;
                        print "          $chown_command\n";
                        system($chown_command);
                        chmod oct($permission), $path_after_user;
                    } else {
                        print "\nERROR: $os unknown\n\n";
                        exit;
                    }
                } # user loop end 
            } # group loop end 
        } # school loop end
        print "--- DONE with $entry_num) Line $line_num:  $_---\n";
    }
    close(REPDIRFILE);
}




sub AD_user_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $user = $arg_ref->{login};
    my $identifier = $arg_ref->{identifier};
    my $user_count = $arg_ref->{user_count};

    &Sophomorix::SophomorixBase::print_title("Killing User $user ($user_count):");
    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$user);
    if ($count > 0){
        my $command="samba-tool user delete ". $user;
        print "   # $command\n";
        system($command);
        return;
    } else {
        print "   * User $user nonexisting ($count results)\n";
        return;
    }
}



sub AD_computer_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $ws = $arg_ref->{workstation};
    my $count = $arg_ref->{count};
    &Sophomorix::SophomorixBase::print_title("Killing computer $ws ($count):");
    my $dn="";
    my $filter="(&(objectClass=computer)(sophomorixRole=computer)(sAMAccountName=".$ws."))";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName']
                         );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $count_result = $mesg->count;
    if ($count_result==1){
        my ($entry,@entries) = $mesg->entries;
        $dn = $entry->dn();
        print "   * DN: $dn\n";
        my $mesg = $ldap->delete( $dn );
    } else {
        print "   * WARNING: $ws not found/to many items ($count_result results)\n";     
    }
}



sub AD_group_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $group = $arg_ref->{group};
    my $type = $arg_ref->{type};
    my $group_count = $arg_ref->{group_count};

    &Sophomorix::SophomorixBase::print_title("Killing Group($type) $group:");
    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count > 0){
        my $command="samba-tool group delete ". $group;
        print "   # $command\n";
        system($command);
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
    my $ws_count = $arg_ref->{ws_count};
    my $school = $arg_ref->{school};
    my $creationdate = $arg_ref->{creationdate};

    # calculation
    my $display_name=$name;
    my $smb_name=$name."\$";

    # dns
    my $root_dns=&AD_dns_get($root_dse);

    $dns_name=$name.".".$root_dns;
    my @service_principal_name=("HOST/".$name,
                                "HOST/".$dns_name,
                                "RestrictedKrbHost/".$name,
                                "RestrictedKrbHost/".$dns_name,
                               );
    my $container=&AD_get_container($role,$room_basename);
    my $dn_room = $container."OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    my $dn = "CN=".$name.",".$container."OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    my $prefix=$school;
    if ($school eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }

    if($Conf::log_level>=1){
        &Sophomorix::SophomorixBase::print_title(
              "Creating workstation $ws_count: $name");
        print "   DN:                    $dn\n";
        print "   DN(Parent):            $dn_room\n";
        print "   Name:                  $name\n";
        print "   Room:                  $room\n";
        print "   School:                $school\n";
        print "   Prefix:                $prefix\n";
        print "   sAMAccountName:        $smb_name\n";
        print "   dNSHostName:           $dns_name\n";
        foreach my $entry (@service_principal_name){
            print "   servicePrincipalName:  $entry\n";
        }
        print "\n";
    }
   $ldap->add($dn_room,attr => ['objectclass' => ['top', 'organizationalUnit']]);
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
#                   sophomorixUnid => $unid,
                   sophomorixStatus => "P",
                   sophomorixAdminClass => $room,    
#                   sophomorixFirstPassword => $plain_password, 
#                   sophomorixFirstnameASCII => $firstname_ascii,
#                   sophomorixSurnameASCII  => $surname_ascii,
                   sophomorixRole => "computer",
                   sophomorixSchoolPrefix => $prefix,
                   sophomorixSchoolname => $school,
                   sophomorixCreationDate => $creationdate, 
                   userAccountControl => '4096',
                   instanceType => '4',
                   objectclass => ['top', 'person',
                                     'organizationalPerson',
                                     'user','computer' ],
#                   'objectclass' => \@objectclass,
                           ]
                           );
    &AD_debug_logdump($result,2,(caller(0))[3]);
}



sub AD_session_manage {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $creationdate = $arg_ref->{creationdate};
    my $supervisor = $arg_ref->{supervisor};
    my $create = $arg_ref->{create};
    my $kill = $arg_ref->{kill};
    my $session = $arg_ref->{session};
    my $new_comment = $arg_ref->{comment};
    my $developer_session = $arg_ref->{developer_session};
    my $new_participants = $arg_ref->{participants};
    my $ref_sessions = $arg_ref->{sessions_ref};

    # the updated session string
    my $session_string_new="";
    my $session_new="";        
    if (defined $creationdate){
        # create session with current timestamp
        $session_new=$creationdate;
    } else {
        $creationdate="---";
    }

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
        } elsif ($creationdate ne "---"){
            # new session
            # this is the default
            $session_new=$creationdate;
            $session_string_new=$creationdate.";".$new_comment.";".$new_participants.";";
        } else {
            
        }
    } elsif (defined $session and defined $new_participants and defined $new_comment){
        # modifying the session
        if (defined $ref_sessions->{'id'}{$session}{'supervisor'}{'name'}){
            # get data from session hash
            $session_new=$session;
            $supervisor=$ref_sessions->{'id'}{$session}{'supervisor'}{'name'};
            $session_string_old=$ref_sessions->{'id'}{$session}{'sophomorixSessions'};
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



sub AD_session_set_exam {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $supervisor = $arg_ref->{supervisor};
    my $user_count = $arg_ref->{user_count};
    print "   * Setting exam mode for session participant $participant (Supervisor: $supervisor)\n";
    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$participant);
    if (not $count==1){
        print "ERROR: Could not set exam mode for nonexisting user $participant\n";
        return;
    }
    &AD_user_update({ldap=>$ldap,
                     root_dse=>$root_dse,
                     dn=>$dn,
                     user=>$participant,
                     user_count=>$user_count,
                     exammode=>$supervisor,
                   });
}



sub AD_session_unset_exam {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $supervisor = $arg_ref->{supervisor};
    my $user_count = $arg_ref->{user_count};
    print "   * Unsetting exam mode for session participant $participant (Supervisor: $supervisor)\n";
    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$participant);
    if (not $count==1){
        print "ERROR: Could not unset exam mode for nonexisting user $participant\n";
        return;
    }
    &AD_user_update({ldap=>$ldap,
                     root_dse=>$root_dse,
                     dn=>$dn,
                     user=>$participant,
                     user_count=>$user_count,
                     exammode=>"---",
                   });
}



sub AD_user_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user_count = $arg_ref->{user_count};
    my $identifier = $arg_ref->{identifier};
    my $login = $arg_ref->{login};
    my $group = $arg_ref->{group};
    my $group_basename = $arg_ref->{group_basename};
    my $firstname_ascii = $arg_ref->{firstname_ascii};
    my $surname_ascii = $arg_ref->{surname_ascii};
    my $firstname_utf8 = $arg_ref->{firstname_utf8};
    my $surname_utf8 = $arg_ref->{surname_utf8};
    my $birthdate = $arg_ref->{birthdate};
    my $plain_password = $arg_ref->{plain_password};
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
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};


    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title(
              "Creating User $user_count : $login");
    }

    # set defaults if not defined
    if (not defined $identifier){
        $identifier="---";
    }
    if (not defined $unid){
        $unid="---";
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

    # calculate
    my $shell="/bin/false";
    my $display_name = $firstname_utf8." ".$surname_utf8;
    my $user_principal_name = $login."\@"."linuxmuster.local";
    my $container=&AD_get_container($role,$group_basename);

    my ($homedirectory,$unix_home)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school,
                                                       $group_basename,
                                                       $login,
                                                       $role);

    my $dn_class = $container."OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    my $dn = "cn=".$login.",".$container."OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    # ou for administrators
    if ($role eq "administrator"){
        # bei global muss im hash in GLOBAL gesucht werden 
        if ($school eq $DevelConf::AD_global_ou or $school eq "global"){
            $dn_class=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{ADMINS}{OU};
	    $dn="cn=".$login.",".$dn_class;
        } else {
            $dn_class=$ref_sophomorix_config->{'SCHOOLS'}{$school}{ADMINS}{OU};
	    $dn="cn=".$login.",".$dn_class;
        }
    }

    # password generation
    my $uni_password=&_unipwd_from_plainpwd($plain_password);

    ## build the conversion map from your local character set to Unicode    
    #my $charmap = Unicode::Map8->new('latin1')  or  die;
    ## surround the PW with double quotes and convert it to UTF-16
    #my $uni_password = $charmap->tou('"'.$plain_password.'"')->byteswap()->utf16();

    my $prefix=$school;
    if ($school eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }

    if($Conf::log_level>=1){
        print "   DN:                 $dn\n";
        print "   DN(Parent):         $dn_class\n";
        print "   Surname(ASCII):     $surname_ascii\n";
        print "   Surname(UTF8):      $surname_utf8\n";
        print "   Firstname(ASCII):   $firstname_ascii\n";
        print "   Firstname(UTF8):    $firstname_utf8\n";
        print "   Birthday:           $birthdate\n";
        print "   Identifier:         $identifier\n";
        print "   School:             $school\n"; # Organisatinal Unit
        print "   Role(User):         $role\n";
        print "   Status:             $status\n";
        print "   Type(Group):        $type\n";
        print "   Group:              $group\n"; # lehrer oder klasse
        #print "   GECOS:              $gecos\n";
        #print "   Login (to check):   $login_name_to_check\n";
        print "   Login (check OK):   $login\n";
        print "   Password:           $plain_password\n";
        # sophomorix stuff
        print "   Creationdate:       $creationdate\n";
        print "   Tolerationdate:     $tolerationdate\n";
        print "   Deactivationdate:   $deactivationdate\n";
        print "   Unid:               $unid\n";
        print "   Unix-uidNumber:     $uidnumber_wish\n";
        print "   File:               $file\n";
        print "   homeDirectory:      $homedirectory\n";
        print "   unixHomeDirectory:  $unix_home\n";
    }

    # make sure $dn_class exists
    $ldap->add($dn_class,attr => ['objectclass' => ['top', 'organizationalUnit']]);

    # add the user
    my $result = $ldap->add( $dn,
                   attr => [
                   sAMAccountName => $login,
                   givenName => $firstname_utf8,
                   sn => $surname_utf8,
                   displayName => [$display_name],
                   userPrincipalName => $user_principal_name,
                   unicodePwd => $uni_password,
                   homeDrive => "H:",
                   homeDirectory => $homedirectory,
                   unixHomeDirectory => $unix_home,
                   sophomorixExitAdminClass => "unknown", 
                   sophomorixUnid => $unid,
                   sophomorixStatus => $status,
                   sophomorixAdminClass => $group,    
                   sophomorixAdminFile => $file,    
                   sophomorixFirstPassword => $plain_password, 
                   sophomorixFirstnameASCII => $firstname_ascii,
                   sophomorixSurnameASCII  => $surname_ascii,
                   sophomorixBirthdate  => $birthdate,
                   sophomorixRole => $role,
                   sophomorixSchoolPrefix => $prefix,
#                   sophomorixCustom => "Tst",
                   sophomorixSchoolname => $school,
                   sophomorixCreationDate => $creationdate, 
                   sophomorixTolerationDate => $tolerationdate, 
                   sophomorixDeactivationDate => $deactivationdate, 
                   sophomorixComment => "created by sophomorix", 
                   sophomorixExamMode => "---", 
                   userAccountControl => '512',
                   uidNumber => $uidnumber_wish,
                   objectclass => ['top', 'person',
                                     'organizationalPerson',
                                     'user' ],
#                   'objectclass' => \@objectclass,
                           ]
                           );
    &AD_debug_logdump($result,2,(caller(0))[3]);

    # add user to management groups (not to admin)
    my @grouplist=("wifi","internet","webfilter","intranet","printing");
    foreach my $group (@grouplist){
        my $management_group=&AD_get_name_tokened($group,$school,"management");
        &AD_group_addmember_management({ldap => $ldap,
                                        root_dse => $root_dse, 
                                        group => $management_group,
                                        addmember => $login,
                                       }); 
    }

    # add administrators to admin group
    if ($role eq "administrator"){
        # add to *-admins of the school, or global-admins
        my $management_group=&AD_get_name_tokened("admins",$school,"management");
        &AD_group_addmember_management({ldap => $ldap,
                                        root_dse => $root_dse, 
                                        group => $management_group,
                                        addmember => $login,
                                       }); 
        if ($school eq "global"){ # not GLOBAL (its the sophomorix-admin option --school)
            # global admin users are 'Domain Admins'
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => "Domain Admins",
                                 addmember => $login,
                               });
        } else {
            # school admin users are NOT 'Domain Admins'
            # do nothing
        }
        # deprecated becaus school-admin users would result as 'Domain Admins'
        ## add/make sure group global-admins to 'Domain admins'
        #&AD_group_addmember({ldap => $ldap,
        #                     root_dse => $root_dse, 
        #                     group => "Domain Admins",
        #                     addgroup => "global-admins",
        #                   });
    }

    &Sophomorix::SophomorixBase::print_title("Creating User $user_count (end)");
}



sub AD_user_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $dn = $arg_ref->{dn};
    my $firstname_ascii = $arg_ref->{firstname_ascii};
    my $surname_ascii = $arg_ref->{surname_ascii};
    my $firstname_utf8 = $arg_ref->{firstname_utf8};
    my $surname_utf8 = $arg_ref->{surname_utf8};
    my $filename = $arg_ref->{filename};
    my $birthdate = $arg_ref->{birthdate};
    my $unid = $arg_ref->{unid};
    my $user_count = $arg_ref->{user_count};
    my $user = $arg_ref->{user};
    my $firstpassword = $arg_ref->{firstpassword};
    my $plain_password = $arg_ref->{plain_password};
    my $status = $arg_ref->{status};
    my $comment = $arg_ref->{comment};
    my $webui_dashboard = $arg_ref->{webui_dashboard};
    my $user_permissions = $arg_ref->{user_permissions};
    my $user_account_control = $arg_ref->{user_account_control};
    my $school = $arg_ref->{school};
    my $role = $arg_ref->{role};
    my $examteacher = $arg_ref->{exammode};

    my $displayname;
    # hash of what to replace
    my %replace=();
    # list of what to delete
    my @delete=();

    if (defined $firstname_utf8 and 
        defined $surname_utf8 and
        defined $firstname_ascii and
        defined $surname_ascii){
        # ok if all 4 are defined
    } elsif (not defined $firstname_utf8 and 
             not defined $surname_utf8 and
             not defined $firstname_ascii and
             not defined $surname_ascii){
        # ok if none are defined
    } else {
        print "ERROR updating $user -> givenName,sn,sophomorixFirstnameASCII,sophomorixSurnameASCII\n";
        return;
    }

    &Sophomorix::SophomorixBase::print_title(
          "Updating User ${user_count}: $user");
    print "   DN: $dn\n";

    if (defined $firstname_utf8 and $firstname_utf8 ne "---"){
        $replace{'givenName'}=$firstname_utf8;
        print "   givenName:                 $firstname_utf8\n";
    }
    if (defined $surname_utf8 and $surname_utf8 ne "---"){
        $replace{'sn'}=$surname_utf8;
        print "   sn:                        $surname_utf8\n";
    }
    if (defined $firstname_utf8 and 
        $surname_utf8 and 
        $firstname_utf8 ne "---" and 
        $surname_utf8 ne "---"
       ){
        $display_name = $firstname_utf8." ".$surname_utf8;
        $replace{'displayName'}=$display_name;
        print "   displayName:               $display_name\n";
    }
    if (defined $firstname_ascii and $firstname_ascii ne "---" ){
        $replace{'sophomorixFirstnameASCII'}=$firstname_ascii;
        print "   sophomorixFirstnameASCII:  $firstname_ascii\n";
    }
    if (defined $surname_ascii and $surname_ascii ne "---"){
        $replace{'sophomorixSurnameASCII'}=$surname_ascii;
        print "   sophomorixSurnameASCII:    $surname_ascii\n";
    }
    if (defined $birthdate and $birthdate ne "---"){
        $replace{'sophomorixBirthdate'}=$birthdate;
        print "   sophomorixBirthdate:       $birthdate\n";
    }
    if (defined $filename and $filename ne "---"){
        $replace{'sophomorixAdminFile'}=$filename;
        print "   sophomorixAdminFile:       $filename\n";
    }
    if (defined $unid and $unid ne "---"){
        if ($unid eq ""){
            $unid="---"; # upload --- for empty unid
        }
        $replace{'sophomorixUnid'}=$unid;
        print "   sophomorixUnid:            $unid\n";
    }
    if (defined $firstpassword){
        $replace{'sophomorixFirstpassword'}=$firstpassword;
        print "   Firstpassword:             $firstpassword\n";
    }
    if (defined $plain_password){
        my $uni_password=&_unipwd_from_plainpwd($plain_password);
        $replace{'unicodePwd'}=$uni_password;
        print "   unicodePwd:                **********\n";
    }
    if (defined $status and $status ne "---"){
        $replace{'sophomorixStatus'}=$status;
        print "   sophomorixStatus:          $status\n";
    }
    if (defined $user_account_control and $user_account_control ne "---"){
        $replace{'userAccountControl'}=$user_account_control;
        print "   userAccountControl:        $user_account_control\n";
    }
    if (defined $school and $school ne "---"){
        # update sophomorixSchoolname AND sophomorixSchoolPrefix
        $replace{'sophomorixSchoolname'}=$school;
        print "   sophomorixSchoolname:      $school\n";
        my $prefix;
        if ($school eq $DevelConf::name_default_school){
            $prefix="---";
        } else {
            $prefix=$school;
        }
        $replace{'sophomorixSchoolPrefix'}=$prefix;
        print "   sophomorixSchoolPrefix:    $prefix\n";
    }
    if (defined $role and $role ne "---"){
        $replace{'sophomorixRole'}=$role;
        print "   sophomorixRole:            $role\n";
    }
    if (defined $examteacher and $examteacher ne ""){
        $replace{'sophomorixExamMode'}=$examteacher;
        print "   sophomorixExamMode:        $examteacher\n";
    }
    if (defined $comment){
        if ($comment eq ""){
            # delete attr if empty
            push @delete, "sophomorixComment";
        } else {
            $replace{'sophomorixComment'}=$comment;
        }
        print "   sophomorixComment:         $comment\n";
    }
    if (defined $webui_dashboard){
        if ($webui_dashboard eq ""){
            # delete attr if empty
            push @delete, "sophomorixWebuiDashboard";
        } else {
            $replace{'sophomorixWebuiDashboard'}=$webui_dashboard;
        }
        print "   sophomorixWebuiDashboard:  $webui_dashboard\n";
    }
    if (defined $user_permissions){
        my @user_permissions=split(/,/,$user_permissions);
        @user_permissions = reverse @user_permissions;
        print "   * Setting sophomorixUserPermissions to: @user_permissions\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixUserPermissions' => \@user_permissions }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # modify
    my $mesg = $ldap->modify( $dn,
		      replace => { %replace }
               );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);

    # delete
    my $mesg2 = $ldap->modify( $dn, 
                       delete => [@delete]
                );
    &AD_debug_logdump($mesg2,2,(caller(0))[3]);
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
        my $existing="TRUE";
        return ($firstname,$lastname,$class,$existing,$exammode,$role);
    }
}



sub AD_user_move {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};
    my $user_count = $arg_ref->{user_count};
    my $group_old = $arg_ref->{group_old};
    my $group_new = $arg_ref->{group_new};
    my $group_old_basename = $arg_ref->{group_old_basename};
    my $group_new_basename = $arg_ref->{group_new_basename};
    my $school_old = $arg_ref->{school_old};
    my $school_new = $arg_ref->{school_new};
    my $role_new = $arg_ref->{role};
    my $creationdate = $arg_ref->{creationdate};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

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

    my $target_branch;
    $school_old=&AD_get_schoolname($school_old);
    $school_new=&AD_get_schoolname($school_new);

    if ($role_new eq "student"){
         $target_branch="OU=".$group_new_basename.",OU=Students,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
    } elsif ($role_new eq "teacher"){
#         $target_branch="OU=".$group_new_basename.",OU=Teachers,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
         $target_branch="OU=Teachers,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
    }

    my ($homedirectory_new,$unix_home_new)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school_new,
                                                       $group_new_basename,
                                                       $user,
                                                       $role_new);

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
        print "   homeDirectory:     $homedirectory_new\n";
        print "   unixHomeDirectory: $unix_home_new\n";
        print "   Creationdate:      $creationdate (if new group must be added)\n";
    }

    # make sure OU and tree exists
    if (not exists $school_created{$school_new}){
         # create new ou
         &AD_school_add({ldap=>$ldap,
                         root_dse=>$root_dse,
                         school=>$school_new,
                         creationdate=>$creationdate,
                         sophomorix_config=>$ref_sophomorix_config,
                       });
         # remember new ou to add it only once
         $school_created{$school_new}="already created";
    } else {
        print "   * OU $school_new already created\n";
    }

    # make sure new group exists
    &AD_group_create({ldap=>$ldap,
                      root_dse=>$root_dse,
                      group=>$group_new,
                      group_basename=>$group_new_basename,
                      description=>$group_new,
                      school=>$school_new,
                      type=>$group_type_new,
                      joinable=>"TRUE",
                      status=>"P",
                      creationdate=>$creationdate,
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

    &Sophomorix::SophomorixBase::print_title("Moving user $user, (end)");
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
        $role eq "room" or 
        $role eq "roomws" or
        $role eq "examaccount" or
        $role eq "computer" or
        $role eq "project" or
        $role eq "management" or
        $role eq "administrator" or
        $role eq "sophomorix-group"){
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
                # add refix to projects: p_ 
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



sub AD_get_container {
    # returns empty string or container followed by comma
    # i.e. >< OR >CN=Students,< 
    # first option: role(user) OR type(group)
    # second option: groupname (with token, i.e. pks-7a) 
    my ($role,$group) = @_;
    my $group_strg="OU=".$group.",";
    my $container="";
    # for user container
    if ($role eq "student"){
        $container=$group_strg.$DevelConf::AD_student_ou;
    }  elsif ($role eq "teacher"){
#        $container=$group_strg.$DevelConf::AD_teacher_ou;
        $container=$DevelConf::AD_teacher_ou;
    }  elsif ($role eq "computer"){
        $container=$group_strg.$DevelConf::AD_devices_ou;
#    }  elsif ($role eq "examaccount"){
#        $container=$group_strg.$DevelConf::AD_examaccount_ou;
    # group container
    }  elsif ($role eq "adminclass"){
        $container=$group_strg.$DevelConf::AD_student_ou;
    }  elsif ($role eq "ouclass"){ # no additional ou with name of group
        $container=$DevelConf::AD_student_ou;
    }  elsif ($role eq "teacherclass"){
        #$container=$group_strg.$DevelConf::AD_teacher_ou;
        $container=$DevelConf::AD_teacher_ou;
    }  elsif ($role eq "project"){
        $container=$DevelConf::AD_project_ou;
    }  elsif ($role eq "sophomorix-group"){
        $container=$DevelConf::AD_project_ou;
    }  elsif ($role eq "room"){
        $container=$group_strg.$DevelConf::AD_devices_ou;
    # other
    }  elsif ($role eq "management"){
        $container=$DevelConf::AD_management_ou;
    }
    # add the comma if necessary
    if ($container ne ""){
        $container=$container.",";
    }
    return $container;
}



sub AD_ou_create {
#     my ($ldap,$root_dse,$dn,$ou)=@_;
#    my $mesg = $ldap->search(
#                       base   => $dn,
#                       scope => 'sub',
#                       filter => 'name=*',
#                       attr => ['cn']
#                             );
#    my $count = $mesg->count;

# print "AD_ou_create $count of $dn\n"; 
#     if ($count==0){
#     &Sophomorix::SophomorixBase::print_title("Creating ou $ou (begin):");
#     print "      * DN:  $dn\n";
#     print "      * OU:  $ou\n";
#     my $result = $ldap->add($dn,attr => [
# # 	                    ou => $ou,
#                             objectclass => ['top', 
#                                             'organizationalUnit']
#                                      ]
#         );
#     &AD_debug_logdump($result,2,(caller(0))[3]);
#     &Sophomorix::SophomorixBase::print_title("Creating ou $ou (end):");
#     }
}



sub AD_school_add {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $school = $arg_ref->{school};
    my $creationdate = $arg_ref->{creationdate};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $gidnumber_wish;

    $school=&AD_get_schoolname($school);

    print "\n";
    &Sophomorix::SophomorixBase::print_title("Adding school $school (begin) ...");

    # providing OU_TOP of school
    my $schools_ou=$DevelConf::AD_schools_ou.",".$root_dse;
    my $result1 = $ldap->add($schools_ou,
                        attr => ['objectclass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result1,2,(caller(0))[3]);

    my $result2 = $ldap->add($ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP},
                        attr => ['objectclass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result1,2,(caller(0))[3]);
    ############################################################
    # sub ou's for OU=*    
    if($Conf::log_level>=2){
        print "   * Adding sub ou's for OU=$school ...\n";
    }

    foreach my $sub_ou (keys %{$ref_sophomorix_config->{'SUB_OU'}{'SCHOOLS'}{'RT_OU'}}) {
        $dn=$sub_ou.",".$ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP};
        print "      * DN: $dn (RT_SCHOOL_OU) $school\n";
        my $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    foreach my $sub_ou (keys %{$ref_sophomorix_config->{'SUB_OU'}{'SCHOOLS'}{'DEVELCONF_OU'}}) {
        my $dn=$sub_ou.",".$ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP};
        print "      * DN: $dn (DEVELCONF_SCHOOL_OU)\n";
        my $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    foreach my $dn (keys %{$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_OU'}}) {
        print "      * DN: $dn (GROUP_OU)\n";
        my $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    ############################################################
    # OU=*    
    if($Conf::log_level>=2){
        print "   * Adding OU's for default groups in OU=$school ...\n";
    }
    foreach my $dn (keys %{$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_CN'}}) {
        print "      * DN: $dn (GROUP_CN)\n";
        # create ou for group
#        &AD_ou_create($ldap,$root_dse,$dn,$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_CN'}{$dn});
        my $group=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_CN'}{$dn};
        my $description=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_DESCRIPTION'}{$group};
        my $type=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_TYPE'}{$group};
        my $school=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'SCHOOL'};
        # create
        &AD_group_create({ldap=>$ldap,
                          root_dse=>$root_dse,
                          dn_wish=>$dn,
                          school=>$school,
                          group=>$group,
                          group_basename=>$group,
                          description=>$description,
                          type=>$type,
                          status=>"P",
                          creationdate=>$creationdate,
                          joinable=>"TRUE",
                          hidden=>"FALSE",
                         });
    }

    ############################################################
    # OU=GLOBAL
    my $result3 = $ldap->add($ref_sophomorix_config->{$DevelConf::AD_global_ou}{OU_TOP},
                        attr => ['objectclass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result3,2,(caller(0))[3]);
    ############################################################
    # sub ou's for OU=GLOBAL    
    if($Conf::log_level>=2){
        print "   * Adding sub ou's for OU=$DevelConf::AD_global_ou ...\n";
    }
    
    foreach my $sub_ou (keys %{$ref_sophomorix_config->{'SUB_OU'}{$DevelConf::AD_global_ou}{'RT_OU'}}) {
        $dn=$sub_ou.",".$ref_sophomorix_config->{$DevelConf::AD_global_ou}{OU_TOP};
        print "      * DN: $dn (RT_GLOBAL_OU)\n";
        my $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    foreach my $sub_ou (keys %{$ref_sophomorix_config->{'SUB_OU'}{$DevelConf::AD_global_ou}{'DEVELCONF_OU'}}) {
        my $dn=$sub_ou.",".$ref_sophomorix_config->{$DevelConf::AD_global_ou}{OU_TOP};
        print "      * DN: $dn (DEVELCONF_GLOBAL_OU)\n";
        my $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    foreach my $dn (keys %{$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_OU'}}) {
        print "      * DN: $dn (GROUP_OU)\n";
        my $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    ############################################################
    # OU=GLOBAL    
    if($Conf::log_level>=2){
        print "   * Adding OU's for default groups in OU=$school ...\n";
    }
    foreach my $dn (keys %{$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_CN'}}) {
        print "      * DN: $dn (GROUP_CN)\n";
        # create ou for group
#        &AD_ou_create($ldap,$root_dse,$dn,$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_CN'}{$dn});

#        $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);
#        &AD_debug_logdump($result,2,(caller(0))[3]);
        my $group=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_CN'}{$dn};
        my $description=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_DESCRIPTION'}{$group};
        my $type=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_TYPE'}{$group};
        my $school=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'SCHOOL'};
        # create
        &AD_group_create({ldap=>$ldap,
                          root_dse=>$root_dse,
                          dn_wish=>$dn,
                          school=>$school,
                          group=>$group,
                          group_basename=>$group,
                          description=>$description,
                          type=>$type,
                          status=>"P",
                          creationdate=>$creationdate,
                          joinable=>"TRUE",
                          hidden=>"FALSE",
                        });
    }
    # all groups created, add some memberships
    foreach my $group (keys %{$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_MEMBER'}}) {
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_MEMBER'}{$group},
                             addgroup => $group,
                            }); 
    }
    &Sophomorix::SophomorixBase::print_title("Adding school $school (end) ...");
    print "\n";
}



sub AD_object_search {
    my ($ldap,$root_dse,$objectclass,$name) = @_;
    # returns 0,"" or 1,"dn of object"
    # objectclass: group, user, ...
    # check if object exists
    # (&(objectclass=user)(cn=pete)
    # (&(objectclass=group)(cn=7a)
    my $filter;
    my $base;
    if ($objectclass eq "dnsNode" or $objectclass eq "dnsZone"){
        # searching dnsNode
        $base="DC=DomainDnsZones,".$root_dse;
        $filter="(&(objectclass=".$objectclass.") (name=".$name."))"; 
    } elsif  ($objectclass eq "all"){
        # find all 
        $base=$root_dse;
        $filter="(cn=".$name.")"; 
    } else {
        $base=$root_dse;
        $filter="(&(objectclass=".$objectclass.") (cn=".$name."))"; 
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
    my ($ldap,$root_dse,$root_dns,$json,$dump_AD,$show_session)=@_;
    my %sessions=();
    my $session_count=0;
    my ($ref_AD) = &AD_get_AD({ldap=>$ldap,
                               root_dse=>$root_dse,
                               root_dns=>$root_dns,
                               computers=>"FALSE",
                               rooms=>"FALSE",
                               management=>"TRUE",
                               users=>"FALSE",
                               dnszones=>"FALSE",
                               dnsnodes=>"FALSE",
                  });
    if ($dump_AD==1){
        &Sophomorix::SophomorixBase::json_dump({json => $json,
                                                jsoninfo => "SEARCH",
                                                jsoncomment => "AD Content",
                                                hash_ref=>$ref_AD,
                                               });
    }

    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(&(objectClass=user)(sophomorixRole=*))',
                  #filter => '(&(objectClass=user) (sophomorixRole=student))',
                   attrs => ['sAMAccountName',
                             'sophomorixSessions',
                             'sophomorixRole',
                             'givenName',
                             'sn',
                            ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max_user = $mesg->count; 
    if($Conf::log_level>=2){
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix users found to test for sessions");
    }
    $AD{'result'}{'supervisor'}{'student'}{'COUNT'}=$max_user;

    # walk through all users
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');
        my $supervisor_role=$entry->get_value('sophomorixRole');
        my $firstname = $entry->get_value('givenName');
        my $lastname = $entry->get_value('sn');
        my @session_list = sort $entry->get_value('sophomorixSessions');
        if($Conf::log_level>=2){
            my $user_session_count=$#session_list+1;
            print "   * User $sam has $user_session_count sessions\n";
	}
        
        # walk through all sessions of the user
        foreach my $session (@session_list){
            $session_count++;
            if($Conf::log_level>=2){
                &Sophomorix::SophomorixBase::print_title("$session_count: User $sam has session $session");
            }
            my ($id,$comment,$participants,$string)=split(/;/,$session);

            if ($show_session eq "all" or $id eq $show_session){
                # just go on
                if($Conf::log_level>=2){
                    print "   * Loading partial data of session $id.\n";
                }            

                # save supervisor information
                #--------------------------------------------------
                # save by user
                $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'string'}=$session;
                $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'comment'}=$comment;
                $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'participantstring'}=$participants;
                $sessions{'supervisor'}{$sam}{'sophomorixRole'}=$supervisor_role;
                $sessions{'supervisor'}{$sam}{'firstname'}=$firstname;
                $sessions{'supervisor'}{$sam}{'lastname'}=$lastname;
                # save by id
                $sessions{'id'}{$id}{'supervisor'}{'name'}=$sam;
                $sessions{'id'}{$id}{'supervisor'}{'sophomorixRole'}=$supervisor_role;
                $sessions{'id'}{$id}{'supervisor'}{'firstname'}=$firstname;
                $sessions{'id'}{$id}{'supervisor'}{'lastname'}=$lastname;
                $sessions{'id'}{$id}{'sophomorixSessions'}=$session;
                $sessions{'id'}{$id}{'comment'}=$comment;
                $sessions{'id'}{$id}{'participantstring'}=$participants;


                # save participant information
                #--------------------------------------------------
                my @participants=split(/,/,$participants);
                if ($#participants==-1){
                    # skip user detection when participantlist is empty
                    next;
                }
                foreach $participant (@participants){
                    # get userinfo
                    my ($firstname,$lastname,$adminclass,$existing,$exammode,$role)=
                        &AD_get_user({ldap=>$ldap,
                                      root_dse=>$root_dse,
                                      root_dns=>$root_dns,
                                      user=>$participant,
                           });

                    $sessions{'id'}{$id}{'participants'}{$participant}{'user_firstname'}=$firstname;
                    $sessions{'id'}{$id}{'participants'}{$participant}{'user_lastname'}=$lastname;
                    $sessions{'id'}{$id}{'participants'}{$participant}{'user_adminclass'}=$adminclass;
                    $sessions{'id'}{$id}{'participants'}{$participant}{'user_existing'}=$existing;
                    $sessions{'id'}{$id}{'participants'}{$participant}{'sophomorixRole'}=$role;
                    $sessions{'id'}{$id}{'participants'}{$participant}{'user_exammode'}=$exammode;

                    $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'participants'}
                             {$participant}{'user_firstname'}=$firstname;
                    $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'participants'}
                             {$participant}{'user_lastname'}=$lastname;
                    $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'participants'}
                             {$participant}{'user_adminclass'}=$adminclass;
                    $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'participants'}
                             {$participant}{'user_existing'}=$existing;
                    $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'participants'}
                             {$participant}{'user_exammode'}=$exammode;
                    $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}{'participants'}
                             {$participant}{'sophomorixRole'}=$role;

                    # test participantship in managementgroups
                    my @grouptypes=("wifiaccess","internetaccess","admins","webfilter","intranetaccess","printing");
                    foreach my $grouptype (@grouptypes){
                        # befor testing set FALSE as default
                        $sessions{'id'}{$id}{'participants'}{$participant}{"group_".$grouptype}="FALSE";
                        $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}
                                 {'participants'}{$participant}{"group_".$grouptype}="FALSE";
                        foreach my $group (keys %{$ref_AD->{'objectclass'}{'group'}{$grouptype}}) {
                            if (exists $ref_AD->{'objectclass'}{'group'}{$grouptype}{$group}{'participants'}{$participant}){
                                # if in the groups, set TRUE
                                $sessions{'id'}{$id}{'participants'}{$participant}{"group_".$grouptype}="TRUE";
                                $sessions{'supervisor'}{$sam}{'sophomorixSessions'}{$id}
                                         {'participants'}{$participant}{"group_".$grouptype}="TRUE";
                            }
                        }
                    }
                    # do more with the session participants
                }

                # save extended information
                #--------------------------------------------------
                if ($id eq $show_session){
                    if($Conf::log_level>=2){
                        print "   * Loading extended data of selected session $id.\n";
                    }  
                    # List contents of share and collect directory 
                    # of the supervisor
                    my $supervisor=$sessions{'id'}{$show_session}{'supervisor'}{'name'};
                    &Sophomorix::SophomorixBase::dir_listing_session_supervisor("/etc/linuxmuster/sophomorix",
                                                                                "collect_dir","supervisor",
                                                                                $supervisor,
                                                                                $show_session,
                                                                                \%sessions);
                    &Sophomorix::SophomorixBase::dir_listing_session_supervisor("/etc/linuxmuster/sophomorix/bsz",
                                                                                "share_dir",
                                                                                "supervisor",
                                                                                $supervisor,
                                                                                $show_session,
                                                                                \%sessions);
                    # List quota 
                    # of all participants
                    foreach my $participant (keys %{$sessions{'id'}{$show_session}{'participants'}}) {
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
    $sessions{'sessioncount'}=$session_count;

    &Sophomorix::SophomorixBase::print_title("$session_count running sessions found");
    return %sessions; 
}



sub AD_get_AD {
    my %AD=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};

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
        # sophomorixType adminclass from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=adminclass))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_adminclass = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_adminclass sophomorix adminclasses found in AD");
        $AD{'result'}{'group'}{'adminclass'}{'COUNT'}=$max_adminclass;
        for( my $index = 0 ; $index < $max_adminclass ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            $AD{'objectclass'}{'group'}{'adminclass'}{$sam}{'room'}=$sam;
            $AD{'objectclass'}{'group'}{'adminclass'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'adminclass'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'adminclass'}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # lists
            push @{ $AD{'lists'}{'by_school'}{'global'}{'groups_by_type'}{$type} }, $sam; 
            push @{ $AD{'lists'}{'by_school'}{$schoolname}{'groups_by_type'}{$type} }, $sam; 
#            push @{ $AD{'lists'}{'by_school'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'lookup'}{'type_by_adminclass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'lists'}{'adminclass'} }; # make list computer empty to allow sort  
#        @{ $AD{'lists'}{'adminclass'} } = sort @{ $AD{'lists'}{'adminclass'} }; 
    }


    ##################################################
    if ($teacherclasses eq "TRUE"){
        # sophomorixType teacherclass from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=teacherclass))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_teacherclass = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_teacherclass sophomorix teacherclasses found in AD");
        $AD{'result'}{'group'}{'teacherclass'}{'COUNT'}=$max_teacherclass;
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
            push @{ $AD{'lists'}{'by_school'}{'global'}{'groups_by_type'}{$type} }, $sam; 
            push @{ $AD{'lists'}{'by_school'}{$schoolname}{'groups_by_type'}{$type} }, $sam; 
#            push @{ $AD{'lists'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'lookup'}{'type_by_adminclass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'lists'}{'teacherclass'} }; # make list computer empty to allow sort  
#        @{ $AD{'lists'}{'teacherclass'} } = sort @{ $AD{'lists'}{'teacherclass'} }; 
    }

    ##################################################
    if ($administratorclasses eq "TRUE"){
        # sophomorixType teacherclass from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=admins))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_teacherclass = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_teacherclass sophomorix admins found in AD");
        $AD{'result'}{'group'}{'teacherclass'}{'COUNT'}=$max_teacherclass;
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
            push @{ $AD{'lists'}{'by_school'}{'global'}{'groups_by_type'}{$type} }, $sam; 
            push @{ $AD{'lists'}{'by_school'}{$schoolname}{'groups_by_type'}{$type} }, $sam; 
#            push @{ $AD{'lists'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'lookup'}{'type_by_adminclass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'lists'}{'teacherclass'} }; # make list computer empty to allow sort  
#        @{ $AD{'lists'}{'teacherclass'} } = sort @{ $AD{'lists'}{'teacherclass'} }; 
    }

    ##################################################
    if ($projects eq "TRUE"){
        # sophomorixType projects from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=project))',
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixStatus',
                                 'sophomorixType',
                                ]);
        my $max_project = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_project sophomorix projects found in AD");
        $AD{'result'}{'group'}{'project'}{'COUNT'}=$max_project;
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
            push @{ $AD{'lists'}{'by_school'}{'global'}{'groups_by_type'}{$type} }, $sam; 
            push @{ $AD{'lists'}{'by_school'}{$schoolname}{'groups_by_type'}{$type} }, $sam; 
#            push @{ $AD{'lists'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'lookup'}{'type_by_adminclass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'lists'}{'teacherclass'} }; # make list computer empty to allow sort  
#        @{ $AD{'lists'}{'teacherclass'} } = sort @{ $AD{'lists'}{'teacherclass'} }; 
    }


    ##################################################
    if ($users eq "TRUE"){
        # sophomorix students,teachers from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=user)(|(sophomorixRole=student)(sophomorixRole=teacher)(sophomorixRole=administrator)))',
                       #filter => '(&(objectClass=user) (sophomorixRole=student))',
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
                                 'sophomorixUnid',
                                 'sophomorixRole',
                                 'userAccountControl',
                                ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix students found in AD");
        $AD{'result'}{'user'}{'student'}{'COUNT'}=$max_user;
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $role=$entry->get_value('sophomorixRole');
            $AD{'objectclass'}{'user'}{$role}{$sam}{'sophomorixAdminClass'}=
                $entry->get_value('sophomorixAdminClass');
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
            $AD{'sam'}{$sam}{'sophomorixAdminClass'}=
                $entry->get_value('sophomorixAdminClass');
            $AD{'sam'}{$sam}{'sophomorixFirstnameASCII'}=
                $entry->get_value('sophomorixFirstnameASCII');
            $AD{'sam'}{$sam}{'sophomorixSurnameASCII'}=
                $entry->get_value('sophomorixSurnameASCII');
            $AD{'sam'}{$sam}{'givenName'}=
                $entry->get_value('givenName');
            $AD{'sam'}{$sam}{'sn'}=
                $entry->get_value('sn');
            $AD{'sam'}{$sam}{'sophomorixBirthdate'}=
                $entry->get_value('sophomorixBirthdate');
            $AD{'sam'}{$sam}{'sophomorixStatus'}=
                $entry->get_value('sophomorixStatus');
            $AD{'sam'}{$sam}{'sophomorixSchoolname'}=
                $entry->get_value('sophomorixSchoolname');
            $AD{'sam'}{$sam}{'sophomorixPrefix'}=
                $entry->get_value('sophomorixPrefix');
            $AD{'sam'}{$sam}{'sophomorixAdminFile'}=
                $entry->get_value('sophomorixAdminFile');
            $AD{'sam'}{$sam}{'sophomorixUnid'}=
                $entry->get_value('sophomorixUnid');
            $AD{'sam'}{$sam}{'sophomorixRole'}=
                $entry->get_value('sophomorixRole');
            $AD{'sam'}{$sam}{'userAccountControl'}=
                $entry->get_value('userAccountControl');
            $AD{'sam'}{$sam}{'IDENTIFIER_ASCII'}=$identifier_ascii;
            $AD{'sam'}{$sam}{'IDENTIFIER_UTF8'}=$identifier_utf8;

            # lookup
            if ($entry->get_value('sophomorixUnid') ne "---"){
                # no lookup for unid '---'
                $AD{'lookup'}{'user_by_unid'}{$entry->get_value('sophomorixUnid')}=$sam;
                $AD{'lookup'}{'identifier_utf8_by_unid'}{$entry->get_value('sophomorixUnid')}=
                    $identifier_utf8;
                $AD{'lookup'}{'identifier_ascii_by_unid'}{$entry->get_value('sophomorixUnid')}=
                    $identifier_ascii;
            }
            $AD{'lookup'}{'user_by_identifier_ascii'}{$identifier_ascii}=$sam;
            $AD{'lookup'}{'user_by_identifier_utf8'}{$identifier_utf8}=$sam;
            $AD{'lookup'}{'status_by_identifier_ascii'}{$identifier_ascii}=$entry->get_value('sophomorixStatus');
            $AD{'lookup'}{'status_by_identifier_utf8'}{$identifier_utf8}=$entry->get_value('sophomorixStatus');
            $AD{'lookup'}{'role_by_user'}{$sam}=$entry->get_value('sophomorixRole');

            # lists
            push @{ $AD{'lists'}{'by_school'}{'global'}{'users_by_role'}{$entry->get_value('sophomorixRole')} }, $sam; 
            push @{ $AD{'lists'}{'by_school'}{$entry->get_value('sophomorixSchoolname')}{'users_by_role'}{$entry->get_value('sophomorixRole')} }, $sam;

            my $type=$AD{'lookup'}{'type_by_adminclass'}{$entry->get_value('sophomorixAdminClass')};
            push @{ $AD{'lists'}{'by_school'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_by_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  
            push @{ $AD{'lists'}{'by_school'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_by_type'}{$type} }, $sam;  

        }
        # sorting some lists
#        my $unneeded1=$#{ $AD{'lists'}{'student'} }; # make list computer nonempty        
#        @{ $AD{'lists'}{'student'} } = sort @{ $AD{'lists'}{'student'} }; 
#        my $unneeded2=$#{ $AD{'lists'}{'teacher'} }; # make list computer nonempty        
#        @{ $AD{'lists'}{'teacher'} } = sort @{ $AD{'lists'}{'teacher'} }; 
    }


    ##################################################
    if ($rooms eq "TRUE"){
        # sophomorixType room from ldap
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => '(&(objectClass=group)(sophomorixType=room))',
                       attrs => ['sAMAccountName',
                                 'sophomorixStatus',
                                 'sophomorixSchoolname',
                                 'sophomorixType',
                                ]);
        my $max_room = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_room sophomorix Rooms found in AD");
        $AD{'result'}{'group'}{'room'}{'COUNT'}=$max_room;
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
            push @{ $AD{'lists'}{'by_school'}{'global'}{'groups_by_type'}{$type} }, $sam; 
            push @{ $AD{'lists'}{'by_school'}{$schoolname}{'groups_by_type'}{$type} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }
            $AD{'lookup'}{'type_by_adminclass'}{$sam}=$type;
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'lists'}{'room'} }; # make list computer empty to allow sort  
#        @{ $AD{'lists'}{'room'} } = sort @{ $AD{'lists'}{'room'} }; 
    }


    ##################################################
    if ($computers eq "TRUE"){
        # sophomorix computers from ldap
        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => '(&(objectClass=computer)(sophomorixRole=computer))',
                          attrs => ['sAMAccountName',
                                    'sophomorixSchoolPrefix',
                                    'sophomorixSchoolname',
                                    'sophomorixAdminFile',
                                    'sophomorixAdminClass',
                                    'sophomorixRole',
                                  ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user Computers found in AD");
        $AD{'result'}{'computer'}{'computer'}{'COUNT'}=$max_user;
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
            # lists
            push @{ $AD{'lists'}{'by_school'}{'global'}{'users_by_role'}{$entry->get_value('sophomorixRole')} }, $sam; 
            push @{ $AD{'lists'}{'by_school'}{$sn}{'users_by_role'}{$entry->get_value('sophomorixRole')} }, $sam; 
            if($Conf::log_level>=2){
                print "   * $sam\n";
            }

            my $type=$AD{'lookup'}{'type_by_adminclass'}{$entry->get_value('sophomorixAdminClass')};
            push @{ $AD{'lists'}{'by_school'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_by_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  
            push @{ $AD{'lists'}{'by_school'}{$entry->get_value('sophomorixSchoolname')}{'users_by_type'}{$type} }, $sam;  

        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'lists'}{'computer'} }; # make list computer empty to allow sort  
        # print "COUNT: $#{ $AD{'lists'}{'computer'} }\n";  # -1  
#        @{ $AD{'lists'}{'computer'} } = sort @{ $AD{'lists'}{'computer'} }; 
        # print "COUNT: $#{ $AD{'lists'}{'computer'} }\n";  # -1   
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
        $AD{'result'}{'group'}{'internetaccess'}{'COUNT'}=$max_internetaccess;
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
                push @{ $AD{'lists'}{'by_school'}{'global'}{'internetaccess'} }, $member;
                push @{ $AD{'lists'}{'by_school'}{$schoolname}{'internetaccess'} }, $member;
            }
        }
        # sorting some lists
#        my $unneeded1=$#{ $AD{'lists'}{'internetaccess'} }; 
#        @{ $AD{'lists'}{'internetaccess'} } = sort @{ $AD{'lists'}{'internetaccess'} }; 
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
        $AD{'result'}{'group'}{'wifiaccess'}{'COUNT'}=$max_wifiaccess;
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
                push @{ $AD{'lists'}{'by_school'}{'global'}{'wifiaccess'} }, $member;
                push @{ $AD{'lists'}{'by_school'}{$schoolname}{'wifiaccess'} }, $member;
            }
        }
        # sorting some lists
#        my $unneeded2=$#{ $AD{'lists'}{'wifiaccess'} }; 
#        @{ $AD{'lists'}{'wifiaccess'} } = sort @{ $AD{'lists'}{'wifiaccess'} }; 

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
        $AD{'result'}{'group'}{'admins'}{'COUNT'}=$max_admins;
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
                push @{ $AD{'lists'}{'by_school'}{'global'}{'admins'} }, $member;
                push @{ $AD{'lists'}{'by_school'}{$schoolname}{'admins'} }, $member;
            }
        }
        # sorting some lists
#        my $unneeded3=$#{ $AD{'lists'}{'admins'} }; 
#        @{ $AD{'lists'}{'admins'} } = sort @{ $AD{'lists'}{'admins'} }; 




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
        $AD{'result'}{'group'}{'webfilter'}{'COUNT'}=$max_webfilter;
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
                push @{ $AD{'lists'}{'by_school'}{'global'}{'webfilter'} }, $member;
                push @{ $AD{'lists'}{'by_school'}{$schoolname}{'webfilter'} }, $member;
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
        $AD{'result'}{'group'}{'intranetaccess'}{'COUNT'}=$max_intranetaccess;
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
                push @{ $AD{'lists'}{'by_school'}{'global'}{'intranetaccess'} }, $member;
                push @{ $AD{'lists'}{'by_school'}{$schoolname}{'intranetaccess'} }, $member;
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
        $AD{'result'}{'group'}{'printing'}{'COUNT'}=$max_printing;
        for( my $index = 0 ; $index < $max_printing ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$AD{'objectclass'}{'group'}{'printing'}{$sam}{'printing'}=$sam;
            $AD{'objectclass'}{'group'}{'printing'}{$sam}{'sophomorixStatus'}=$stat;
            $AD{'objectclass'}{'group'}{'printing'}{$sam}{'sophomorixType'}=$type;
            $AD{'objectclass'}{'group'}{'printing'}{$sam}{'sophomorixSchoolname'}=$schoolname;
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
                push @{ $AD{'lists'}{'by_school'}{'global'}{'printing'} }, $member;
                push @{ $AD{'lists'}{'by_school'}{$schoolname}{'printing'} }, $member;
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
    #     $AD{'result'}{'user'}{'examaccount'}{'COUNT'}=$max_user;
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
                push @{ $AD{'lists'}{'by_school'}{'global'}{'sophomorixdnsZone'} }, $zone;
            } else {
                # other dnsZone
		$sopho_max_zone=$sopho_max_zone-1;
                $other_max_zone=$other_max_zone+1;
                $AD{'objectclass'}{'dnsZone'}{'otherdnsZone'}{$zone}{'name'}=$name;
                $AD{'objectclass'}{'dnsZone'}{'otherdnsZone'}{$zone}{'adminDescription'}=$desc;
                push @{ $AD{'lists'}{'by_school'}{'global'}{'otherdnsZone'} }, $zone;
            }
        }
        $AD{'result'}{'dnsZone'}{$DevelConf::dns_zone_prefix_string}{'COUNT'}=$sopho_max_zone;
        $AD{'result'}{'dnsZone'}{'otherdnsZone'}{'COUNT'}=$other_max_zone;
        # sorting some lists
#        my $unneeded1=$#{ $AD{'lists'}{'sophomorixdnsZone'} }; 
#        @{ $AD{'lists'}{'sophomorixdnsZone'} } = sort @{ $AD{'lists'}{'sophomorixdnsZone'} }; 
#        my $unneeded2=$#{ $AD{'lists'}{'otherdnsZone'} }; 
#        @{ $AD{'lists'}{'otherdnsZone'} } = sort @{ $AD{'lists'}{'otherdnsZone'} }; 
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
                my $record=$entry->get_value('dnsRecord');
                my $desc=$entry->get_value('adminDescription');
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'dnsNode'}=$dc;
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'dnsZone'}=$dns_zone;
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'IPv4'}=$ip;
                $AD{'objectclass'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'adminDescription'}=$desc;
                push @{ $AD{'lists'}{'by_school'}{'global'}{'dnsNode'} }, $dc;
                if($Conf::log_level>=2){
                    print "   * $dc\n";
                }
            }
            if (defined $dc){ 
                $AD{'result'}{'dnsNode'}{$DevelConf::dns_node_prefix_string}{$dc}{'COUNT'}=$max_node;
	    }
        }
        # sorting some lists
#        my $unneeded=$#{ $AD{'lists'}{'dnsNode'} }; 
#        @{ $AD{'lists'}{'dnsNode'} } = sort @{ $AD{'lists'}{'dnsNode'} }; 
    }

    return(\%AD);
}



sub AD_class_fetch {
    my ($ldap,$root_dse,$class,$school,$info) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. class7a
    my $adminclass="";  # the option i.e. 'class7*'
    if (defined $school){
        $adminclass=&AD_get_name_tokened($class,$school,"adminclass");
    } else {
        $adminclass=&AD_get_name_tokened($class,"---","adminclass");
    }

   my $filter="(&(objectClass=group)(sophomorixType=adminclass)(cn=".$adminclass."))";

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

        if($Conf::log_level>=2 or $info==1){
            # adminclass attributes
	    my $description = $entry->get_value('description');
	    my $gidnumber = $entry->get_value('gidNumber');
	    my $quota = $entry->get_value('sophomorixQuota');
            my $mailquota = $entry->get_value('sophomorixMailQuota');
            my $mailalias = $entry->get_value('sophomorixMailAlias');
            my $maillist = $entry->get_value('sophomorixMailList');
            my $status = $entry->get_value('sophomorixStatus');
            my $joinable = $entry->get_value('sophomorixJoinable');
            my $hidden = $entry->get_value('sophomorixHidden');
            my $maxmembers = $entry->get_value('sophomorixMaxMembers');
            my $creationdate = $entry->get_value('sophomorixCreationDate');
            my @admin_by_attr = sort $entry->get_value('sophomorixAdmins');
            my $admin_by_attr = $#admin_by_attr+1;
            my @member_by_attr = sort $entry->get_value('sophomorixMembers');
            my $member_by_attr = $#member_by_attr+1;
            my @admingroups_by_attr = sort $entry->get_value('sophomorixAdminGroups');
            my $admingroups_by_attr = $#admingroups_by_attr+1;
            my @membergroups_by_attr = sort $entry->get_value('sophomorixMemberGroups');
            my $membergroups_by_attr = $#membergroups_by_attr+1;

            # memberships (actual state)
            my @members= $entry->get_value('member');
            my %members=();
            foreach my $entry (@members){
                $members{$entry}="seen";
            }

            # sophomorix-memberships (target state of memberships)
            my @s_members= (@member_by_attr, @admin_by_attr);
            my @s_groups= (@membergroups_by_attr,@admingroups_by_attr);
            # all memberships
            my %s_allmem=();
            # remember all users and groups (warn when double)
            my %seen=();
            # save warnings for later printout
            my @membership_warn=();

            # mapping of display names
            #           key    ---> value
            # example1: maier1 ---> +maier1   (+: exists and is member)
            # example2: maier2 ---> -maier2   (-: exists and is NOT member)
            # example3: maier3 ---> ?maier3   (?: maier does not exist)
            # empty element stays empty
            my %name_prefixname_map=(""=>""); 
           
            # go through all user memberships (target state)
            foreach my $item (@s_members){
                if (exists $seen{$item}){
                    push @membership_warn, 
                         "WARNING: $item seen twice! Remove one of them!\n";
                } else {
                    # save item
                    $seen{$item}="seen";
                }
                my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$item);
                if ($count==1){
                    # user of target state exists: save its dn
                    $s_allmem{$dn_exist}=$item;
                    if (exists $members{$dn_exist}){
                        # existing user is member (+)
                        $name_prefixname_map{$item}="+$item";
                    } else {
                        # existing user is not member (-)
                        $name_prefixname_map{$item}="-$item";
                    }
                } else {
                    # nonexisting user 
                    $name_prefixname_map{$item}="?$item";
                }
            }

            # go through all user memberships (target state)
            foreach my $item (@s_groups){
                if (exists $seen{$item}){
                    push @membership_warn, 
                         "WARNING: $item seen twice! Remove one of them!\n";
                } else {
                    # save item
                    $seen{$item}="seen";
                }
                my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$item);
                if ($count==1){
                    # group of target state exists: save its dn
                    $s_allmem{$dn_exist}=$item;
                    if (exists $members{$dn_exist}){
                        # existing group is member (+)
                        $name_prefixname_map{$item}="+$item";
                    } else {
                        # existing group is not member (-)
                        $name_prefixname_map{$item}="-$item";
                    }
                } else {
                    # nonexisting group 
                    $name_prefixname_map{$item}="?$item";
                }
            }

            # check for actual members that should not be members
            foreach my $mem (@members){
                if (not exists $s_allmem{$mem}){
                    push @membership_warn, 
                         "WARNING: $mem\n         IS member but SHOULD NOT BE member of $sam_account\n";
                }
            }

            # left column in printout
            my @project_attr=("gidnumber: $gidnumber",
                              "Description:",
                              " $description",
                              "Quota: ${quota} MB",
                              "MailQuota: ${mailquota} MB",
                              "MailAlias: $mailalias",
                              "MailList: $maillist",
                              "SophomorixStatus: $status",
                              "Joinable: $joinable",
                              "Hidden: $hidden",
                              "MaxMembers: $maxmembers",
                              "CreationDate:",
                              " $creationdate"
                             );

            # calculate max height of colums
            my $max=$#project_attr;
            if ($#admin_by_attr > $max){
	        $max=$#admin_by_attr;
            }
            if ($#member_by_attr > $max){
	        $max=$#member_by_attr;
            }
            if ($#membergroups_by_attr > $max){
	        $max=$#membergroups_by_attr;
            }
            if ($#admingroups_by_attr > $max){
	        $max=$#admingroups_by_attr;
            }

            &Sophomorix::SophomorixBase::print_title("($max_class) $dn");
            print "+-------------------------+--------------+--------------+",
                  "--------+--------+\n";
            printf "|%-25s|%-14s|%-14s|%-8s|%-8s|\n",
                   "AdminClass:"," "," "," "," ";
            printf "|%-25s|%-14s|%-14s|%-8s|%-8s|\n",
                   "  $sam_account"," Admins "," Members "," --- "," --- ";
            print "+-------------------------+--------------+--------------+",
                  "--------+--------+\n";

            # print the columns
            for (my $i=0;$i<=$max;$i++){
                if (not defined $project_attr[$i]){
	            $project_attr[$i]="";
                }
                if (not defined $admin_by_attr[$i]){
	            $admin_by_attr[$i]="";
                }
                if (not defined $member_by_attr[$i]){
	            $member_by_attr[$i]="";
                }
                if (not defined $membergroups_by_attr[$i]){
	            $membergroups_by_attr[$i]="";
                }
                if (not defined $admingroups_by_attr[$i]){
	            $admingroups_by_attr[$i]="";
                }
                printf "|%-25s| %-13s| %-13s|%-8s|%-8s|\n",
                       $project_attr[$i],
                       $name_prefixname_map{$admin_by_attr[$i]},
                       $name_prefixname_map{$member_by_attr[$i]},
                       $name_prefixname_map{$admingroups_by_attr[$i]},
		       $name_prefixname_map{$membergroups_by_attr[$i]};
            }

            print "+-------------------------+--------------+--------------+",
                  "--------+--------+\n";
            printf "|%24s |%13s |%13s |%7s |%7s |\n",
                   "",$admin_by_attr,$member_by_attr,$admingroups_by_attr,$membergroups_by_attr;
            print "+-------------------------+--------------+--------------+",
                  "--------+--------+\n";
            print "?: nonexisting user/group, -: existing but not member, +: existing and member\n";

            # print warnings            
            foreach my $warn (@membership_warn){
                print $warn;
	    }
        }
    }
    return ($dn,$max_class);
}



sub AD_project_fetch {
    my ($ldap,$root_dse,$pro,$school,$info) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. p_abt3
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

        if($Conf::log_level>=2 or $info==1){
            # project attributes
	    my $description = $entry->get_value('description');
	    my $gidnumber = $entry->get_value('gidNumber');
	    my $addquota = $entry->get_value('sophomorixAddQuota');
            my $addmailquota = $entry->get_value('sophomorixAddMailQuota');
            my $mailalias = $entry->get_value('sophomorixMailAlias');
            my $maillist = $entry->get_value('sophomorixMailList');
            my $status = $entry->get_value('sophomorixStatus');
            my $joinable = $entry->get_value('sophomorixJoinable');
            my $hidden = $entry->get_value('sophomorixHidden');
            my $maxmembers = $entry->get_value('sophomorixMaxMembers');
            my $creationdate = $entry->get_value('sophomorixCreationDate');
            my @admin_by_attr = sort $entry->get_value('sophomorixAdmins');
            my $admin_by_attr = $#admin_by_attr+1;
            my @member_by_attr = sort $entry->get_value('sophomorixMembers');
            my $member_by_attr = $#member_by_attr+1;
            my @admingroups_by_attr = sort $entry->get_value('sophomorixAdminGroups');
            my $admingroups_by_attr = $#admingroups_by_attr+1;
            my @membergroups_by_attr = sort $entry->get_value('sophomorixMemberGroups');
            my $membergroups_by_attr = $#membergroups_by_attr+1;

            # memberships (actual state)
            my @members= $entry->get_value('member');
            my %members=();
            foreach my $entry (@members){
                $members{$entry}="seen";
            }

            # sophomorix-memberships (target state of memberships)
            my @s_members= (@member_by_attr, @admin_by_attr);
            my @s_groups= (@membergroups_by_attr,@admingroups_by_attr);
            # all memberships
            my %s_allmem=();
            # remember all users and groups (warn when double)
            my %seen=();
            # save warnings for later printout
            my @membership_warn=();

            # mapping of display names
            #           key    ---> value
            # example1: maier1 ---> +maier1   (+: exists and is member)
            # example2: maier2 ---> -maier2   (-: exists and is NOT member)
            # example3: maier3 ---> ?maier3   (?: maier does not exist)
            # empty element stays empty
            my %name_prefixname_map=(""=>""); 
           
            # go through all user memberships (target state)
            foreach my $item (@s_members){
                if (exists $seen{$item}){
                    push @membership_warn, 
                         "WARNING: $item seen twice! Remove one of them!\n";
                } else {
                    # save item
                    $seen{$item}="seen";
                }
                my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$item);
                if ($count==1){
                    # user of target state exists: save its dn
                    $s_allmem{$dn_exist}=$item;
                    if (exists $members{$dn_exist}){
                        # existing user is member (+)
                        $name_prefixname_map{$item}="+$item";
                    } else {
                        # existing user is not member (-)
                        $name_prefixname_map{$item}="-$item";
                    }
                } else {
                    # nonexisting user 
                    $name_prefixname_map{$item}="?$item";
                }
            }

            # go through all user memberships (target state)
            foreach my $item (@s_groups){
                if (exists $seen{$item}){
                    push @membership_warn, 
                         "WARNING: $item seen twice! Remove one of them!\n";
                } else {
                    # save item
                    $seen{$item}="seen";
                }
                my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$item);
                if ($count==1){
                    # group of target state exists: save its dn
                    $s_allmem{$dn_exist}=$item;
                    if (exists $members{$dn_exist}){
                        # existing group is member (+)
                        $name_prefixname_map{$item}="+$item";
                    } else {
                        # existing group is not member (-)
                        $name_prefixname_map{$item}="-$item";
                    }
                } else {
                    # nonexisting group 
                    $name_prefixname_map{$item}="?$item";
                }
            }

            # check for actual members that should not be members
            foreach my $mem (@members){
                if (not exists $s_allmem{$mem}){
                    push @membership_warn, 
                         "WARNING: $mem\n         IS member but SHOULD NOT BE member of $sam_account\n";
                }
            }

            # left column in printout
            my @project_attr=("gidnumber: $gidnumber",
                              "Description:",
                              " $description",
                              "AddQuota: ${addquota} MB",
                              "AddMailQuota: ${addmailquota} MB",
                              "MailAlias: $mailalias",
                              "MailList: $maillist",
                              "SophomorixStatus: $status",
                              "Joinable: $joinable",
                              "Hidden: $hidden",
                              "MaxMembers: $maxmembers",
                              "CreationDate:",
                              " $creationdate"
                             );

            # calculate max height of colums
            my $max=$#project_attr;
            if ($#admin_by_attr > $max){
	        $max=$#admin_by_attr;
            }
            if ($#member_by_attr > $max){
	        $max=$#member_by_attr;
            }
            if ($#membergroups_by_attr > $max){
	        $max=$#membergroups_by_attr;
            }
            if ($#admingroups_by_attr > $max){
	        $max=$#admingroups_by_attr;
            }

            &Sophomorix::SophomorixBase::print_title("($max_pro) $dn");
            print "+---------------------+-----------+-----------+",
                  "---------------+---------------+\n";
            printf "|%-21s|%-11s|%-11s|%-15s|%-15s|\n",
                   "Project:"," "," "," "," ";
            printf "|%-21s|%-11s|%-11s|%-15s|%-15s|\n",
                   "  $sam_account"," Admins "," Members "," AdminGroups "," MemberGroups ";
            print "+---------------------+-----------+-----------+",
                  "---------------+---------------+\n";

            # print the columns
            for (my $i=0;$i<=$max;$i++){
                if (not defined $project_attr[$i]){
	            $project_attr[$i]="";
                }
                if (not defined $admin_by_attr[$i]){
	            $admin_by_attr[$i]="";
                }
                if (not defined $member_by_attr[$i]){
	            $member_by_attr[$i]="";
                }
                if (not defined $membergroups_by_attr[$i]){
	            $membergroups_by_attr[$i]="";
                }
                if (not defined $admingroups_by_attr[$i]){
	            $admingroups_by_attr[$i]="";
                }
                printf "|%-21s|%-11s|%-11s|%-15s|%-15s|\n",
                       $project_attr[$i],
                       $name_prefixname_map{$admin_by_attr[$i]},
                       $name_prefixname_map{$member_by_attr[$i]},
                       $name_prefixname_map{$admingroups_by_attr[$i]},
		       $name_prefixname_map{$membergroups_by_attr[$i]};
            }

            print "+---------------------+-----------+-----------+",
                  "---------------+---------------+\n";
            printf "|%20s |%10s |%10s |%14s |%14s |\n",
                   "",$admin_by_attr,$member_by_attr,$admingroups_by_attr,$membergroups_by_attr;
            print "+---------------------+-----------+-----------+",
                  "---------------+---------------+\n";
            print "?: nonexisting user/group, -: existing but not member, +: existing and member\n";

            # print warnings            
            foreach my $warn (@membership_warn){
                print $warn;
	    }
        }
    }
    return ($dn,$max_pro);
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
    my $maxmembers = $arg_ref->{maxmembers};
    my $members = $arg_ref->{members};
    my $admins = $arg_ref->{admins};
    my $membergroups = $arg_ref->{membergroups};
    my $admingroups = $arg_ref->{admingroups};
    my $creationdate = $arg_ref->{creationdate};
    my $gidnumber = $arg_ref->{gidnumber};

    my $sync_members=0;

    &Sophomorix::SophomorixBase::print_title("Updating $dn");
    # description   
    if (defined $description){
        print "   * Setting Description to '$description'\n";
        my $mesg = $ldap->modify($dn,replace => {Description => $description}); 
    }
    # quota   
    if (defined $quota){
        print "   * Setting sophomorixQuota to $quota\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixQuota => $quota}); 
    }
    # mailquota   
    if (defined $mailquota){
        print "   * Setting sophomorixMailquota to $mailquota\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMailquota => $mailquota}); 
    }
    # addquota   
    if (defined $addquota){
        print "   * Setting sophomorixAddquota to $addquota\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixAddquota => $addquota}); 
    }
    # addmailquota   
    if (defined $addmailquota){
        print "   * Setting sophomorixAddmailquota to $addmailquota\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixAddmailquota => $addmailquota}); 
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

    # sync memberships if necessary
    if ($sync_members>0){
        &AD_project_sync_members($ldap,$root_dse,$dn);
    }
}



sub AD_project_sync_members {
    my ($ldap,$root_dse,$dn) = @_;
    print "   * Sync member: $dn\n";
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
                                          });   
                } elsif ($actual{$key} eq "group"){
                    &AD_group_removemember({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $cn,
                                            removegroup => $key,
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
}



sub AD_admin_list {
    my ($ldap,$root_dse)=@_;
    # sophomorix students,teachers from ldap
    my $mesg = $ldap->search( # perform a search
                      base   => $root_dse,
                      scope => 'sub',
                      filter => '(&(objectClass=user) (sophomorixRole=administrator))',
                      attrs => ['sAMAccountName',
                                'sophomorixAdminClass',
                                'givenName',
                                'sn',
                                'sophomorixStatus',
                                'sophomorixSchoolname',
                                'sophomorixSchoolPrefix',
                                'sophomorixRole',
                                'userAccountControl',
                               ]);
    my $max_user = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title("$max_user sophomorix administrators found in AD");
    print "+------------------------+----------------+\n";
    printf "| %-22s | %-14s |\n","administrator","School";
    print "+------------------------+----------------+\n";
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');
        my $school=$entry->get_value('sophomorixSchoolname');
        printf "| %-22s | %-14s |\n",$sam,$school;
    }
    print "+------------------------+----------------+\n";
}



sub AD_group_list {
    # show==0 return list of project dn's
    # show==1 print list, no return
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
    if ($show==1){ 
        &Sophomorix::SophomorixBase::print_title("$max_pro ${type}-groups");
        print "-------------------+----------+-----+----+-+-",
              "+-+-+-+--------------------------------\n";
	if ($type eq "project"){
        printf "%-19s|%9s |%4s |%3s |%1s|%1s|%1s|%1s|%1s| %-31s \n",
               "Project Name","AQ","AMQ","MM","H","A","L","S","J","Project Description";
        } elsif ($type eq "sophomorix-group"){
        printf "%-19s|%9s |%4s |%3s |%1s|%1s|%1s|%1s|%1s| %-31s \n",
               "Group Name","Quota","MQ","MM","H","A","L","S","J","Class Description";
        } elsif ($type eq "adminclass"){
        printf "%-19s|%9s |%4s |%3s |%1s|%1s|%1s|%1s|%1s| %-31s \n",
               "Class Name","Quota","MQ","MM","H","A","L","S","J","Class Description";
        }
        print "-------------------+----------+-----+----+-+-",
              "+-+-+-+--------------------------------\n";
        

        for( my $index = 0 ; $index < $max_pro ; $index++) {
            my $entry = $mesg->entry($index);
            $dn=$entry->dn();
            my $description;
            if (not defined $entry->get_value('description')){
                $description=""
            } else {
                $description=$entry->get_value('description')
	    }
            my $status;
            if (not defined $entry->get_value('sophomorixStatus')){
                $status=""
            } else {
                $status=$entry->get_value('sophomorixStatus')
	    }
            my $quota;
            if (not defined $entry->get_value('sophomorixQuota')){
                $quota=""
            } else {
                $quota=$entry->get_value('sophomorixQuota')
	    }
            my $mailquota;
            if (not defined $entry->get_value('sophomorixMailQuota')){
                $mailquota=""
            } else {
                $mailquota=$entry->get_value('sophomorixMailQuota')
	    }
            my $maxmembers;
            if (not defined $entry->get_value('sophomorixMaxMembers')){
                $maxmembers=""
            } else {
                $maxmembers=$entry->get_value('sophomorixMaxMembers')
	    }
            my $mailalias;
            if (not defined $entry->get_value('sophomorixMailAlias')){
                $mailalias=""
            } elsif ($entry->get_value('sophomorixMailAlias') eq "FALSE"){
                $mailalias=0;
            } else {
                $mailalias=1;
            }
            my $maillist;
            if (not defined $entry->get_value('sophomorixMailList')){
                $maillist="";
            } elsif ($entry->get_value('sophomorixMailList') eq "FALSE"){
                $maillist=0;
            } else {
                $maillist=1;
            }
            my $joinable;
            if (not defined $entry->get_value('sophomorixJoinable')){
                $joinable="";
            } elsif ($entry->get_value('sophomorixJoinable') eq "FALSE"){
                $joinable=0;
            } else {
                $joinable=1;
            }
            my $hidden;
            if (not defined $entry->get_value('sophomorixHidden')){
                $hidden="";
            } elsif ($entry->get_value('sophomorixHidden') eq "FALSE"){
                $hidden=0;
            } else {
                $hidden=1;
            }
            if ($type eq "project"){
                printf "%-19s|%9s |%4s |%3s |%1s|%1s|%1s|%1s|%1s| %-31s\n",
                    $entry->get_value('sAMAccountName'),
                    $entry->get_value('sophomorixAddQuota'),
                    $entry->get_value('sophomorixAddMailQuota'),
                    $maxmembers,
                    $hidden,
                    $mailalias,
                    $maillist,
                    $status,
                    $joinable,
	            $description;
            } elsif ($type eq "sophomorix-group"){
                printf "%-19s|%9s |%4s |%3s |%1s|%1s|%1s|%1s|%1s| %-31s\n",
                    $entry->get_value('sAMAccountName'),
                    $quota,
                    $mailquota,
                    $maxmembers,
                    $hidden,
                    $mailalias,
                    $maillist,
                    $status,
                    $joinable,
	            $description;
            } elsif ($type eq "adminclass"){
                printf "%-19s|%9s |%4s |%3s |%1s|%1s|%1s|%1s|%1s| %-31s\n",
                    $entry->get_value('sAMAccountName'),
                    $quota,
                    $mailquota,
                    $maxmembers,
                    $hidden,
                    $mailalias,
                    $maillist,
                    $status,
                    $joinable,
	            $description;
            }
        }
        print "-------------------+----------+-----+----+-+-",
              "+-+-+-+--------------------------------\n";
	if ($type eq "project"){
            print "AQ=addquota   AMQ=addmailquota   J=joinable   MM=maxmembers\n";
            print " A=mailalias    L=mailist,       S=status      H=hidden\n";
        } elsif ($type eq "sophomorix-group"){
            print "MQ=mailquota   J=joinable   MM=maxmembers      H=hidden\n";
            print " A=mailalias      L=mailist,    S=status\n";
        } elsif ($type eq "adminclass"){
            print "MQ=mailquota   J=joinable   MM=maxmembers      H=hidden\n";
            print " A=mailalias      L=mailist,    S=status\n";
        }
        &Sophomorix::SophomorixBase::print_title("$max_pro ${type}-groups");
    } elsif ($show==0){
        my @projects_dn=();
        for( my $index = 0 ; $index < $max_pro ; $index++) {
            my $entry = $mesg->entry($index);
            $dn=$entry->dn();
            push @projects_dn,$dn;   
        }
	@projects_dn = sort @projects_dn;
        return @projects_dn;
    }
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
    my $result = $ldap->add($target_branch,attr => ['objectclass' => ['top', 'organizationalUnit']]);
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
    my $group = $arg_ref->{group};
    my $group_basename = $arg_ref->{group_basename};
    my $description = $arg_ref->{description};
    my $school = $arg_ref->{school};
    my $type = $arg_ref->{type};
    my $creationdate = $arg_ref->{creationdate};
    my $status = $arg_ref->{status};
    my $joinable = $arg_ref->{joinable};
    my $gidnumber_wish = $arg_ref->{gidnumber_wish};
    my $dn_wish = $arg_ref->{dn_wish};
    my $cn = $arg_ref->{cn};
    my $file = $arg_ref->{file};

    if (not defined $joinable){
        $joinable="FALSE";    
    }

    if (not defined $cn){
        $cn=$group;    
    }
    if (not defined $file){
        $file="none";    
    }

    &Sophomorix::SophomorixBase::print_title("Creating group $group of type $type (begin):");

    $school=&AD_get_schoolname($school);

    # calculate missing Attributes
    my $container=&AD_get_container($type,$group_basename);

    my $target_branch=$container."OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;

    my $dn = "CN=".$group.",".$container."OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
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
        print "   Creationdate:    $creationdate\n";
        print "   Description:     $description\n";
        print "   File:            $file\n";
        print "   School:          $school\n";

        # make sure target ou exists
        my $target = $ldap->add($target_branch,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($target,2,(caller(0))[3]);
        # Create object
        my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $cn,
                                    description => $description,
                                    sAMAccountName => $group,
                                    sophomorixCreationDate => $creationdate, 
                                    sophomorixType => $type, 
                                    sophomorixSchoolname => $school, 
                                    sophomorixStatus => $status,
                                    sophomorixAddQuota => "---",
                                    sophomorixAddMailQuota => "---",
                                    sophomorixQuota => "---",
                                    sophomorixMailQuota => "-1",
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
    } else {
        print "   * Group $group exists already ($count results)\n";
    }
    if ($type eq "adminclass"){
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
        # add group <token>-students to global-students
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => "global-".$DevelConf::student,
                             addgroup => $token_students,
                           });
    } elsif ($type eq "teacherclass"){
            # add <token>-teachers to global-teachers
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => "global-".$DevelConf::teacher,
                                 addgroup => $group,
                               });

        #} else {
    } elsif ($type eq "room"){
        #my $token_examaccounts=&AD_get_name_tokened($DevelConf::examaccount,$school,"examaccount");
        ## add the room to <token>-examaccounts
        #&AD_group_addmember({ldap => $ldap,
        #                     root_dse => $root_dse, 
        #                     group => $token_examaccounts,
        #                     addgroup => $group,
        #                   });
        ## add group <token>-examaccounts to global-examaccounts
        #&AD_group_addmember({ldap => $ldap,
        #                     root_dse => $root_dse, 
        #                     group => "global-".$DevelConf::examaccount,
        #                     addgroup => $token_examaccounts,
        #                   });
    }
    &Sophomorix::SophomorixBase::print_title("Creating group $group of type $type (end)");
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
         print "   * Removing group $removegroup from $group\n";
         my ($count_group,$dn_exist_removegroup,$cn_exist_removegroup)=&AD_object_search($ldap,$root_dse,"group",$removegroup);
         if ($count_group > 0){
             print "   * Group $removegroup exists ($count_group results)\n";
             my $mesg = $ldap->modify( $dn_exist_group,
     	    	                   delete => {
                                   member => $dn_exist_removegroup,
                                   }
                               );
             &AD_debug_logdump($mesg,2,(caller(0))[3]);
             return;
         }
    } else {
        return;
    }
}



sub  get_forbidden_logins{
    my ($ldap,$root_dse) = @_;
    my %forbidden_logins = %DevelConf::forbidden_logins;

    # users from ldap
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(objectClass=user)',
                   attr => ['sAMAccountName']
                         );
    my $max_user = $mesg->count; 
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        my @values = $entry->get_value( 'sAMAccountName' );
        foreach my $login (@values){
            $forbidden_logins{$login}="login $login exists in AD";
        }
    }

    # users in /etc/passwd
    if (-e "/etc/passwd"){
        open(PASS, "/etc/passwd");
        while(<PASS>) {
            my ($login)=split(/:/);
            $forbidden_logins{$login}="login $login exists in /etc/passwd";
        }
        close(PASS);
    }

    # future groups in students.csv
    #my $schueler_file=$DevelConf::path_conf_user."/schueler.txt";
    #if (-e "$schueler_file"){
    #    open(STUDENTS, "$schueler_file");
    #    while(<STUDENTS>) {
    #        my ($group)=split(/;/);
    #        chomp($group);
    #        if ($group ne ""){
    #            $forbidden_logins{$group}="future group $group in schueler.txt";
    # 	    }
    #     }
    #     close(STUDENTS);
    #}

    # groups from ldap
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(objectClass=group)',
                   attr => ['sAMAccountName']
                         );
    my $max_group = $mesg->count; 
    for( my $index = 0 ; $index < $max_group ; $index++) {
        my $entry = $mesg->entry($index);
        my @values = $entry->get_value( 'sAMAccountName' );
        foreach my $group (@values){
            $forbidden_logins{$group}="group $group exists in AD";
        }
    }

    # groups in /etc/group
    if (-e "/etc/group"){
        open(GROUP, "/etc/group");
        while(<GROUP>) {
            my ($group)=split(/:/);
            $forbidden_logins{$group}="group $group exists in /etc/group";
        }
        close(GROUP);
    }

    # output forbidden logins:
    if($Conf::log_level>=3){
        print("Login-Name:                    ",
              "                                   Status:\n");
        print("================================",
              "===========================================\n");
        while (($k,$v) = each %forbidden_logins){
            printf "%-50s %3s\n","$k","$v";
        }
    }
    return %forbidden_logins;
}



sub AD_debug_logdump {
    # dumping ldap message object in loglevels
    my ($message,$level,$text) = @_;
    my $string=$message->error;
    if ($string=~/.*: Success/ or $string eq "Success"){
        # ok
    } elsif ($string=~/Entry .* already exists/){
        # not so bad, just display it
        #print "         * OK: $string\n";
    } elsif ($string=~/Attribute member already exists for target/){
        # not so bad, just display it
        #print "         * OK: $string\n";
    } else {
        # bad error
        print "\nERROR in $text:\n";
        print "   $string\n\n";
        if($Conf::log_level>=$level){
            if ( $message->code) { # 0: no error
                print "   Debug info from server($text):\n";
                print Dumper(\$message);
            }
        }
    }
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
                      attr => ['sophomorixFirstPassword']
                            );
    my $entry = $mesg->entry(0);
    my $firstpassword = $entry->get_value('sophomorixFirstPassword');
    my $samaccount = $entry->get_value('sAMAccountName');
    if (not defined $firstpassword){
        return -1;
    }

    # smbclient test
    #my $command="smbclient -L localhost --user=$samaccount%'$firstpassword' > /dev/null 2>&1 ";
    #print "   # $command\n";
    #my $result=system($command);

    # pam login
    my $command="wbinfo --pam-logon=$samaccount%'$firstpassword' > /dev/null 2>&1 ";
    print "   # $command\n";
    my $result=system($command);

    # kerberos login
    #my $command="wbinfo --krb5auth=$samaccount%'$firstpassword'' > /dev/null 2>&1 ";
    #print "   # $command\n";
    #my $result=system($command);


    return $result;
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
        my $filter="(&(objectclass=user) (uidNumber=".$uidnumber_prop."))"; 
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
        my $filter="(&(objectclass=user) (gidnumber=".$gidnumber_prop."))"; 
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
    # create string for unicodePwd in AD from $plain_password 
    my ($plain_password) = @_;
    # build the conversion map from your local character set to Unicode 
    my $charmap = Unicode::Map8->new('latin1')  or  die;
    # surround the PW with double quotes and convert it to UTF-16
    my $uni_password = $charmap->tou('"'.$plain_password.'"')->byteswap()->utf16();
    return $uni_password;
}


# END OF FILE
# Return true=1
1;
