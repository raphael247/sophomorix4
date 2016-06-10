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
#use Sophomorix::SophomorixBase;
use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 

@ISA = qw(Exporter);

@EXPORT_OK = qw( );
@EXPORT = qw(
            AD_bind_admin
            AD_unbind_admin
            AD_dns_get
            AD_user_create
            AD_user_update
            AD_computer_create
            AD_user_move
            AD_user_kill
            AD_computer_kill
            AD_group_create
            AD_group_kill
            AD_group_addmember
            AD_group_removemember
            AD_get_ou_tokened
            AD_get_name_tokened
            get_forbidden_logins
            AD_ou_add
            AD_object_search
            AD_computer_fetch
            AD_class_fetch
            AD_project_fetch
            AD_group_update
            AD_dn_fetch_multivalue
            AD_project_sync_members
            AD_group_list
            AD_object_move
            AD_debug_logdump
            );

sub AD_get_passwd {
    my $smb_pwd="";
    if (-e $DevelConf::file_samba_pwd) {
        open (SECRET, $DevelConf::file_samba_pwd);
        while(<SECRET>){
            $smb_pwd=$_;
            chomp($smb_pwd);
        }
        close(SECRET);
    } else {
        print "Password of samba Administrator must ",
               "be in $DevelConf::file_samba_pwd\n";
        exit;
    }
    return($smb_pwd);
}


sub AD_bind_admin {
    my ($smb_pwd)=&AD_get_passwd();
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
    my $admin_dn="CN=Administrator,CN=Users,".$root_dse;
    my $mesg = $ldap->bind($admin_dn, password => $smb_pwd);
    # show errors from bind
    $mesg->code && die $mesg->error;

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
        if($Conf::log_level>=2){
            print "   * ERROR: Sophomorix-Schema nonexisting\n";
        }
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
    my $role = $arg_ref->{role};
    my $ws_count = $arg_ref->{ws_count};
    my $ou = $arg_ref->{ou};
    my $school_token = $arg_ref->{school_token};
    my $creationdate = $arg_ref->{creationdate};

    # calculation
    # make name uppercase
    #my $name_uppercase=$name;
    #$name_uppercase=~tr/a-z/A-Z/;

    # make school-token uppercase
    #my $school_token_uppercase=$school_token;
    #$school_token_uppercase=~tr/a-z/A-Z/;


    # names with tokens
#    my $room_token=&AD_get_name_tokened($room,$school_token,"roomws");
#    my $name_token=&AD_get_name_tokened($name,$school_token,"workstation");
#    my $display_name=$name_token;
#    my $smb_name=$name_token."\$";
    my $display_name=$name;
    my $smb_name=$name."\$";

    # dns
    my $root_dns=&AD_dns_get($root_dse);

    #my @dns_part_stripped=(); # without 'DC='
    #my @dns_part=split(/,/,$root_dse);
    #foreach my $part (@dns_part){
    #    $part=~s/DC=//g;
    #    #print "PART: $part\n";
    #    push @dns_part_stripped, $part;
    #}
    #my $dns_name = join(".",@dns_part_stripped);

#    $dns_name=$name_token.".".$root_dns;
#    my @service_principal_name=("HOST/".$name_token,
#                                "HOST/".$dns_name,
#                                "RestrictedKrbHost/".$name_token,
#                                "RestrictedKrbHost/".$dns_name,
#                               );
    $dns_name=$name.".".$root_dns;
    my @service_principal_name=("HOST/".$name,
                                "HOST/".$dns_name,
                                "RestrictedKrbHost/".$name,
                                "RestrictedKrbHost/".$dns_name,
                               );

#     my $container=&AD_get_container($role,$room_token);
    my $container=&AD_get_container($role,$room);
    my $dn_room = $container."OU=".$ou.",".$root_dse;
#    my $dn = "CN=".$name_token.",".$container."OU=".$ou.",".$root_dse;
    my $dn = "CN=".$name.",".$container."OU=".$ou.",".$root_dse;

    if($Conf::log_level>=1){
        &Sophomorix::SophomorixBase::print_title(
              "Creating workstation $ws_count: $name");
        print "   DN:                    $dn\n";
        print "   DN(Parent):            $dn_room\n";
#        print "   Name:                  $name_token\n";
#        print "   Room:                  $room_token\n";
        print "   Name:                  $name\n";
        print "   Room:                  $room\n";
        print "   OU:                    $ou\n";
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
#                   givenName   =s> "Workstation",
#                   sn   => "Account",
#                   cn   => $name_token,
                   cn   => $name,
                   accountExpires => '9223372036854775807', # means never
                   servicePrincipalName => \@service_principal_name,
#                   unicodePwd => $uni_password,
#                   sophomorixExitAdminClass => "unknown", 
#                   sophomorixUnid => $unid,
                   sophomorixStatus => "P",
#                   sophomorixAdminClass => $group_token,    
#                   sophomorixFirstPassword => $plain_password, 
#                   sophomorixFirstnameASCII => $firstname_ascii,
#                   sophomorixSurnameASCII  => $surname_ascii,
                   sophomorixRole => "computer",
                   sophomorixSchoolPrefix => $school_token,
                   sophomorixSchoolname => $ou,
                   sophomorixCreationDate => $creationdate, 
                   userAccountControl => '4096',
                   instanceType => '4',
                   objectclass => ['top', 'person',
                                     'organizationalPerson',
                                     'user','computer' ],
#                   'objectclass' => \@objectclass,
                           ]
                           );
    $result->code && warn "Failed to add entry: ", $result->error ;
    &AD_debug_logdump($result,2,(caller(0))[3]);
}




sub AD_user_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $user_count = $arg_ref->{user_count};
    my $identifier = $arg_ref->{identifier};
    my $login = $arg_ref->{login};
    my $group = $arg_ref->{group};
    my $firstname_ascii = $arg_ref->{firstname_ascii};
    my $surname_ascii = $arg_ref->{surname_ascii};
    my $firstname_utf8 = $arg_ref->{firstname_utf8};
    my $surname_utf8 = $arg_ref->{surname_utf8};
    my $birthdate = $arg_ref->{birthdate};
    my $plain_password = $arg_ref->{plain_password};
    my $unid = $arg_ref->{unid};
    my $uidnumber_wish = $arg_ref->{uidnumber_wish};
    my $gidnumber_wish = $arg_ref->{gidnumber_wish};
    my $ou = $arg_ref->{ou};
    my $school_token = $arg_ref->{school_token};
    my $role = $arg_ref->{role};
    my $type = $arg_ref->{type};
    my $creationdate = $arg_ref->{creationdate};
    my $tolerationdate = $arg_ref->{tolerationdate};
    my $deactivationdate = $arg_ref->{deactivationdate};
    my $status = $arg_ref->{status};

    # set defaults if not defined
    if (not defined $identifier){
        $identifier="---";
    }
    if (not defined $unid){
        $unid="---";
    }
    if (not defined $uidnumber_wish){
        $uidnumber_wish="---";
    }
    if (not defined $gidnumber_wish){
        $gidnumber_wish="---";
    }
    if ($tolerationdate eq "---"){
        $tolerationdate=$DevelConf::default_date;
    }
    if ($deactivationdate eq "---"){
        $deactivationdate=$DevelConf::default_date;
    }
    $ou=&AD_get_ou_tokened($ou);

    # calculate
    my $shell="/bin/false";
    my $display_name = $firstname_utf8." ".$surname_utf8;
    my $user_principal_name = $login."\@"."linuxmuster.local";

    my $container=&AD_get_container($role,$group);

    my $dn_class = $container."OU=".$ou.",".$root_dse;
    my $dn = "cn=".$login.",".$container."OU=".$ou.",".$root_dse;
 
    # password generation
    # build the conversion map from your local character set to Unicode    
    my $charmap = Unicode::Map8->new('latin1')  or  die;
    # surround the PW with double quotes and convert it to UTF-16
    my $uni_password = $charmap->tou('"'.$plain_password.'"')->byteswap()->utf16();

    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title(
              "Creating User $user_count : $login");
        print "   DN:                 $dn\n";
        print "   DN(Parent):         $dn_class\n";
        print "   Surname(ASCII):     $surname_ascii\n";
        print "   Surname(UTF8):      $surname_utf8\n";
        print "   Firstname(ASCII):   $firstname_ascii\n";
        print "   Firstname(UTF8):    $firstname_utf8\n";
        print "   Birthday:           $birthdate\n";
        print "   Identifier:         $identifier\n";
        print "   OU:                 $ou\n"; # Organisatinal Unit
        print "   School Token:       $school_token\n"; # Organisatinal Unit
        print "   Role(User):         $role\n";
        print "   Status:             $status\n";
        print "   Type(Group):        $type\n";
        print "   Group:              $group\n"; # lehrer oder klasse
        print "   Unix-gid:           $gidnumber_wish\n"; # lehrer oder klasse
        #print "   GECOS:              $gecos\n";
        #print "   Login (to check):   $login_name_to_check\n";
        print "   Login (check OK):   $login\n";
        print "   Password:           $plain_password\n";
        # sophomorix stuff
        print "   Creationdate:       $creationdate\n";
        print "   Tolerationdate:     $tolerationdate\n";
        print "   Deactivationdate:   $deactivationdate\n";
        print "   Unid:               $unid\n";
        print "   Unix-id:            $uidnumber_wish\n";
    }

    $ldap->add($dn_class,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    my $result = $ldap->add( $dn,
                   attr => [
                   sAMAccountName => $login,
                   givenName   => $firstname_utf8,
                   sn   => $surname_utf8,
                   displayName   => [$display_name],
                   userPrincipalName => $user_principal_name,
                   unicodePwd => $uni_password,
                   sophomorixExitAdminClass => "unknown", 
                   sophomorixUnid => $unid,
                   sophomorixStatus => $status,
                   sophomorixAdminClass => $group,    
                   sophomorixFirstPassword => $plain_password, 
                   sophomorixFirstnameASCII => $firstname_ascii,
                   sophomorixSurnameASCII  => $surname_ascii,
                   sophomorixBirthdate  => $birthdate,
                   sophomorixRole => $role,
                   sophomorixSchoolPrefix => $school_token,
                   sophomorixSchoolname => $ou,
                   sophomorixCreationDate => $creationdate, 
                   sophomorixTolerationDate => $tolerationdate, 
                   sophomorixDeactivationDate => $deactivationdate, 
                   userAccountControl => '512',
                   objectclass => ['top', 'person',
                                     'organizationalPerson',
                                     'user' ],
#                   'objectclass' => \@objectclass,
                           ]
                           );
    $result->code && warn "Failed to add entry: ", $result->error ;
    &AD_debug_logdump($result,2,(caller(0))[3]);
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
    my $birthdate = $arg_ref->{birthdate};
    my $user_count = $arg_ref->{user_count};
    my $user = $arg_ref->{user};

    # calculate missing attributes
    my $display_name = $firstname_utf8." ".$surname_utf8;

    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title(
              "Updating User $user_count : $user");
        print "   DN:                 $dn\n";
        print "   Surname(ASCII):     $surname_ascii\n";
        print "   Surname(UTF8):      $surname_utf8\n";
        print "   Firstname(ASCII):   $firstname_ascii\n";
        print "   Firstname(UTF8):    $firstname_utf8\n";
        print "   Birthday:           $birthdate\n";
    }

    my $mesg = $ldap->modify( $dn,
		      replace => {
                          sophomorixFirstnameASCII => $firstname_ascii,
                          sophomorixSurnameASCII => $surname_ascii,
                          sophomorixBirthdate => $birthdate,
                          givenName => $firstname_utf8,
                          sn => $surname_utf8,
                          displayName => [$display_name],

                      }
               );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
}


sub AD_user_move {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $user = $arg_ref->{user};
    my $user_count = $arg_ref->{user_count};
    my $group_old = $arg_ref->{group_old};
    my $group_new = $arg_ref->{group_new};
    my $ou_old = $arg_ref->{ou_old};
    my $ou_new = $arg_ref->{ou_new};
    my $school_token_old = $arg_ref->{school_token_old};
    my $school_token_new = $arg_ref->{school_token_new};
    my $role_new = $arg_ref->{role};
    my $creationdate = $arg_ref->{creationdate};

    # calculate
    my $group_type_old;
    my $group_type_new;
    my $target_branch;
    $ou_old=&AD_get_ou_tokened($ou_old);
    $ou_new=&AD_get_ou_tokened($ou_new);

    if ($role_new eq "student"){
         $target_branch="OU=".$group_new.",OU=Students,OU=".$ou_new.",".$root_dse;
    } elsif ($role_new eq "teacher"){
         $target_branch="OU=".$group_new.",OU=Teachers,OU=".$ou_new.",".$root_dse;
    }

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
        &Sophomorix::SophomorixBase::print_title("Moving User $user ($user_count):");

        print "   DN:             $dn\n";
        print "   Target DN:      $target_branch\n";
        print "   Group (Old):    $group_old\n";
        print "   Group (New):    $group_new\n";
        print "   Role (New):     $role_new\n";
        print "   School(Old):    $school_token_old ($ou_old)\n";
        print "   School(New):    $school_token_new ($ou_new)\n";
        print "   Creationdate:   $creationdate (if new group must be added)\n";
    }

    # make sure OU and tree exists
#    if (not exists $ou_created{$ou_new}){
#         # create new ou
         &AD_ou_add({ldap=>$ldap,
                     root_dse=>$root_dse,
                     ou=>$ou_new,
                     school_token=>$school_token_new,
                     creationdate=>$creationdate,
                   });
#         # remember new ou to add it only once
#         $ou_created{$ou_new}="already created";
#     }

    # make sure new group exits
    &AD_group_create({ldap=>$ldap,
                      root_dse=>$root_dse,
                      group=>$group_new,
                      description=>$group_new,
                      ou=>$ou_new,
                      school_token=>$school_token_new,
                      type=>"adminclass",
                      joinable=>"TRUE",
                      status=>"P",
                      creationdate=>$creationdate,
                    });

    # update user entry
    my $mesg = $ldap->modify( $dn,
		      replace => {
                          sophomorixAdminClass => $group_new,
                          sophomorixExitAdminClass => $group_old,
                          sophomorixSchoolPrefix => $school_token_new,
                          sophomorixSchoolname => $ou_new,
                          sophomorixRole => $role_new,
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
#    # move user membership to new group
#    &AD_group_removemember({ldap => $ldap,
#                            root_dse => $root_dse, 
#                            group => $group_old,
#                            removemember => $user,
#                          });   

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

    #&AD_group_addmember({ldap => $ldap,
    #                     root_dse => $root_dse, 
    #                     group => $group_new,
    #                     addmember => $user,
    #                   }); 





    # move the object in ldap tree
    &AD_object_move({ldap=>$ldap,
                     dn=>$dn,
                     rdn=>$rdn,
                     target_branch=>$target_branch,
                    });
    &Sophomorix::SophomorixBase::print_title("Moving User $user (end)");
}


sub AD_get_ou_tokened {
    my ($ou) = @_;
    if ($ou eq "---"){ # use default OU: SCHOOL
        # remove OU= from configured value
        my $string=$DevelConf::AD_school_ou;
        $string=~s/^OU=//;
        $ou=$string;
    }
    return $ou;
}

sub AD_get_name_tokened {
    # $role is: group type / user role
    # prepend <token> or not, depending on the users role/groups type 
    my ($name,$school_token,$role) = @_;
    my $name_tokened="";
    if ($role eq "adminclass" or
        $role eq "room" or 
        $role eq "roomws" or
        $role eq "examaccount" or
        $role eq "workstation" or
        $role eq "project" or
        $role eq "sophomorix-group"){
        if ($school_token eq "---" or $school_token eq ""){
            # SCHOOL, no multischool
            $name_tokened=$name;
        } else {
            # multischool
            if ($DevelConf::token_postfix==0){
                # prefix
                $name_tokened=$school_token."-".$name;
            } elsif ($DevelConf::token_postfix==1){
                # postfix
                $name_tokened=$name."-".$school_token;
            }
        }
        if ($role eq "workstation"){
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
    # } elsif ($role eq "project"){
    #     if ($school_token eq "---" or $school_token eq ""){
    #         # OU=SCHOOL
    #         $name_tokened=$school_token."-".$name;
    #     } else 
    #     unless ($name_tokened =~ m/^p\_/) { 
    #         # add refix to projects: p_ 
    #         $name_tokened="p_".$name_tokened;
    #     }
    #     return $name_tokened;
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
        $container=$group_strg.$DevelConf::AD_teacher_ou;
    }  elsif ($role eq "workstation"){
        $container=$group_strg.$DevelConf::AD_computer_ou;
    }  elsif ($role eq "examaccount"){
        $container=$group_strg.$DevelConf::AD_examaccount_ou;
    # group container
    }  elsif ($role eq "adminclass"){
        $container=$group_strg.$DevelConf::AD_student_ou;
    }  elsif ($role eq "project"){
        $container=$DevelConf::AD_project_ou;
    }  elsif ($role eq "sophomorix-group"){
        $container=$DevelConf::AD_project_ou;
    }  elsif ($role eq "room"){
        $container=$group_strg.$DevelConf::AD_examaccount_ou;
    # other
    }  elsif ($role eq "management"){
        $container=$DevelConf::AD_management_ou;
    }  elsif ($role eq "printer"){
        $container=$DevelConf::AD_printer_ou;
    }
    # add the comma if necessary
    if ($container ne ""){
        $container=$container.",";
    }
}


sub AD_ou_add {
    # if $result->code is not given, the add is silent
    #my ($ldap,$root_dse,$ou,$token) = @_;
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $ou = $arg_ref->{ou};
    my $token = $arg_ref->{school_token};
    my $creationdate = $arg_ref->{creationdate};

    $ou=&AD_get_ou_tokened($ou);
    if ($token eq "---"){
        $token=""; # OU=SCHOOL
    } else {
        $token=$token."-";
    }
    if($Conf::log_level>=2){
        print "Adding OU=$ou ($token) ...\n";
    }

    my $dn="OU=".$ou.",".$root_dse;
    # provide that a ou SCHOOLNAME exists
    my $result = $ldap->add($dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);

    if($Conf::log_level>=2){
        print "   * Adding sub ou's ...\n";
    }
    # ou's for users
    my $student=$DevelConf::AD_student_ou.",".$dn;
    $result = $ldap->add($student,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    my $teacher=$DevelConf::AD_teacher_ou.",".$dn;
    $result = $ldap->add($teacher,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    my $workstation=$DevelConf::AD_computer_ou.",".$dn;
    $result = $ldap->add($workstation,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    my $examaccount=$DevelConf::AD_examaccount_ou.",".$dn;
    $result = $ldap->add($examaccount,attr => ['objectclass' => ['top', 'organizationalUnit']]);

    # other
    my $project=$DevelConf::AD_project_ou.",".$dn;
    $result = $ldap->add($project,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    my $management=$DevelConf::AD_management_ou.",".$dn;
    $result = $ldap->add($management,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    my $printer=$DevelConf::AD_printer_ou.",".$dn;
    $result = $ldap->add($printer,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    my $custom=$DevelConf::AD_custom_ou.",".$dn;
    $result = $ldap->add($custom,attr => ['objectclass' => ['top', 'organizationalUnit']]);

    # Adding some groups
    # <token>-teachers
    my $group=$token.$DevelConf::teacher;
    my $target_branch="OU=".$group.",".$DevelConf::AD_teacher_ou.",".$dn;
    my $dn_group="CN=".$group.",OU=".$group.",".$DevelConf::AD_teacher_ou.",".$dn;

    if($Conf::log_level>=2){
        print "   * Adding group $group\n";
    }
    # create parent
    my $target = $ldap->add($target_branch,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    # create group
    $result = $ldap->add( $dn_group,
                         attr => [
                           cn   => $group,
                           sAMAccountName => $group,
                           sophomorixCreationDate => $creationdate,
                           sophomorixStatus => "P",
                           sophomorixType => "adminclass",
                           sophomorixJoinable=>"TRUE",
                           sophomorixHidden => "FALSE",
                           sophomorixMaxmembers=> "0",
                           sophomorixQuota=> "---",
                           sophomorixMailQuota=> "-1",
                           sophomorixMailalias => "FALSE",
                           sophomorixMaillist => "FALSE",
                           description => "LML Teachers $ou",
                           objectclass => ['top',
                                             'group' ],
                         ]
                     );

    # <token>-students
    $group=$token.$DevelConf::student;

    $target_branch="OU=".$group.",".$DevelConf::AD_student_ou.",".$dn;
    $dn_group="CN=".$group.",OU=".$group.",".$DevelConf::AD_student_ou.",".$dn;

    if($Conf::log_level>=2){
        print "   * Adding group $group\n";
    }
    # create parent
    $target = $ldap->add($target_branch,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    # create group
    $result = $ldap->add( $dn_group,
                         attr => [
                             cn   => $group,
                             sAMAccountName => $group,
                             sophomorixCreationDate => $creationdate,
                             sophomorixStatus => "P",
                             sophomorixType => "adminclass",
                             sophomorixJoinable=>"TRUE",
                             sophomorixHidden => "FALSE",
                             sophomorixMaxmembers=> "0",
                             sophomorixQuota=> "---",
                             sophomorixMailQuota=> "-1",
                             sophomorixMailalias => "FALSE",
                             sophomorixMaillist => "FALSE",
                             description => "LML Students $ou",
                             objectclass => ['top',
                                               'group' ],
                         ]
                     );

    # <token>-examaccounts
    $group=$token.$DevelConf::examaccount;
    $target_branch="OU=".$group.",".$DevelConf::AD_examaccount_ou.",".$dn;
    $dn_group="CN=".$group.",OU=".$group.",".$DevelConf::AD_examaccount_ou.",".$dn;

    if($Conf::log_level>=2){
        print "   * Adding group $group\n";
    }
    # create parent
    $target = $ldap->add($target_branch,attr => ['objectclass' => ['top', 'organizationalUnit']]);
    # create group
    $result = $ldap->add( $dn_group,
                         attr => [
                             cn   => $group,
                             sAMAccountName => $group,
                             sophomorixCreationDate => $creationdate,
                             sophomorixStatus => "P",
                             sophomorixType => "adminclass",
                             sophomorixJoinable=>"TRUE",
                             sophomorixHidden => "FALSE",
                             sophomorixMaxmembers=> "0",
                             sophomorixQuota=> "---",
                             sophomorixMailQuota=> "-1",
                             sophomorixMailalias => "FALSE",
                             sophomorixMaillist => "FALSE",
                             description => "LML ExamAccounts $ou",
                             objectclass => ['top',
                                               'group' ],
                         ]
                     );


    # <token>-wifi
    $group=$token.$DevelConf::AD_wifi_group;
    $dn_group="CN=".$group.",".$DevelConf::AD_management_ou.",".$dn;
    if($Conf::log_level>=2){
        print "   * Adding group $group\n";
    }
    $result = $ldap->add( $dn_group,
                         attr => [
                             cn   => $group,
                             sAMAccountName => $group,
                             sophomorixCreationDate => $creationdate,
                             sophomorixStatus => "P",
                             sophomorixType => "adminclass",
                             sophomorixJoinable=>"TRUE",
                             sophomorixHidden => "FALSE",
                             sophomorixMaxmembers=> "0",
                             sophomorixQuota=> "---",
                             sophomorixMailQuota=> "-1",
                             sophomorixMailalias => "FALSE",
                             sophomorixMaillist => "FALSE",
                             description => "LML Wifigroup $ou",
                             objectclass => ['top',
                                               'group' ],
                         ]
                     );

    # <token>-internet
    $group=$token.$DevelConf::AD_internet_group;
    $dn_group="CN=".$group.",".$DevelConf::AD_management_ou.",".$dn;
    if($Conf::log_level>=2){
        print "   * Adding group $group\n";
    }
    $result = $ldap->add( $dn_group,
                         attr => [
                             cn   => $group,
                             sophomorixCreationDate => $creationdate,
                             sAMAccountName => $group,
                             sophomorixStatus => "P",
                             sophomorixType => "adminclass",
                             sophomorixJoinable=>"TRUE",
                             sophomorixHidden => "FALSE",
                             sophomorixMaxmembers=> "0",
                             sophomorixQuota=> "---",
                             sophomorixMailQuota=> "-1",
                             sophomorixMailalias => "FALSE",
                             sophomorixMaillist => "FALSE",
                             description => "LML Internetaccess $ou",
                             objectclass => ['top',
                                               'group' ],
                         ]
                     );




    ############################################################
    # OU=GLOBAL
    { # start: make the following vars for OU=GLOBAL local vars
    my $global_dn=$DevelConf::AD_global_ou.",".$root_dse;
    if($Conf::log_level>=2){
        print "Adding $global_dn\n";
    }
    $result = $ldap->add($global_dn,attr => ['objectclass' => ['top', 'organizationalUnit']]);

    if($Conf::log_level>=2){
        print "   * Adding sub ou's ...\n";
    }
    # Groups ou
    my $globalgroup=$DevelConf::AD_globalgroup_ou.",".$global_dn;
    $result = $ldap->add($globalgroup,attr => ['objectclass' => ['top', 'organizationalUnit']]);

#    # Projects ou
#    my $projects=$DevelConf::AD_project_ou.",".$global_dn;
#    $result = $ldap->add($projects,attr => ['objectclass' => ['top', 'organizationalUnit']]);

    my $custom=$DevelConf::AD_custom_ou.",".$global_dn;
    $result = $ldap->add($custom,attr => ['objectclass' => ['top', 'organizationalUnit']]);

    # students in Groups,OU=GLOBAL
    my $global_dn_group="CN=global-".$DevelConf::student.",".$DevelConf::AD_globalgroup_ou.",".$global_dn;
    $result = $ldap->add( $global_dn_group,
                         attr => [
                             cn => "global-".$DevelConf::student,
                             sAMAccountName => "global-".$DevelConf::student,
                             sophomorixCreationDate => $creationdate,
                             sophomorixStatus => "P",
                             sophomorixType => "adminclass",
                             sophomorixJoinable=>"TRUE",
                             sophomorixHidden => "FALSE",
                             sophomorixMaxmembers=> "0",
                             sophomorixQuota=> "---",
                             sophomorixMailQuota=> "-1",
                             sophomorixMailalias => "FALSE",
                             sophomorixMaillist => "FALSE",
                             description => "LML Global Students",
                             objectclass => ['top',
                                               'group' ],
                         ]
                     );
    if($Conf::log_level>=2){
        print "   * Adding OU=SOPHOMOROX global-groups ...\n";
    }
    # teachers in Groups,OU=GLOBAL
    $global_dn_group="CN=global-".$DevelConf::teacher.",".$DevelConf::AD_globalgroup_ou.",".$global_dn;
    $result = $ldap->add( $global_dn_group,
                         attr => [
                             cn => "global-".$DevelConf::teacher,
                             sAMAccountName => "global-".$DevelConf::teacher,
                             sophomorixCreationDate => $creationdate,
                             sophomorixStatus => "P",
                             sophomorixType => "adminclass",
                             sophomorixJoinable=>"TRUE",
                             sophomorixHidden => "FALSE",
                             sophomorixMaxmembers=> "0",
                             sophomorixQuota=> "---",
                             sophomorixMailQuota=> "-1",
                             sophomorixMailalias => "FALSE",
                             sophomorixMaillist => "FALSE",
                             description => "LML Global Teachers",
                             objectclass => ['top',
                                               'group' ],
                         ]
                     );
    # ExamAccounts in Groups,OU=GLOBAL
    $global_dn_group="CN=global-".$DevelConf::examaccount.",".$DevelConf::AD_globalgroup_ou.",".$global_dn;
    $result = $ldap->add( $global_dn_group,
                         attr => [
                             cn => "global-".$DevelConf::examaccount,
                             sAMAccountName => "global-".$DevelConf::examaccount,
                             sophomorixCreationDate => $creationdate,
                             sophomorixStatus => "P",
                             sophomorixType => "adminclass",
                             sophomorixJoinable=>"TRUE",
                             sophomorixHidden => "FALSE",
                             sophomorixMaxmembers=> "0",
                             sophomorixQuota=> "---",
                             sophomorixMailQuota=> "-1",
                             sophomorixMailalias => "FALSE",
                             sophomorixMaillist => "FALSE",
                             description => "LML Global ExamAccounts",
                             objectclass => ['top',
                                               'group' ],
                         ]
                     );

    } # end: make the following vars for OU=GLOBAL local vars
    &AD_debug_logdump($result,2,(caller(0))[3]);
}



sub AD_object_search {
    my ($ldap,$root_dse,$objectclass,$name) = @_;
    # returns 0,"" or 1,"dn of object"
    # objectclass: group, user, ...
    # check if object exists
    # (&(objectclass=user)(cn=pete)
    # (&(objectclass=group)(cn=7a)
    my $filter="(&(objectclass=".$objectclass.") (cn=".$name."))"; 
    my $mesg = $ldap->search(
                      base   => $root_dse,
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
        my $cn = $entry->get_value ('cn');
        $cn="CN=".$cn;
        my $info="no sophomorix info available (Role, Type)";
        if ($objectclass eq "group"){
            $info = $entry->get_value ('sophomorixType');
        } elsif ($objectclass eq "user"){
            $info = $entry->get_value ('sophomorixRole');
        }
        return ($count,$dn,$cn,$info);
    } else {
        return (0,"","");
    }
}

sub AD_computer_fetch {
    my ($ldap,$root_dse) = @_;
    # domcomputers
    # key: host$ (lowercase)
    # Value: $room (lml6: always domcomputers)
    my %domcomputers_system = ();
    # domcomputers from ldap
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(&(objectClass=computer)(sophomorixRole=computer))',
                   attrs => ['sAMAccountName']
                         );
    my $max_user = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title("$max_user Workstations found in AD");

    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        if($Conf::log_level>=2){
            print "   * ",$entry->get_value('sAMAccountName'),"\n";
        }
        $domcomputers_system{$entry->get_value('sAMAccountName')}="domcomputers";
    }



    # rooms
    # key: room/group
    # Value: 'seen'
    my %rooms_system = ();

# remove that later ????????????????????????????????
   print "This rooms were manually added:\n"; 
   $rooms_system{"bsz-j1008"}="seen";
    $rooms_system{"bsz-j1010"}="seen";

#    $mesg = $ldap->search( # perform a search
#                   base   => $root_dse,
#                   scope => 'sub',
#                   filter => '(&(objectClass=group)(sophomorixType=room))',
#                   attrs => ['sAMAccountName']
#                         );
#    $max_user = $mesg->count; 
#    &Sophomorix::SophomorixBase::print_title("$max_user Rooms found");#
#
#    for( my $index = 0 ; $index < $max_user ; $index++) {
#        my $entry = $mesg->entry($index);
#        print "   * ",$entry->get_value('sAMAccountName'),"\n";
#        $domcomputers_system{$entry->get_value('sAMAccountName')}="domcomputers";
#    }




    # examaccounts
    # key:   Account name i.e. j1008p01  
    # Value: room/group i.e. j1008
    my %examaccounts_system = ();
    # examaccounts from ldap
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(&(objectClass=user)(sophomorixRole=examaccount))',
                   attrs => ['sAMAccountName',"sophomorixAdminClass"]
                         );
    $max_user = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title("$max_user ExamAccounts found in AD");

    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        if($Conf::log_level>=2){
            print "   * ",$entry->get_value('sAMAccountName'),
                  "  in Room  ".$entry->get_value('sophomorixAdminClass')."\n";
        }
        $examaccounts_system{$entry->get_value('sAMAccountName')}=$entry->get_value('sophomorixAdminClass');
    }





    return(\%domcomputers_system, 
           \%rooms_system, 
           \%examaccounts_system, 
          );
}



sub AD_class_fetch {
    my ($ldap,$root_dse,$class,$ou,$school_token,$info) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. class7a
    my $adminclass="";  # the option i.e. 'class7*'
    if (defined $school_token){
        $adminclass=&AD_get_name_tokened($class,$school_token,"adminclass");
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
            my @project_attr=("gidnumber: ???",
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
    my ($ldap,$root_dse,$pro,$ou,$school_token,$info) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. p_abt3
    my $project="";     # the option i.e. 'p_abt*'
    # projects from ldap
    if (defined $school_token){
        $project=&AD_get_name_tokened($pro,$school_token,"project");
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
            my @project_attr=("gidnumber: ???",
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
    # members   
    if (defined $members){
        my @members=split(/,/,$members);
        @members = reverse @members;
        @members = &_keep_object_class_only($ldap,$root_dse,"user",@members);
        print "   * Setting sophomorixMembers to @members\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixMembers' => \@members }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # admins
    if (defined $admins){
        my @admins=split(/,/,$admins);
        @admins = reverse @admins;
        @admins = &_keep_object_class_only($ldap,$root_dse,"user",@admins);
        print "   * Setting sophomorixAdmins to @admins\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixAdmins' => \@admins }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # membergroups   
    if (defined $membergroups){
        my @membergroups=split(/,/,$membergroups);
        @membergroups = reverse @membergroups;
        @membergroups = &_keep_object_class_only($ldap,$root_dse,"group",@membergroups);
        print "   * Setting sophomorixMemberGroups to @membergroups\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixMemberGroups' => \@membergroups }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # admingroups
    if (defined $admingroups){
        my @admingroups=split(/,/,$admingroups);
        @admingroups = reverse @admingroups;
        @admingroups = &_keep_object_class_only($ldap,$root_dse,"group",@admingroups);
        print "   * Setting sophomorixAdmingroups to @admingroups\n";
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



sub AD_group_list {
    # show==0 return list of project dn's
    # show==1 print ist, no return
    my ($ldap,$root_dse,$type,$show) = @_;
    my $filter;
    if ($type eq "project"){
        $filter="(&(objectClass=group)(sophomorixType=project))";
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
    my $description = $arg_ref->{description};
    my $ou = $arg_ref->{ou};
    my $type = $arg_ref->{type};
    my $school_token = $arg_ref->{school_token};
    my $creationdate = $arg_ref->{creationdate};
    my $status = $arg_ref->{status};
    my $joinable = $arg_ref->{joinable};

    if (not defined $joinable){
        $joinable="FALSE";    
    }
    $ou=&AD_get_ou_tokened($ou);

    # calculate missing Attributes
    my $container=&AD_get_container($type,$group);
    my $target_branch=$container."OU=".$ou.",".$root_dse;
    my $dn = "CN=".$group.",".$container."OU=".$ou.",".$root_dse;

    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count==0){
        # adding the group
        &Sophomorix::SophomorixBase::print_title("Creating Group (begin):");
        print("   DN:            $dn\n");
        print("   Target:        $target_branch\n");
        print("   Group:         $group\n");
        print("   Type:          $type\n");
        print("   Joinable:      $joinable\n");
        print "   Creationdate:  $creationdate\n";

        # Create target branch
        my $target = $ldap->add($target_branch,attr => ['objectclass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($target,2,(caller(0))[3]);

        # Create object
        my $result = $ldap->add( $dn,
                                attr => [
                                    cn   => $group,
                                    description => $description,
                                    sAMAccountName => $group,
                                    sophomorixCreationDate => $creationdate, 
                                    sophomorixType => $type, 
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
                                    objectclass => ['top',
                                                      'group' ],
                                ]
                            );
        $result->code && warn "failed to add entry: ", $result->error ;
        &AD_debug_logdump($result,2,(caller(0))[3]);
    } else {
        print "   * Group $group exists already ($count results)\n";
    }
    if ($type eq "adminclass"){
        my $teacher_group_expected=&AD_get_name_tokened($DevelConf::teacher,$school_token,"adminclass");
        if ($group eq $teacher_group_expected){
            # add <token>-teachers to global-teachers
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => "global-".$DevelConf::teacher,
                                 addgroup => $group,
                               });
        } else {
            # a group like 7a, 7b
            #print "Student class of the school: $group\n";
            my $token_students=&AD_get_name_tokened($DevelConf::student,$school_token,"adminclass");
            # add the group to <token>-students
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $token_students,
                                 addgroup => $group,
                               });
            # add group <token>-students to global-students
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => "global-".$DevelConf::student,
                                 addgroup => $token_students,
                               });
        }
    } elsif ($type eq "room"){
        my $token_examaccounts=$school_token."-".$DevelConf::examaccount;
        # add the room to <token>-examaccounts
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $token_examaccounts,
                             addgroup => $group,
                           });
        # add group <token>-examaccounts to global-examaccounts
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => "global-".$DevelConf::examaccount,
                             addgroup => $token_examaccounts,
                           });
    }
    &Sophomorix::SophomorixBase::print_title("Creating Group (end)");
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
     }

     if (defined $adduser){
         my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$adduser);
         print "   * Adding user $adduser to group $group\n";
         if ($count > 0){
             print "   * User $adduser exists ($count results)\n";
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
        print "   * Removing user $removeuser from group $group\n";
        if ($count > 0){
            print "   * User $removeuser exists ($count results)\n";
            my $mesg = $ldap->modify( $dn_exist_group,
	  	                  delete => {
                                  member => $dn_exist,
                                  }
                              );
            #my $command="samba-tool group removemembers ". $group." ".$removeuser;
            #print "   # $command\n";
            #system($command);
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

    # future groups in schueler.txt
    my $schueler_file=$DevelConf::path_conf_user."/schueler.txt";
    if (-e "$schueler_file"){
        open(STUDENTS, "$schueler_file");
        while(<STUDENTS>) {
            my ($group)=split(/;/);
            chomp($group);
            if ($group ne ""){
                $forbidden_logins{$group}="future group $group in schueler.txt";
   	    }
         }
         close(STUDENTS);
    }

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
    if($Conf::log_level>=$level){
        if ( $message->code) { # 0: no error
            print "   Debug info from server($text):\n";
            print Dumper(\$message);
        }
    }
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


# END OF FILE
# Return true=1
1;
