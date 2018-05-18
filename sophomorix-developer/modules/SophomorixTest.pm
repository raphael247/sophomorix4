#!/usr/bin/perl -w
# This perl module SophomorixTest is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linuxmuster.net

package Sophomorix::SophomorixTest;
require Exporter;
use File::Basename;
use Unicode::Map8;
use Unicode::String qw(utf16);
use Net::LDAP;
use Sophomorix::SophomorixConfig;
use Test::More "no_plan";
use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 

@ISA = qw(Exporter);

@EXPORT_OK = qw( );
@EXPORT = qw(
            AD_object_nonexist
            AD_dn_nonexist
            AD_test_object
            AD_test_session_count
            AD_test_dns
            AD_test_nondns
            AD_computers_any
            AD_examaccounts_any
            AD_dnsnodes_count
            AD_dnszones_count
            AD_rooms_any
            AD_user_timeupdate
            ACL_test
            NTACL_test
            start_fs_test
            end_fs_test
            directory_tree_test
            run_command
            file_test_lines
            file_test_chars
            AD_get_samaccountname
            cat_wcl_test
            smbcquotas_test
            diff_acl_snapshot
            );


sub AD_test_session_count {
    my ($ldap,$root_dse,$root_dns,$smb_admin_pass,$should) = @_;
    my %sessions=&Sophomorix::SophomorixSambaAD::AD_get_sessions($ldap,$root_dse,$root_dns,0,0,"all",
                                                                 $smb_admin_pass,$ref_sophomorix_config);
    my $count=$sessions{'SESSIONCOUNT'};
    is ($count,$should,"  * There exist $should sessions");
    return $count;
}



sub AD_computers_any {
    my ($ldap,$root_dse) = @_;
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(&(objectClass=computer)(sophomorixRole=computer))',
                   attrs => ['sAMAccountName']
                         );
    my $max_user = $mesg->count; 
    is ($max_user,0,"  * All sophomorix computers are deleted");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        print "   * ",$entry->get_value('sAMAccountName'),"\n";
    }
}



sub AD_test_dns {
    my ($res,$host,$ipv4)=@_;
    # Test lookup
    my $reply = $res->search($host);
    if ($reply) {
        foreach my $rr ($reply->answer) {
            next unless $rr->type eq "A";
            is ($rr->address,$ipv4,"  * $host has IPv4 $ipv4 by dns query");
        }
    } else {
        is (0,1,"  * dns query succesful (1) or not (0)");
    }

    # Test reverse lookup
    my $nslookup=system("nslookup $ipv4 >> /dev/null");
    is ($nslookup,0,"  * nslookup returned $nslookup (reverse lookup)");
}



sub AD_test_nondns {
    my ($res,$host)=@_;
    my $reply = $res->search($host);
    if ($reply) {
        foreach my $rr ($reply->answer) {
            next unless $rr->type eq "A";
            my $ipv4=$rr->address;
            is (0,1,"  * $host has no IPv4 (IPv4 is $ipv4, positive dns response");
        }
    } else {
        is (0,0,"  * dns query for $host failed (0) ");
    }
}


           
sub AD_examaccounts_any {
    my ($ldap,$root_dse) = @_;
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(&(objectClass=user)(sophomorixRole=examaccount))',
                   attrs => ['sAMAccountName',"sophomorixAdminClass"]
                         );
    my $max_user = $mesg->count; 
    is ($max_user,0,"  * All ExamAccounts are deleted");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
            print "   * ",$entry->get_value('sAMAccountName'),
                  "  sophomorixAdminClass:  ".$entry->get_value('sophomorixAdminClass')."\n";
    }
}



sub AD_rooms_any {
    my ($ldap,$root_dse) = @_;
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(&(objectClass=group)(sophomorixType=room))',
                   attrs => ['sAMAccountName',"sophomorixType"]
                         );
    my $max_user = $mesg->count; 
    is ($max_user,0,"  * All room groups are deleted");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
            print "   * ",$entry->get_value('sAMAccountName')."\n";
    }
}



sub AD_user_timeupdate {
    my ($ldap,$root_dse,$dn,$toleration_date,$deactivation_date)=@_;
    print "Updating: $dn\n";
    if ($toleration_date ne "---"){
        $replace{'sophomorixTolerationDate'}=$toleration_date;
        print "   sophomorixTolerationDate:      $toleration_date  \n";
    }
    if ($deactivation_date ne "---"){
        $replace{'sophomorixDeactivationDate'}=$deactivation_date;
        print "   sophomorixDeactivationDate:    $deactivation_date  \n";
    }

    # modify
    my $mesg = $ldap->modify( $dn,
		      replace => { %replace }
               );
    #&AD_debug_logdump($mesg,2,(caller(0))[3]);
}



sub AD_dnsnodes_count {
    my ($expected,$ldap,$root_dse) = @_;
    my $filter_node="(&(objectClass=dnsNode)(sophomorixRole=*))";
    $mesg = $ldap->search( # perform a search
                   base   => "CN=MicrosoftDNS,DC=DomainDnsZones,DC=linuxmuster,DC=local",
                   scope => 'sub',
                   filter => $filter_node,
                   attrs => ['dc','sophomorixRole','sophomorixdnsNodename']
                         );
    my $max_user = $mesg->count; 
    is ($max_user,$expected,"  * $expected sophomorix dnsNodes found");
    if ($max_user==$expected){
        # no output
    } else {
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $string="sophomorixdnsNodename:".$entry->get_value('sophomorixdnsNodename').", ".
                       "sophomorixRole:".$entry->get_value('sophomorixRole');
            printf "   * %-14s-> %-50s\n",$entry->get_value('dc'),$string;
        }
    }
}



sub AD_dnszones_count {
    my ($expected,$ldap,$root_dse) = @_;
    my $filter_zone="(& (objectClass=dnsZone) (sophomorixRole=sophomorixdnsZone) )";
    $mesg = $ldap->search( # perform a search
                   base   => "CN=MicrosoftDNS,DC=DomainDnsZones,DC=linuxmuster,DC=local",
                   scope => 'sub',
                   filter => $filter_zone,
                   attrs => ['dc','sophomorixRole','cn']
                         );
    my $max_user = $mesg->count; 
    is ($max_user,$expected,"  * $expected sophomorixdnsZones found");
    if ($max_user==$expected){
        # no output
    } else {
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $string="sophomorixRole:".$entry->get_value('sophomorixRole').", ".
                       "cn:".$entry->get_value('cn');
            printf "   * %-26s-> %-40s\n",$entry->get_value('dc'),$string;
        }
    }
}



sub AD_object_nonexist {
    my ($ldap,$root_dse,$type,$name) = @_;
    # type: group, user, ...
    # check if object exists
    # (&(objectClass=user)(cn=pete)
    # (&(objectClass=group)(cn=7a)
    my $filter;   
    if ($type eq "examaccount"){
        $filter="(&(objectClass=user) (cn=".$name.") (sAMAccountname=".$name.") )";
    } elsif ($type eq "computer"){
        $filter="(&(objectClass=computer) (sAMAccountname=".$name.") )";
    } else {
        $filter="(&(objectClass=".$type.") (cn=".$name."))";
    } 
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['cn']
                            );
    #print Dumper(\$mesg);
    #&Sophomorix::SophomorixSambaAD::AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $count = $mesg->count;
    is ($count,0,"  * $type-Object $name does not exist");
}



sub AD_dn_nonexist {
    my ($ldap,$root_dse,$dn) = @_;
    my $mesg = $ldap->search(
                      base   => $dn,
                      scope => 'sub',
                      filter => 'name=*',
                      attr => ['cn']
                            );
    #print Dumper(\$mesg);
    #&Sophomorix::SophomorixSambaAD::AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $count = $mesg->count;
    is ($count,0,"  * $dn does not exist");


}



sub AD_get_samaccountname {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $given_name = $arg_ref->{givenName};
    my $sn = $arg_ref->{sn};
    my $birthdate = $arg_ref->{birthdate};
    my $filter="(&(sn=".$sn.") (givenName=".$given_name.
               ") (sophomorixBirthdate=".$birthdate."))";
    print "Finding Loginname with the following filter:\n";
    print "   $filter\n";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName',
                            ]);
    my $res = $mesg->count; 
    if ($res!=1){
            print "   * WARNUNG $res for $given_name $sn $birthdate\n";
        #exit;
        return
    } elsif ($res==1){
        my ($entry,@entries) = $mesg->entries;
        my $dn = $entry->dn();
        my $sam = $entry->get_value('sAMAccountName');
        print "   * DN:      $dn\n";
        print "   * ACCOUNT: $sam\n";
        return ($sam,$dn);
    }
}



sub AD_test_object {
    # verifies an object and Attributes in ldap
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $dn = $arg_ref->{dn};
    my $cn = $arg_ref->{cn};
    my $root_dse = $arg_ref->{root_dse};

    # user
    my $display_name = $arg_ref->{displayName};
    my $name = $arg_ref->{name};
    my $given_name = $arg_ref->{givenName};
    my $upn =$arg_ref->{userPrincipalName};
    my $mail =$arg_ref->{mail};
    my $sam_account =$arg_ref->{sAMAccountname};
    my $account_expires =$arg_ref->{accountExpires};
    my $dns_hostname =$arg_ref->{dNSHostName};
    my $ser_pri_name =$arg_ref->{servicePrincipalName};
    my $sn =$arg_ref->{sn};
    my $description =$arg_ref->{description};
    my $uidnumber =$arg_ref->{uidNumber};
    my $homedrive =$arg_ref->{homeDrive};
    my $homedirectory =$arg_ref->{homeDirectory};
    my $unixhomedirectory =$arg_ref->{unixHomeDirectory};
    my $useraccountcontrol =$arg_ref->{userAccountControl};

    # group
    my $gidnumber =$arg_ref->{gidNumber};

    # room
    my $s_room_ips =$arg_ref->{sophomorixRoomIPs};
    my $s_room_macs =$arg_ref->{sophomorixRoomMACs};
    my $s_room_computers =$arg_ref->{sophomorixRoomComputers};

    # sophomorix computer
    my $s_dns_nodename = $arg_ref->{sophomorixDnsNodename};
    my $s_ip = $arg_ref->{sophomorixComputerIP};
    my $s_mac = $arg_ref->{sophomorixComputerMAC};
    my $s_room = $arg_ref->{sophomorixComputerRoom};

    # sophomorix user
    my $s_admin_class = $arg_ref->{sophomorixAdminClass};
    my $s_exit_admin_class = $arg_ref->{sophomorixExitAdminClass};
    my $s_first_password = $arg_ref->{sophomorixFirstPassword};
    my $s_firstname_ascii = $arg_ref->{sophomorixFirstnameASCII};
    my $s_surname_ascii = $arg_ref->{sophomorixSurnameASCII};
    my $s_firstname_ini = $arg_ref->{sophomorixFirstnameInitial};
    my $s_surname_ini = $arg_ref->{sophomorixSurnameInitial};
    my $s_usertoken = $arg_ref->{sophomorixUserToken};
    my $s_birthdate = $arg_ref->{sophomorixBirthdate};
    my $s_role = $arg_ref->{sophomorixRole};
    my $s_school_prefix = $arg_ref->{sophomorixSchoolPrefix};
    my $s_school_name = $arg_ref->{sophomorixSchoolname};
    my $s_creationdate = $arg_ref->{sophomorixCreationDate};
    my $s_tolerationdate = $arg_ref->{sophomorixTolerationDate};
    my $s_deactivationdate = $arg_ref->{sophomorixDeactivationDate};
    my $s_comment = $arg_ref->{sophomorixComment};
    my $s_webui = $arg_ref->{sophomorixWebuiDashboard};
    my $s_user_permissions = $arg_ref->{sophomorixWebuiPermissions};
    my $s_user_permissions_calculated = $arg_ref->{sophomorixWebuiPermissionsCalculated};
    my $s_admin_file = $arg_ref->{sophomorixAdminFile};
    my $s_unid = $arg_ref->{sophomorixUnid};
    my $s_exammode = $arg_ref->{sophomorixExamMode};
    my $s_quota = $arg_ref->{sophomorixQuota};
    my $s_mailquota = $arg_ref->{sophomorixMailQuota};
    my $s_mailquotacalc = $arg_ref->{sophomorixMailQuotaCalculated};
    my $s_cloudquotacalc = $arg_ref->{sophomorixCloudQuotaCalculated};

    # sophomorix group
    my $s_type = $arg_ref->{sophomorixType};
    my $s_addquota = $arg_ref->{sophomorixAddQuota};
    my $s_addmailquota = $arg_ref->{sophomorixAddMailQuota};
    my $s_mailalias = $arg_ref->{sophomorixMailAlias};
    my $s_maillist = $arg_ref->{sophomorixMailList};
    my $s_status = $arg_ref->{sophomorixStatus};
    my $s_joinable = $arg_ref->{sophomorixJoinable};
    my $s_maxmembers = $arg_ref->{sophomorixMaxMembers};
    my $s_admins = $arg_ref->{sophomorixAdmins};
    my $s_members = $arg_ref->{sophomorixMembers};
    my $s_admingroups = $arg_ref->{sophomorixAdminGroups};
    my $s_membergroups = $arg_ref->{sophomorixMemberGroups};
    my $s_hidden = $arg_ref->{sophomorixHidden};
    my $s_sessions = $arg_ref->{sophomorixSessions};

    my $member = $arg_ref->{member};
    my $member_of = $arg_ref->{memberOf};
    #my $not_member_of = $arg_ref->{not_memberOf};

    my $filter="(|(cn=*)(dn=*))";
    my $mesg = $ldap->search(
                      base   => $dn,
                      scope => 'base',
                      filter => $filter,
                            );
    #print Dumper(\$mesg);
    my ($entry,@entries) = $mesg->entries;
    my $count = $mesg->count;

    # Testing object existence
    is ($count,1, "****** Found 1 Object: $dn");
   
    if ($count==1){
        # 
        my @object_classes=$entry->get_value ('objectClass');
        my $objectclass=""; # user, group, ...
        foreach my $oc (@object_classes){
            if ($oc eq "group"){
                $objectclass="group";
            } elsif ($oc eq "user"){
                $objectclass="user";
            } elsif ($oc eq "computer"){
                $objectclass="computer";
            } elsif ($oc eq "dnsNode"){
                $objectclass="dnsNode";
            } elsif ($oc eq "dnsZone"){
                $objectclass="dnsZone";
            }
        }
        print "*********** objectClass: $objectclass\n";


        # Testing attributes
        if (defined $cn){
            is ($entry->get_value ('cn'),$cn,
                                   "  * cn is $cn");
        }
        if (defined $display_name){
            is ($entry->get_value ('DisplayName'),$display_name,
                                   "  * displayName is $display_name");
        }
        if (defined $given_name){
            is ($entry->get_value ('givenName'),$given_name,
		"  * givenName is $given_name");
        }
        if (defined $name){
            is ($entry->get_value ('name'),$name,
		"  * name is $name");
        }
        if (defined $sam_account){
            is ($entry->get_value ('sAMAccountName'),$sam_account,
		"  * sAMAccountName is $sam_account");
        }
        if (defined $account_expires){
            is ($entry->get_value ('accountExpires'),$account_expires,
		"  * account_expires is $account_expires");
        }
        if (defined $dns_hostname){
            is ($entry->get_value ('dNSHostName'),$dns_hostname,
		"  * dNSHostName is $dns_hostname");
        }
        if (defined $sn){
            is ($entry->get_value ('sn'),$sn,
		"  * sn is $sn");
        }
        if (defined $description){
            is ($entry->get_value ('description'),$description,
		"  * description is $description");
        }
        if (defined $homedrive){
            is ($entry->get_value ('homeDrive'),$homedrive,
		"  * homeDrive is $homedrive");
        }
        if (defined $homedirectory){
            is ($entry->get_value ('homeDirectory'),$homedirectory,
		"  * homeDirectory is $homedirectory");
        }
        if (defined $unixhomedirectory){
            is ($entry->get_value ('unixHomeDirectory'),$unixhomedirectory,
		"  * unixHomeDirectory is $unixhomedirectory");
        }
        if (defined $useraccountcontrol){
            is ($entry->get_value ('userAccountControl'),$useraccountcontrol,
		"  * userAccountControl is $useraccountcontrol");
        }
        if (defined $uidnumber){
            my $uidnumber_sys=$entry->get_value ('uidNumber');
            if ($uidnumber==-1){
                my $min=9999;
                my $max=3000000;
                my $uidnumber_ok=0;
                if($uidnumber_sys > $min and $uidnumber_sys < $max){
                    $uidnumber_ok=1;
                }
                is ($uidnumber_ok,1,
		    "  * uidNumber $uidnumber_sys between $max and $min");
            } else {
                is ($uidnumber_sys,$uidnumber,
		    "  * uidNumber is $uidnumber");
            }
        }
        if (defined $gidnumber){
            my $gidnumber_sys=$entry->get_value ('gidNumber');
            if ($gidnumber==-1){
                my $min=9999;
                my $max=3000000;
                my $gidnumber_ok=0;
                if($gidnumber_sys > $min and $gidnumber_sys < $max){
                    $gidnumber_ok=1;
                }
                is ($gidnumber_ok,1,
		    "  * gidNumber $gidnumber_sys between $max and $min");
            } else {
                is ($gidnumber_sys,$gidnumber,
		    "  * gidNumber is $gidnumber");
            }
        }
        if (defined $upn){
            is ($entry->get_value ('userPrincipalName'),$upn,
		"  * userPrincipalName is $upn");
        }
        if (defined $mail){
            is ($entry->get_value ('mail'),$mail,
		"  * mail is $mail");
        }
        if (defined $s_admin_class){
            is ($entry->get_value ('sophomorixAdminClass'),$s_admin_class,
		"  * sophomorixAdminClass is $s_admin_class");
        }
        if (defined $s_dns_nodename){
            is ($entry->get_value ('sophomorixDnsNodename'),$s_dns_nodename,
		"  * sophomorixDnsNodename is $s_dns_nodename");
        }
        if (defined $s_ip){
            is ($entry->get_value ('sophomorixComputerIP'),$s_ip,
		"  * sophomorixComputerIP is $s_ip");
        }
        if (defined $s_mac){
            is ($entry->get_value ('sophomorixComputerMAC'),$s_mac,
		"  * sophomorixComputerMAC is $s_mac");
        }
        if (defined $s_room){
            is ($entry->get_value ('sophomorixComputerRoom'),$s_room,
		"  * sophomorixComputerRoom is $s_room");
        }
        if (defined $s_exit_admin_class){
            is ($entry->get_value ('sophomorixExitAdminClass'),$s_exit_admin_class,
		"  * sophomorixExitAdminClass is $s_exit_admin_class");
        }
        if (defined $s_first_password){
            is ($entry->get_value ('sophomorixFirstPassword'),$s_first_password,
		"  * sophomorixFirstPassword is $s_first_password");
        }
        if (defined $s_firstname_ascii){
            is ($entry->get_value ('sophomorixFirstnameASCII'),$s_firstname_ascii,
		"  * sophomorixFirstnameASCII is $s_firstname_ascii");
        }
        if (defined $s_surname_ascii){
            is ($entry->get_value ('sophomorixSurnameASCII'),$s_surname_ascii,
		"  * sophomorixSurnameASCII is $s_surname_ascii");
        }
        if (defined $s_firstname_ini){
            is ($entry->get_value ('sophomorixFirstnameInitial'),$s_firstname_ini,
		"  * sophomorixFirstnameInitial is $s_firstname_ini");
        }
        if (defined $s_surname_ini){
            is ($entry->get_value ('sophomorixSurnameInitial'),$s_surname_ini,
		"  * sophomorixSurnameInitial is $s_surname_ini");
        }
        if (defined $s_usertoken){
            is ($entry->get_value ('sophomorixUserToken'),$s_usertoken,
		"  * sophomorixUserToken is $s_usertoken");
        }
        if (defined $s_birthdate){
            is ($entry->get_value ('sophomorixBirthdate'),$s_birthdate,
		"  * sophomorixBirthdate is $s_birthdate");
        }
        if (defined $s_role){
            is ($entry->get_value ('sophomorixRole'),$s_role,
		"  * sophomorixRole is $s_role");
        }
        if (defined $s_school_prefix){
            is ($entry->get_value ('sophomorixSchoolPrefix'),$s_school_prefix,
		"  * sophomorixSchoolPrefix is $s_school_prefix");
        }
        if (defined $s_school_name){
            is ($entry->get_value ('sophomorixSchoolname'),$s_school_name,
		"  * sophomorixSchoolname is $s_school_name");
        }
        if (defined $s_admin_file){
            is ($entry->get_value ('sophomorixAdminFile'),$s_admin_file,
		"  * sophomorixAdminFile is $s_admin_file");
        }
        if (defined $s_unid){
            is ($entry->get_value ('sophomorixUnid'),$s_unid,
		"  * sophomorixUnid is $s_unid");
        }
        if (defined $s_exammode){
            is ($entry->get_value ('sophomorixExamMode'),$s_exammode,
		"  * sophomorixExamMode is $s_exammode");
        } else {
            $s_exammode="---";
        }
        if (defined $s_type){
            is ($entry->get_value ('sophomorixType'),$s_type,
		"  * sophomorixType is $s_type");
        }
        if (defined $s_status){
            is ($entry->get_value ('sophomorixStatus'),$s_status,
		"  * sophomorixStatus is $s_status");
        }
        if (defined $s_mailquota){
            is ($entry->get_value ('sophomorixMailQuota'),$s_mailquota,
		"  * sophomorixMailQuota is $s_mailquota");
        }
        if (defined $s_mailquotacalc){
            if (defined $entry->get_value ('sophomorixMailQuotaCalculated')){
                is ($entry->get_value ('sophomorixMailQuotaCalculated'),$s_mailquotacalc,
  		    "  * sophomorixMailQuotaCalculated is $s_mailquotacalc");
            } else {
                # undef
                is ("undef",$s_mailquotacalc,
  		    "  * sophomorixMailQuotaCalculated is undef");
            }
        }
        if (defined $s_cloudquotacalc){
            is ($entry->get_value ('sophomorixCloudQuotaCalculated'),$s_cloudquotacalc,
  	        "  * sophomorixCloudQuotaCalculated is $s_cloudquotacalc");
        }
        if (defined $s_addmailquota){
            is ($entry->get_value ('sophomorixAddMailQuota'),$s_addmailquota,
		"  * sophomorixAddMailQuota is $s_addmailquota");
        }
        if (defined $s_mailalias){
            is ($entry->get_value ('sophomorixMailalias'),$s_mailalias,
		"  * sophomorixMailalias is $s_mailalias");
        }
        if (defined $s_maillist){
            is ($entry->get_value ('sophomorixMaillist'),$s_maillist,
		"  * sophomorixMaillist is $s_maillist");
        }
        if (defined $s_joinable){
            is ($entry->get_value ('sophomorixJoinable'),$s_joinable,
		"  * sophomorixJoinable is $s_joinable");
        }
        if (defined $s_maxmembers){
            is ($entry->get_value ('sophomorixMaxMembers'),$s_maxmembers,
		"  * sophomorixMaxMembers is $s_maxmembers");
        }
        if (defined $s_hidden){
            is ($entry->get_value ('sophomorixHidden'),$s_hidden,
		"  * sophomorixHidden is $s_hidden");
        }
        if (defined $s_creationdate){
            my $date=$entry->get_value ('sophomorixCreationDate');
            $test_date=substr($date,0,4); # first 4 chars
            # set string ok
            my $strg_ok="2018";
            if ($s_creationdate eq "exists"){
                # test first 4 digits
                is ($test_date,$strg_ok,
		    "  * CreationDate $date beginns with $strg_ok ");
            } else {
                is ($date,$s_creationdate,
   		    "  * CreationDate $date is $s_creationdate ");
#                $strg_ok=$s_creationdate;
#                is ($date,$strg_ok,
#   		    "  * CreationDate $date is $strg_ok ");
            }
        }
        if (defined $s_tolerationdate){
            my $date=$entry->get_value ('sophomorixTolerationDate');
            $test_date=substr($date,0,4); # first 3 chars
            # set string ok
            my $strg_ok="2018";
            if ($s_tolerationdate eq "exists"){
                # test first 4 digits
                is ($test_date,$strg_ok,
		    "  * TolerationDate $date beginns with $strg_ok ");
            } elsif ($s_tolerationdate eq "default") {
                $strg_ok=$DevelConf::default_date;
                is ($date,$strg_ok,
   		    "  * TolerationDate $date is $strg_ok ");
            } else {
                is ($date,$s_tolerationdate,
   		    "  * TolerationDate $date is $s_tolerationdate ");
            }
        }
        if (defined $s_deactivationdate){
            my $date=$entry->get_value ('sophomorixDeactivationDate');
            $test_date=substr($date,0,4); # first 4 chars
            # set string ok
            my $strg_ok="2018";
            if ($s_deactivationdate eq "exists"){
                # test first 3 digits
                is ($test_date,$strg_ok,
		    "  * DeactivationDate $date beginns with $strg_ok ");
            } elsif ($s_deactivationdate eq "default") {
                $strg_ok=$DevelConf::default_date;
                is ($date,$strg_ok,
   		    "  * DeactivationDate $date is $strg_ok ");
            } else {
                is ($date,$s_deactivationdate,
   		    "  * DeactivationDate $date is $s_deactivationdate ");
            }
        }
        if (defined $s_comment){
            is ($entry->get_value ('sophomorixComment'),$s_comment,
		"  * sophomorixComment is $s_comment");
        }
        if (defined $s_webui){
            is ($entry->get_value ('sophomorixWebuiDashboard'),$s_webui,
		"  * sophomorixWebuiDashboard is $s_webui");
        }

        ##################################################
        # servicePrincipalName
        if (defined $ser_pri_name){
            # get servicePrincipalName data into hash
            my %ser_pri=();
            my @data=$entry->get_value ('servicePrincipalName');
            my $spn_count=0;
            foreach my $item (@data){
                my ($spn,@rest)=split(/,/,$item);
                #$group=~s/^CN=//;
                #print "      * MemberOf: $group\n";
                $ser_pri{$spn}="seen";
                $spn_count++;
            }

            # test servicePrincipalName
            my $test_count=0;
            my @should_be_spn=split(/,/,$ser_pri_name);
            foreach my $should_be_spn (@should_be_spn){
                is (exists $ser_pri{$should_be_spn},1,
		    "  * Entry $sam_account HAS servicePrincipalName  $should_be_spn");
		$test_count++;
            } 
            is ($spn_count,$test_count,
                "  * $sam_account has $spn_count servicePrincipalName entries: $test_count tested");
        }


        ##################################################
        if (defined $s_addquota){
            &test_multivalue($s_addquota,"sophomorixAddQuota",$entry,$sam_account);
        }

        ##################################################
        if (defined $s_quota){
            &test_multivalue($s_quota,"sophomorixQuota",$entry,$sam_account);
        }

        ##################################################
        if (defined $s_user_permissions){
            &test_multivalue($s_user_permissions,"sophomorixWebuiPermissions",$entry,$sam_account);
        }

        ##################################################
        if (defined $s_user_permissions_calculated){
            &test_multivalue($s_user_permissions_calculated,"sophomorixWebuiPermissionsCalculated",$entry,$sam_account);
        }

        ##################################################
        if (defined $s_admins){
            &test_multivalue($s_admins,"sophomorixAdmins",$entry,$sam_account);
        }
        ##################################################
        if (defined $s_members){
            &test_multivalue($s_members,"sophomorixMembers",$entry,$sam_account);
        }
        ##################################################
        if (defined $s_admingroups){
            &test_multivalue($s_admingroups,"sophomorixAdminGroups",$entry,$sam_account);
        }
        ##################################################
        if (defined $s_membergroups){
            &test_multivalue($s_membergroups,"sophomorixMemberGroups",$entry,$sam_account);
        }
        ##################################################
        if (defined $s_sessions){
            &test_multivalue($s_sessions,"sophomorixSessions",$entry,$sam_account);
        }
        ##################################################
        if (defined $s_room_ips){
            &test_multivalue($s_room_ips,"sophomorixRoomIPs",$entry,$sam_account);
        }
        ##################################################
        if (defined $s_room_macs){
            &test_multivalue($s_room_macs,"sophomorixRoomMACs",$entry,$sam_account);
        }
        ##################################################
        if (defined $s_room_computers){
            &test_multivalue($s_room_computers,"sophomorixRoomComputers",$entry,$sam_account);
        }
        ##################################################
        if (defined $member){
            &test_multivalue($member,"member",$entry,$sam_account);
        }
        # ##################################################
        # # member
        # if (defined $member){
        #     # get member data into hash
        #     my %member=();
        #     my @data=$entry->get_value ('member');
        #     my $member_count=0;
        #     foreach my $item (@data){
        #         my ($entry,@rest)=split(/,/,$item);
        #         $entry=~s/^CN=//;
        #         #print "      * Member: $entry\n";
        #         $member{$entry}="seen";
        #         $member_count++;
        #     }
        #     # test membership
        #     my $test_count=0;
        #     my @should_be_member=split(/,/,$member);
        #     foreach my $should_be_member (@should_be_member){
        #         is (exists $member{$should_be_member},1,
	# 	    "  * Entry $should_be_member IS member of $sam_account");
	# 	$test_count++;
        #     } 

        #     # were all actual memberships tested
        #     is ($member_count,$test_count,
        #         "  * $sam_account has $member_count member entries: $test_count tested");
        # }


        ##################################################
        if (defined $member_of){
            &test_multivalue($member_of,"memberOf",$entry,$sam_account);
        }
        ##################################################
        # test login only if status is U,E,A,S,P,T,X
        # and exammode is off (sophomorixExamMode="---")
        if ($objectclass eq "user" and 
            ($s_status eq "U" or
             $s_status eq "E" or
             $s_status eq "A" or
             $s_status eq "S" or
             $s_status eq "P" or
             $s_status eq "T" or
             $s_status eq "X"
            ) 
           ){
            my $res=&Sophomorix::SophomorixSambaAD::AD_login_test($ldap,$root_dse,$dn);
            my $firstpass=$entry->get_value ('sophomorixFirstPassword');
            if ($firstpass eq "---" and -e "/etc/linuxmuster/.secret/$sam_account"){
                $firstpass = `cat /etc/linuxmuster/.secret/$sam_account`;
            }
            if ($res==2){
                #skip test
            } else {
                is ($res,0,"  * Login OK (pwd: $firstpass): $dn");
            }
	} elsif ($objectclass eq "user") {
            print "  * Login test skipped (Status: $s_status):\n";
            print "    $dn\n";
        } else {
            print "  * Login test skipped (objectClass: $objectclass):\n";
            print "    $dn\n";
        }

        # ##################################################
        # # membeOf
        # if (defined $member_of and $not_member_of){
        #     # get membership data into hash
        #     my %member_of=();
        #     my @data=$entry->get_value ('memberOf');
        #     my $membership_count=0;
        #     foreach my $item (@data){
        #         my ($group,@rest)=split(/,/,$item);
        #         $group=~s/^CN=//;
        #         #print "      * MemberOf: $group\n";
        #         $member_of{$group}="seen";
        #         $membership_count++;
        #     }

        #     # test membership
        #     my $test_count=0;
        #     my @should_be_member=split(/,/,$member_of);
        #     foreach my $should_be_member (@should_be_member){
        #         is (exists $member_of{$should_be_member},1,
	# 	    "  * Entry $sam_account IS member of $should_be_member");
	# 	$test_count++;
        #     } 

        #     # were all actual memberships tested
        #     is ($membership_count,$test_count,
        #         "  * $sam_account has $membership_count memberOf entries: $test_count tested");

        #     # test non-membership
        #     my @should_not_be_member=split(/,/,$not_member_of);
        #     foreach my $should_not_be_member (@should_not_be_member){
        #         is (exists $member_of{$should_not_be_member},'',
	# 	    "  * $sam_account IS NOT member of $should_not_be_member");
        #      } 
        # } elsif (defined $member_of or $not_member_of) {
        #      print "\nWARNING: Skipping memberOf and not_memberOf completely: Use BOTH in your test script!\n\n"
        # } else {
	#     #print "Not testing any membership on $cn\n";
        # }

    } else {
        print "\nWARNING: Skipping a lot of tests\n\n";
    }
}



sub test_multivalue {
    my ($should,$attr,$entry,$sam_account) = @_;
    # get actual attrs
    #print "ATTR: <$attr>\n";
    my %is=();
    my @data=$entry->get_value ($attr);
    my $count=0;
    foreach my $item (@data){
        my ($ent,@rest)=split(/,/,$item);
            $ent=~s/^CN=//;
        #print "   * Item is: <$ent> <$item>\n";
        if ($attr eq "memberOf" or $attr eq "member"){
            $is{$ent}="seen";
        } else {
            $is{$item}="seen";
        }
        $count++;
    }

    #foreach my $item ( keys %is ) {
    #    print " Hash: <$item> <$is{$item}>\n";
    #}

    # compare with should attrs
    my $test_count=0;
    my @should_be=split(/\|/,$should);
    foreach my $should_be (@should_be){
        is (exists $is{$should_be},1,
	    "  * Entry <$should_be> IS in multivalue attribute $attr of $sam_account");
        if (not exists $is{$should_be}){
            print "   Found the following $count entries in AD:\n";
   	    foreach my $entry (@data){
                print "      $entry\n";
            }
        }
	$test_count++;
    } 
    # were all actual memberships tested
    is ($count,$test_count,
        "  * $sam_account has $count entries in multivalue attribute $attr: $test_count tested");
    if (not $count==$test_count){
        print "   Found the following $count entries in AD:\n";
	foreach my $entry (@data){
            print "      $entry\n";
        }
        print "   Expected the following $test_count entries in the test:\n";
	foreach my $entry (@should_be){
            print "      $entry\n";
        }
    }
}



############################################################
# fs
############################################################
sub start_fs_test {
    my ($ref_fs_test_result) = @_;
    my $oldnum;
    if (defined $ref_fs_test_result->{'testnumber'}){
        $oldnum=$ref_fs_test_result->{'testnumber'};
        # check if test was endet
        if ($ref_fs_test_result->{'testnumber'} eq $ref_fs_test_result->{'closed'}){
            # ok
        } else {
            print "\nERROR: $ref_fs_test_result->{'testnumber'} was not closed/ended\n\n";
            exit;
        }
    } else {
        $oldnum=0;
    }
    my $newnum=$oldnum+1;
    %{$ref_fs_test_result} = (); 
    $ref_fs_test_result->{'testnumber'}=$newnum;
    #print "fs_test_result_hash at beginning:\n";
    print "########## Ready for fs_test $ref_fs_test_result->{'testnumber'}  ##########\n";
    $ref_fs_test_result->{'ACL_count'}=0;
    $ref_fs_test_result->{'NTACL_count'}=0;
    print Dumper ($ref_fs_test_result);
}



sub end_fs_test {
    my ($ref_fs_test_result) = @_;
    my $count=1;
    print "########## fs_test $ref_fs_test_result->{'testnumber'} summary for $ref_fs_test_result->{'finddir'} ##########\n";
    foreach my $dir (@{ $ref_fs_test_result->{'directory_tree_test'} }){
        if (exists $ref_fs_test_result->{'NTACL_lookup'}{$dir}){
            #print "  NTACL tested:  $dir\n";
        } else {
            print "  $count: No NTACL-test: $dir\n";
            $count++;
        }
    }
    $ref_fs_test_result->{'closed'}=$ref_fs_test_result->{'testnumber'};
    # show all
    #print Dumper ($ref_fs_test_result);
}



############################################################
# directory_tree
############################################################
sub directory_tree_test {
    # fist option: wher to search for the dirs
    # 2nd, ... the dirs to test
    my ($finddir,$ref_fs_test_result,@dirlist) = @_;
    # remember finddir
    $ref_fs_test_result->{'finddir'}=$finddir;

    my %dir_hash=();
    my $string=`find $finddir`;
    my @dirs=split(/\n/,$string);
    foreach my $dir (@dirs){
        my $filename = basename($dir);
        if ($filename eq "aquota.user" or
            $filename eq "aquota.group" or
            $filename eq "lost+found"
	    ){
            print "Skipping test for file $filename\n";
            next;
        }
        $dir_hash{$dir}="seen";
	#print "<$dir>\n";
    }
    print "****** Testing directory tree $finddir\n";
    foreach my $dir (@dirlist){
        # remember in list
        push @{ $ref_fs_test_result->{'directory_tree_test'} }, $dir;

        # remember in hash
        if (exists $ref_fs_test_result->{'directory_tree_test_lookup'}{$dir}){
            print "\nERROR: $dir tested twice (Fix your &directory_tree_test)\n\n";
            exit;
        }else {
            $ref_fs_test_result->{'directory_tree_test_lookup'}{$dir}=1;
        }

        # test
        is (exists $dir_hash{$dir} ,1, "* Existing: $dir");
        if (exists $dir_hash{$dir}){
            delete $dir_hash{$dir};
        }
    }
   
    # print the untested that exist
    my @untested=();
    foreach my $dir ( keys %dir_hash ) {
        push @untested, $dir;
    }
    @untested = sort @untested;
    foreach my $dir (@untested){
        is (0,1, "* Existing, but not tested: $dir");
    } 
}



############################################################
# ACL
############################################################
sub ACL_test {
    # tests ACL, not NTACL
    my ($abs_path,$filetype,$ref_fs_test_result,@test)=@_;
    my $testnum=$ref_fs_test_result->{'ACL_count'}+1;
    $ref_fs_test_result->{'ACL_count'}=$testnum;

    my $command="getfacl $abs_path 2> /dev/null";
    print "****** Run $ref_fs_test_result->{'testnumber'} ACL-test $testnum: $command\n";
    # remember in list
    push @{ $ref_fs_test_result->{'ACL_test'} }, $abs_path;
    # remember in hash
    if (exists $ref_fs_test_result->{'ACL_lookup'}{$abs_path}){
        print "\nERROR: $abs_path tested twice (Fix your set of NTACL tests)\n\n";
        exit;
    } else {
        $ref_fs_test_result->{'ACL_lookup'}{$abs_path}=1;
    }

    my $string=`getfacl $abs_path 2> /dev/null`;
    my @lines_raw=split(/\n/,$string);
    my @fs=();
    foreach my $line (@lines_raw){
        if ($line=~m/^# file/){
            next;
        }
        push @fs, $line;
    }
    # starting tests
    my $exists=0;
    # existence and type
    if ($filetype eq "f"){
        if (-f $abs_path){
            $exists=1;
        }
        is ($exists,1,"* File exists: $abs_path");
    } elsif ($filetype eq "d"){
        if (-d $abs_path){
            $exists=1;
        }
        is ($exists,1,"* Directory exists: $abs_path"); 
    }
    # ACL lines
    is ($#test,$#fs,"* ACL contains correct number of entries(lines)");    
    for (my $i=0;$i<=$#test;$i++){
        my $line_num=$i+1;
        is ($test[$i],$fs[$i],"* ACL entry $line_num is $test[$i]");
    }
} 



############################################################
# smbcquotas
############################################################
sub smbcquotas_test {
    my ($user,$share,$quota_expected,$root_dns,$smb_pass)=@_;
    my $smbcquotas_command="/usr/bin/smbcquotas -mNT1 --debuglevel=0 -U administrator%'".$smb_pass."'".
                           " --user ".$user." //".$root_dns."/".$share;
    #print "$smbcquotas_command\n";
    my $stdout=`$smbcquotas_command`;
    my ($full_user,$colon,$used,$soft_limit,$hard_limit)=split(/\s+/,$stdout);
    my ($unused,$quota_user)=split(/\\/,$full_user);
    $used=~s/\/$//;
    $hard_limit=~s/\/$//;
    if ($hard_limit eq "NO" or $hard_limit eq "LIMIT"){
        $hard_limit="NO LIMIT";
    }
    if ($hard_limit=~m/[0-9]/) { 
        # a number consisting of 0-9
        $hard_limit_mib=$hard_limit/1024/1024;        
    } else {
        # not a number
        $hard_limit_mib=$hard_limit;
    }
    #print "QUOTA COMMAND RETURNED: $quota_user has used $used of $hard_limit ($hard_limit_mib)\n";
    is ($hard_limit_mib,$quota_expected, "* Quota of $user is $quota_expected MiB (was: $hard_limit_mib MiB)");  
}



############################################################
# NTACL
############################################################
sub NTACL_test {
    # tests ACL, not NTACL
    my ($share,$smb_rel,$root_dns,$smb_pass,$ref_fs_test_result,@test)=@_;
    my $testnum=$ref_fs_test_result->{'NTACL_count'}+1;
    $ref_fs_test_result->{'NTACL_count'}=$testnum;

    my $unc_path="//".$root_dns."/".$share;

    my $abs_path_linux;
    if ($share eq "global" or $share eq "linuxmuster-global" or $share eq "lmn-global" ){
        $abs_path_linux="/srv/samba/global".$smb_rel;
        $abs_path_linux=~s/\/$//; # remove trailing /
    } else {
        $abs_path_linux="/srv/samba/schools/".$share.$smb_rel;
        $abs_path_linux=~s/\/$//; # remove trailing /
    }
    my $command="/usr/bin/smbcacls -U administrator"."%".$smb_pass." ".$unc_path." ".$smb_rel;
    print "****** Run $ref_fs_test_result->{'testnumber'} NTACL-test $testnum: $command\n";
    # print "****** $share $smb_rel $abs_path_linux\n";
    # remember in list
    push @{ $ref_fs_test_result->{'NTACL_test'} }, $abs_path_linux;
    # remember in hash
    if (exists $ref_fs_test_result->{'NTACL_lookup'}{$abs_path_linux}){
        print "\nERROR: $abs_path_linux tested twice (Fix your set of NTACL tests)\n\n";
        exit;
    } else {
        $ref_fs_test_result->{'NTACL_lookup'}{$abs_path_linux}=1;
    }

    my $string=`$command`;
    my %result=();

    # what is actually seen
    my @lines=split(/\n/,$string);

    my $count_test=$#test+1;
    my $count_test_success=0; # should be $count_test if 100% match
    my $count_lines=$#lines+1;
 
    is ($count_lines,$count_test, "* NTACL contains: $count_test lines");   
    foreach my $testline (@test){
        my $ok=0;
        foreach my $line (@lines){
            if ($testline eq $line){
                $ok=1; 
                $count_test_success++; 
                $result{$line}="ok";
                last;
            }
        }
        is ($ok,1,"* NTACL contains: $testline");
    }
    # if not 100% ok print what is and what shoul be
    if ($count_test==$count_test_success){
        #ok
    } else {
        foreach my $line (@test){
            if (exists $result{$line}){
                print "   Expected:(ok) -->$line<--\n";
            } else {
                print "   Expected:(??) -->$line<--\n";
            }
        }
        foreach my $line (@lines){
            if (exists $result{$line}){
                print "   Got:(ok)      -->$line<--\n";
            } else {
                print "   Got:(??)      -->$line<--\n";
            }
        }
    }
} 



sub file_test_lines {
    # abs path to file
    # line number -1=skip test
    # list of lines that mus be in the file (one test each)
    my ($abs,$is_line_num,@lines)=@_;
    my $exists=0;
    my %hit=();
    my %hit_count=();

    # existence
    if (-e $abs){
        $exists=1;
    }
    is ($exists,1,"* $abs exists");
    if ($exists==0){
        return;
    }
   
    # read lines
    my $line_num=0;
    open(FILE,"$abs") || die "Cannot open $abs \n";
    while(<FILE>){
        $line_num++;
        chomp;
        #print;
        foreach my $grep (@lines){
            if (m/$grep/){
                #print "$_ contains $grep\n";
                $hit{$grep}=$_;
                if (not exists $hit_count{$grep}){
                    $hit_count{$grep}=1;
                } else {
                    $hit_count{$grep}=$hit_count{$grep}+1;
                }
            }
        }
    }
    close(FILE);

    # line num test
    is ($line_num,$is_line_num,"  * File has $is_line_num lines");

    # grep tests
    foreach my $grep (@lines){
        my $seen=0;
        if (exists $hit{$grep}){
            $seen=1;
            $line=$hit{$grep};
        } else {
            $line="... no match ...";
        }
          is ($seen,1,"  * >$grep< in >$line<");
          is ($hit_count{$grep},1,"  * >$grep< found only once");
    }
}



sub file_test_chars {
    # abs path to file
    # char number
    my ($abs,$is_char_num)=@_;

    if (-e $abs){
        $exists=1;
    }
    is ($exists,1,"* $abs exists");
    if ($exists==0){
        return;
    }
    my $command="cat $abs | wc -c";
    print "\n";
    print "######################################################################\n";
    print "$command\n";
    print "######################################################################\n";
    my $count=`$command`;
    chomp($count);
    is ($count,$is_char_num,"  * $count chars in file $abs")
}



sub run_command {
    my ($command) = @_;
    my $return_value=666;
    print "\n";
    print "######################################################################\n";
    print "$command\n";
    print "######################################################################\n";
    $return_value=system("$command");
    print "######################################################################\n";
    return $return_value;
}



sub cat_wcl_test {
    # $abs: abs path to file
    # $grep: what to grep for in that file
    # $expected result (number of lines)
    my ($abs,$grep,$expect) = @_;
    my $command="cat ".$abs." | grep \"".$grep."\" | wc -l";
    print "\n";
    print "######################################################################\n";
    print "$command\n";
    print "######################################################################\n";
    my $count=`$command`;
    chomp($count);
    is ($count,$expect,"  * $count results for \"$grep\" in $abs");
}



sub diff_acl_snapshot {
    my ($file,$snapshot1,$snapshot2)=@_;
    print "Running diff command:\n";
    my $command="/usr/bin/diff /var/lib/sophomorix/sophomrix-repair/".$snapshot1."/".$file.
                             " /var/lib/sophomorix/sophomrix-repair/".$snapshot2."/".$file;

    print "$command\n";
    my $stdout=`$command`;
    my $return=${^CHILD_ERROR_NATIVE}; # return of value of last command

    # Test for return Value
    is ($return,0,"  * Diff returned 0 (file is identical)");

    # Test output
    my $output_lines;
    if ($stdout eq ""){
        $output_lines=0;
    } else {
        my (@lines)=split(/\n/,$stdout);
        $output_lines=$#lines+1;
    }
    is ($output_lines,0,"  * Diff output line number is 0 (file is identical)");

    # display output nicely when not 0 lines
    if ($output_lines>0){
        print "####### diff output (start) #####################################################\n";
        print $stdout;
        print "####### diff output (end)   #####################################################\n";
    }

}



# END OF FILE
# Return true=1
1;
