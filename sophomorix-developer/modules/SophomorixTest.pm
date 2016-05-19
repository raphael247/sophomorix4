#!/usr/bin/perl -w
# This perl module SophomorixTest is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linuxmuster.net

package Sophomorix::SophomorixTest;
require Exporter;
#use File::Basename;
#use Time::Local;
#use Time::localtime;
#use Quota;
#use Sys::Filesystem ();
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
            AD_test_object
            AD_workstations_any
            AD_examaccounts_any
            run_command
            );


sub AD_workstations_any {
    my ($ldap,$root_dse) = @_;
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => '(&(objectClass=computer)(sophomorixRole=computer))',
                   attrs => ['sAMAccountName']
                         );
    my $max_user = $mesg->count; 
    is ($max_user,0,"  * All workstations are deleted");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        print "   * ",$entry->get_value('sAMAccountName'),"\n";
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



sub AD_object_nonexist {
    my ($ldap,$root_dse,$type,$name) = @_;
    # type: group, user, ...
    # check if object exists
    # (&(objectclass=user)(cn=pete)
    # (&(objectclass=group)(cn=7a)
    my $filter="(&(objectclass=".$type.") (cn=".$name."))"; 
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
    my $sam_account =$arg_ref->{sAMAccountname};
    my $account_expires =$arg_ref->{accountExpires};
    my $dns_hostname =$arg_ref->{dNSHostName};
    my $ser_pri_name =$arg_ref->{servicePrincipalName};
    my $sn =$arg_ref->{sn};
    my $description =$arg_ref->{description};

    # sophomorix user
    my $s_admin_class = $arg_ref->{sophomorixAdminClass};
    my $s_exit_admin_class = $arg_ref->{sophomorixExitAdminClass};
    my $s_first_password = $arg_ref->{sophomorixFirstPassword};
    my $s_firstname_ascii = $arg_ref->{sophomorixFirstnameASCII};
    my $s_surname_ascii = $arg_ref->{sophomorixSurnameASCII};
    my $s_role = $arg_ref->{sophomorixRole};
    my $s_school_prefix = $arg_ref->{sophomorixSchoolPrefix};
    my $s_school_name = $arg_ref->{sophomorixSchoolname};
    my $s_creationdate = $arg_ref->{sophomorixCreationDate};
    my $s_tolerationdate = $arg_ref->{sophomorixTolerationDate};
    my $s_deactivationdate = $arg_ref->{sophomorixDeactivationDate};

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

    my $member = $arg_ref->{member};
    my $member_of = $arg_ref->{memberOf};
    #my $not_member_of = $arg_ref->{not_memberOf};

    my $filter="(cn=*)";
    my $mesg = $ldap->search(
                      base   => $dn,
                      scope => 'base',
                      filter => $filter,
                            );
    #print Dumper(\$mesg);
    my ($entry,@entries) = $mesg->entries;
    my $count = $mesg->count;

    # Testing object existence
    is ($count,1, "*** Found 1 Object: $dn");
   
    if ($count==1){
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
        if (defined $upn){
            is ($entry->get_value ('userPrincipalName'),$upn,
		"  * userPrincipalName is $upn");
        }
        if (defined $s_admin_class){
            is ($entry->get_value ('sophomorixAdminClass'),$s_admin_class,
		"  * sophomorixAdminClass is $s_admin_class");
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
        if (defined $s_type){
            is ($entry->get_value ('sophomorixType'),$s_type,
		"  * sophomorixType is $s_type");
        }
        if (defined $s_status){
            is ($entry->get_value ('sophomorixStatus'),$s_status,
		"  * sophomorixStatus is $s_status");
        }
        if (defined $s_addquota){
            is ($entry->get_value ('sophomorixAddQuota'),$s_addquota,
		"  * sophomorixAddQuota is $s_addquota");
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
        if (defined $s_creationdate){
            my $strg_ok="201";
            my $date=$entry->get_value ('sophomorixCreationDate');
            $test_date=substr($date,0,3);
            is ($test_date,$strg_ok,
		"  * $date beginns with $strg_ok ");
        }
        if (defined $s_tolerationdate){
            my $strg_ok="201";
            my $date=$entry->get_value ('sophomorixTolerationDate');
            $test_date=substr($date,0,3);
            is ($test_date,$strg_ok,
		"  * $date beginns with $strg_ok ");
        }
        if (defined $s_deactivationdate){
            my $strg_ok="201";
            my $date=$entry->get_value ('sophomorixDeactivationDate');
            $test_date=substr($date,0,3);
            is ($test_date,$strg_ok,
		"  * $date beginns with $strg_ok ");
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
    my %is=();
    my @data=$entry->get_value ($attr);
    my $count=0;
    foreach my $item (@data){
        my ($ent,@rest)=split(/,/,$item);
        $ent=~s/^CN=//;
        #print "      * Datum: $ent\n";
        $is{$ent}="seen";
        $count++;
    }
    # compare with should attrs
    my $test_count=0;
    my @should_be=split(/,/,$should);
    foreach my $should_be (@should_be){
        is (exists $is{$should_be},1,
	    "  * Entry $should_be IS in multivalue attribute $attr of $sam_account");
	$test_count++;
    } 
    # were all actual memberships tested
    is ($count,$test_count,
        "  * $sam_account has $count entries in multivalue attribute $attr: $test_count tested");
}


sub run_command {
    my ($command) = @_;
    print "\n";
    print "######################################################################\n";
    print "$command\n";
    print "######################################################################\n";
    system("$command");
    print "######################################################################\n";
}


# END OF FILE
# Return true=1
1;
