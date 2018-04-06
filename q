[1mdiff --git a/sophomorix-samba/modules/SophomorixBase.pm b/sophomorix-samba/modules/SophomorixBase.pm[m
[1mindex 146227d..31fa172 100644[m
[1m--- a/sophomorix-samba/modules/SophomorixBase.pm[m
[1m+++ b/sophomorix-samba/modules/SophomorixBase.pm[m
[36m@@ -312,6 +312,8 @@[m [msub json_dump {[m
             &_console_print_shares($hash_ref,$object_name,$log_level,$ref_sophomorix_config)[m
         } elsif ($jsoninfo eq "UI"){[m
             &_console_print_ui($hash_ref,$object_name,$log_level,$ref_sophomorix_config)[m
[32m+[m[32m        } elsif ($jsoninfo eq "SCHEMA_ATTRIBUTE"){[m
[32m+[m[32m            &_console_print_schema_attribute($hash_ref,$object_name,$log_level,$ref_sophomorix_config)[m
         }[m
     } elsif ($json==1){[m
         # pretty output[m
[36m@@ -708,6 +710,46 @@[m [msub _console_print_projects_overview {[m
 [m
 [m
 [m
[32m+[m[32msub _console_print_schema_attribute {[m
[32m+[m[32m    my ($ref_schema,$attribute,$log_level,$ref_sophomorix_config)=@_;[m
[32m+[m[32m    my $line1="#####################################################################\n";[m
[32m+[m[32m    my $line= "---------------------------------------------------------------------\n";[m
[32m+[m
[32m+[m[32m    if (exists $ref_schema->{'LDAPDisplayName'}{$attribute}){[m
[32m+[m[32m        print "\n";[m
[32m+[m[32m        print $line1;[m
[32m+[m[32m        print "Schema attribute $attribute:\n";[m
[32m+[m[32m        print "DN=$ref_schema->{'LDAPDisplayName'}{$attribute}{'DN'}\n";[m
[32m+[m[32m        print $line1;[m
[32m+[m
[32m+[m[32m        # create an ascibetical list of keys[m
[32m+[m[32m        my @list=();[m
[32m+[m[32m        foreach my $key (keys %{ $ref_schema->{'LDAPDisplayName'}{$attribute} }) {[m
[32m+[m[32m            if ($key eq "DN"){[m
[32m+[m[32m            } else {[m
[32m+[m[32m                push @list, $key;[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m[32m        @list = sort @list;[m
[32m+[m
[32m+[m[32m        # display the keys[m
[32m+[m[32m        foreach my $item (@list){[m
[32m+[m[32m            foreach $value (@{ $ref_schema->{'LDAPDisplayName'}{$attribute}{$item} }){[m
[32m+[m[32m                my $camel_case=$ref_schema->{'LOOKUP'}{'CamelCase'}{$item};[m
[32m+[m[32m                #printf "%29s: %-40s\n",$item,$value; # all lowercase[m
[32m+[m[32m                printf "%29s: %-40s\n",$camel_case,$value; # camelcase[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m[32m        print $line;[m
[32m+[m[32m    } else {[m
[32m+[m[32m        print "\nAttribute $attribute not found\n";[m
[32m+[m[32m        print "\nFor a list of all attributes use:\n";[m
[32m+[m[32m        print "   sophomorix-samba --show-all-attributes\n\n";[m
[32m+[m[32m    }[m
[32m+[m[32m}[m
[32m+[m
[32m+[m
[32m+[m
 sub _console_print_users_overview {[m
     my ($ref_users_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;[m
     my @school_list;[m
[1mdiff --git a/sophomorix-samba/modules/SophomorixSambaAD.pm b/sophomorix-samba/modules/SophomorixSambaAD.pm[m
[1mindex 4c719c2..45767a0 100644[m
[1m--- a/sophomorix-samba/modules/SophomorixSambaAD.pm[m
[1m+++ b/sophomorix-samba/modules/SophomorixSambaAD.pm[m
[36m@@ -4825,22 +4825,82 @@[m [msub AD_get_schema {[m
                                    );[m
     my $max = $mesg->count;[m
     my $ref_mesg = $mesg->as_struct; # result in Datenstruktur darstellen[m
[32m+[m[32m    print Dumper \%mesg;[m
     # set total counter[m
     $schema{'RESULT'}{'LDAPDisplayName'}{'TOTAL'}{'COUNT'}=$max;[m
     print "$max attributes found with LDAPDisplayName\n";[m
     for( my $index = 0 ; $index < $max ; $index++) {[m
[32m+[m[32m        my $is_sophomorix=0; # from sophomorix schema or not[m
         my $entry = $mesg->entry($index); [m
         my $dn=$entry->dn();[m
         my $name=$entry->get_value('LDAPDisplayName');[m
[31m-        #print "   * $name -> $dn\n";[m
         $schema{'LDAPDisplayName'}{$name}{'DN'}=$dn;[m
         $schema{'LOOKUP'}{'LDAPDisplayName_by_DN'}{$dn}=$name;[m
[32m+[m
[32m+[m[32m        # save Camelcase names[m[41m [m
[32m+[m[32m        my $lowercase_name=$name;[m
[32m+[m[32m        $lowercase_name=~tr/A-Z/a-z/; # make lowercase[m
[32m+[m[32m        $schema{'LOOKUP'}{'CamelCase'}{$lowercase_name}=$name;[m
[32m+[m
[32m+[m[32m        # $ype is classSchema or attributeSchema[m
[32m+[m[32m        my $type="NONE";[m
[32m+[m[32m        foreach my $objectclass (@{ $ref_mesg->{$dn}{'objectclass'} }) { # objectclass MUST be lowercase(NET::LDAP hash)[m
[32m+[m[32m            if ($objectclass eq "classSchema" ){[m
[32m+[m[32m                $type=$objectclass;[m
[32m+[m[32m            } elsif ($objectclass eq "attributeSchema"){[m
[32m+[m[32m                $type=$objectclass;[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
         foreach my $attr (keys %{ $ref_mesg->{$dn} }) {[m
[31m-            print "    attr: $attr -> $ref_mesg->{$dn}{$attr}\n";[m
[32m+[m[32m            # save it in returned data structure[m
             $schema{'LDAPDisplayName'}{$name}{$attr}=$ref_mesg->{$dn}{$attr};[m
[32m+[m[32m            # test if its a sophomorix attribute[m
[32m+[m[32m            if ($attr eq "attributeid"){[m
[32m+[m[32m                my $attribute_id=$ref_mesg->{$dn}{$attr}[0];[m
[32m+[m[32m                # 1.3.6.1.4.1.47512     is linuxmuster.net[m
[32m+[m[32m                # 1.3.6.1.4.1.47512.1   is the sophomorix subspace[m
[32m+[m[32m                if ( $attribute_id=~m/^1.3.6.1.4.1.47512.1/ ){[m
[32m+[m[32m                    $is_sophomorix=1;[m
[32m+[m[32m                }[m[41m [m
[32m+[m[32m            }[m
         }[m
 [m
[31m-    }[m
[32m+[m[32m        # save attribute in LISTS[m
[32m+[m[32m        push @{ $schema{'LISTS'}{'ALL_ATTRS'}{$type}{'LDAPDisplayName'} }, $name;[m
[32m+[m[32m        if ($is_sophomorix==1){[m
[32m+[m[32m            push @{ $schema{'LISTS'}{'SOPHOMORIX_ATTRS'}{$type}{'LDAPDisplayName'} }, $name;[m
[32m+[m[32m        } else {[m
[32m+[m[32m            push @{ $schema{'LISTS'}{'NON_SOPHOMORIX_ATTRS'}{$type}{'LDAPDisplayName'} }, $name;[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    # sort some lists[m
[32m+[m[32m    @{ $schema{'LISTS'}{'ALL_ATTRS'}{$type}{'LDAPDisplayName'} } =[m[41m [m
[32m+[m[32m        sort @{ $schema{'LISTS'}{'ALL_ATTRS'}{$type}{'LDAPDisplayName'} };[m
[32m+[m[32m    @{ $schema{'LISTS'}{'SOPHOMORIX_ATTRS'}{$type}{'LDAPDisplayName'} } =[m[41m [m
[32m+[m[32m        sort @{ $schema{'LISTS'}{'SOPHOMORIX_ATTRS'}{$type}{'LDAPDisplayName'} };[m
[32m+[m[32m    @{ $schema{'LISTS'}{'NON_SOPHOMORIX_ATTRS'}{$type}{'LDAPDisplayName'} } =[m[41m [m
[32m+[m[32m        sort @{ $schema{'LISTS'}{'NON_SOPHOMORIX_ATTRS'}{$type}{'LDAPDisplayName'} };[m
[32m+[m
[32m+[m[32m    # counters[m
[32m+[m[32m    # all[m
[32m+[m[32m    $schema{'RESULT'}{'LDAPDisplayName'}{'ALL_ATTRS'}{'attributeSchema'}{'COUNT'}=[m
[32m+[m[32m        $#{ $schema{'LISTS'}{'ALL_ATTRS'}{'attributeSchema'}{'LDAPDisplayName'} }+1;[m
[32m+[m[32m    $schema{'RESULT'}{'LDAPDisplayName'}{'ALL_ATTRS'}{'classSchema'}{'COUNT'}=[m
[32m+[m[32m        $#{ $schema{'LISTS'}{'ALL_ATTRS'}{'classSchema'}{'LDAPDisplayName'} }+1;[m
[32m+[m
[32m+[m[32m    # non-sophomorix[m
[32m+[m[32m    $schema{'RESULT'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{'attributeSchema'}{'COUNT'}=[m
[32m+[m[32m        $#{ $schema{'LISTS'}{'NON_SOPHOMORIX_ATTRS'}{'attributeSchema'}{'LDAPDisplayName'} }+1;[m
[32m+[m[32m    $schema{'RESULT'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{'classSchema'}{'COUNT'}=[m
[32m+[m[32m        $#{ $schema{'LISTS'}{'NON_SOPHOMORIX_ATTRS'}{'classSchema'}{'LDAPDisplayName'} }+1;[m
[32m+[m
[32m+[m[32m    # sophomorix[m
[32m+[m[32m    $schema{'RESULT'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{'attributeSchema'}{'COUNT'}=[m
[32m+[m[32m        $#{ $schema{'LISTS'}{'SOPHOMORIX_ATTRS'}{'attributeSchema'}{'LDAPDisplayName'} }+1;[m
[32m+[m[32m    $schema{'RESULT'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{'classSchema'}{'COUNT'}=[m
[32m+[m[32m        $#{ $schema{'LISTS'}{'SOPHOMORIX_ATTRS'}{'classSchema'}{'LDAPDisplayName'} }+1;[m
     &Sophomorix::SophomorixBase::print_title("Query AD for schema (end)");[m
     return \%schema;[m
 }[m
[1mdiff --git a/sophomorix-samba/scripts/sophomorix-samba b/sophomorix-samba/scripts/sophomorix-samba[m
[1mindex a3e06f8..b263877 100755[m
[1m--- a/sophomorix-samba/scripts/sophomorix-samba[m
[1m+++ b/sophomorix-samba/scripts/sophomorix-samba[m
[36m@@ -66,6 +66,8 @@[m [mmy $start=0;[m
 [m
 my $edit_searchflags="";[m
 my $editor="emacs";[m
[32m+[m[32mmy $show_all_attributes=0;[m
[32m+[m[32mmy $show_sophomorix_attributes=0;[m
 my $show_attribute="";[m
 [m
 my $samba_private="/var/lib/samba/private";[m
[36m@@ -81,6 +83,8 @@[m [mmy $testopt=GetOptions([m
            "restore-samba=s" => \$restore_samba,[m
            "edit-searchflags=s" => \$edit_searchflags,[m
            "show-attribute=s" => \$show_attribute,[m
[32m+[m[32m           "show-all-attributes" => \$show_all_attributes,[m
[32m+[m[32m           "show-sophomorix-attributes" => \$show_sophomorix_attributes,[m
            "editor=s" => \$editor,[m
            "schema-load" => \$schema_load,[m
            "start" => \$start,[m
[36m@@ -275,6 +279,36 @@[m [mif ($edit_searchflags ne ""){[m
 [m
 }[m
 [m
[32m+[m
[32m+[m
[32m+[m[32m# --show-all-attributes[m
[32m+[m[32mif ($show_all_attributes==1){[m
[32m+[m[32m    my ($ref_schema) = &AD_get_schema({ldap=>$ldap,[m
[32m+[m[32m                                       root_dse=>$root_dse,[m
[32m+[m[32m                                       root_dns=>$root_dns,[m
[32m+[m[32m                                       sophomorix_config=>\%sophomorix_config,[m
[32m+[m[32m                                      });[m
[32m+[m[32m    foreach my $attr ( @{ $ref_schema->{'LISTS'}{'ALL_ATTRS'}{'LDAPDisplayName'} } ) {[m
[32m+[m[32m        print "   * $attr\n";[m
[32m+[m[32m    }[m[41m [m
[32m+[m[32m}[m[41m [m
[32m+[m
[32m+[m
[32m+[m
[32m+[m[32m# --show-sophomorix-attributes[m
[32m+[m[32mif ($show_sophomorix_attributes==1){[m
[32m+[m[32m    my ($ref_schema) = &AD_get_schema({ldap=>$ldap,[m
[32m+[m[32m                                       root_dse=>$root_dse,[m
[32m+[m[32m                                       root_dns=>$root_dns,[m
[32m+[m[32m                                       sophomorix_config=>\%sophomorix_config,[m
[32m+[m[32m                                      });[m
[32m+[m[32m    foreach my $attr ( @{ $ref_schema->{'LISTS'}{'SOPHOMORIX_ATTRS'}{'LDAPDisplayName'} } ) {[m
[32m+[m[32m        print "   * $attr\n";[m
[32m+[m[32m    }[m[41m [m
[32m+[m[32m}[m[41m [m
[32m+[m
[32m+[m
[32m+[m
 # --show-attribute <LDAPDisplayName>[m
 if ($show_attribute ne ""){[m
     my ($ref_schema) = &AD_get_schema({ldap=>$ldap,[m
[36m@@ -282,11 +316,12 @@[m [mif ($show_attribute ne ""){[m
                                        root_dns=>$root_dns,[m
                                        sophomorix_config=>\%sophomorix_config,[m
                                       });[m
[31m-    my $jsoninfo="SCHEMA_FULL";[m
[32m+[m[32m    my $jsoninfo="SCHEMA_ATTRIBUTE";[m
     my $jsoncomment="The AD Schema";[m
     &json_dump({json => $json,[m
                 jsoninfo => $jsoninfo,[m
                 jsoncomment => $jsoncomment,[m
[32m+[m[32m                object_name => $show_attribute,[m
                 log_level => $Conf::log_level,[m
                 hash_ref => $ref_schema,[m
                 sophomorix_config => \%sophomorix_config,[m
