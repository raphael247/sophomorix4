#!/usr/bin/perl -w
use strict;
use Getopt::Long;
Getopt::Long::Configure ("bundling");

my $script="";
my $option="";

my $testopt=GetOptions(
           "script|s=s" => \$script,
           "option|o=s" => \$option,
          );


my @scriptlist=();

if ($option ne ""){
    $option="-".$option;
}



if ($script eq "r"){
    &reset_smb();
} elsif ($script eq "all"){
    @scriptlist=("sophomorix-test-1 $option ", 
                 "sophomorix-test-2 $option ", 
                 "sophomorix-test-3 $option ", 
                 "sophomorix-test-4 $option ", 
                 "sophomorix-test-5 $option ", 
                 "sophomorix-test-workflow $option ");
} elsif ($script eq "1"){
    @scriptlist=("sophomorix-test-1 $option ");
} elsif ($script eq "2"){
    @scriptlist=("sophomorix-test-2 $option ");
} elsif ($script eq "3"){
    @scriptlist=("sophomorix-test-3 $option ");
} elsif ($script eq "4"){
    @scriptlist=("sophomorix-test-4 $option ");
} elsif ($script eq "5"){
    @scriptlist=("sophomorix-test-5 $option ");
} elsif ($script eq "w"){
    @scriptlist=("sophomorix-test-workflow $option ");
}



# run the scripts
foreach my $script (@scriptlist){
    my (@parts)=split(/ /,$script);
    my $command=$script."--full 1> /tmp/".$parts[0].".log 2> /tmp/".$parts[0].".error";
    &reset_smb();
    print "\n";
    &printline();
    print "TEST: $command \n";
    system($command);
    print "\n";
}


# typeout
foreach my $script (@scriptlist){
    my (@parts)=split(/ /,$script);
    &printline();
    print "TEST: $script \n";
    &printline();
    my $res1_command="tail -n 3 /tmp/".$parts[0].".log";
    print "STDOUT: $res1_command\n";
    system($res1_command);
    &printline();
    my $res2_command="cat /tmp/".$parts[0].".error | grep -v \"Domain=\" | grep -v \"OS=\" | grep -v \"Server=\"";
    print "ERRORS: $res2_command\n";
    system($res2_command);
    &printline();
    print "\n";
}


sub reset_smb {
    &printline();
    print "Resetting samba for test ... \n";
    system("net conf delshare linuxmuster-global");
    system("net conf delshare abc");
    system("net conf delshare bsz");
    system("net conf delshare default-school");
    system("net conf delshare ghs");
    system("net conf delshare lin");
    system("net conf delshare ltg");
    system("net conf delshare test");
    system("net conf delshare uni");
    system("rm -f /etc/linuxmuster/sophomorix/bsz/bsz.devices.csv");
    system("rm -f /etc/linuxmuster/sophomorix/bsz/bsz.teachers.csv");
    system("rm -f /etc/linuxmuster/sophomorix/bsz/bsz.students.csv");
    system("rm -f /etc/linuxmuster/sophomorix/uni/uni.teachers.csv");
    system("rm -f /etc/linuxmuster/sophomorix/uni/uni.students.csv");
    system("rm -f /etc/linuxmuster/sophomorix/default-school/teachers.csv");
    system("rm -f /etc/linuxmuster/sophomorix/default-school/students.csv");
    system("rm -f /etc/linuxmuster/sophomorix/default-school/devices.csv");
    system("sophomorix-samba --restore-samba ohne-user --schema-load");
    system("rm -rf /srv/samba");
    sleep 5;
    system("sshpass -p \"Muster!\" samba-tool user setpassword Administrator");
    print "... done resetting samba for test\n";
    &printline();
}

sub printline {
    print "######################################################################\n";
}
