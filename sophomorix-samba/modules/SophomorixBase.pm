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


@ISA = qw(Exporter);

@EXPORT_OK = qw( 
               );
@EXPORT = qw(
            print_line
            print_title
            time_stamp_AD
            time_stamp_file
            unlock_sophomorix
            lock_sophomorix
            log_script_start
            log_script_end
            log_script_exit
            backup_amku_file
            get_passwd_charlist
            get_plain_password
            check_options
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
           open(LOCK,">$DevelConf::lock_file") || die "Cannot create lock file \n";;
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
           open(LOCK,">$DevelConf::lock_file") || die "Cannot create lock file \n";;
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
    my @password_chars=@_;
    my $password="";
    my $i;
    if ($role eq "teacher") {
        # Teacher
        if ($Conf::teacher_password_random eq "yes") {
	    $password=&create_plain_password($Conf::teacher_password_random_charnumber,@password_chars);
        } else {
            $password=$DevelConf::student_password_default;
	}
    } elsif ($role eq "student") {
        # Student
        if ($Conf::student_password_random eq "yes") {
	    $password=&create_plain_password($Conf::student_password_random_charnumber,@password_chars);
        } else {
            $password=$DevelConf::teacher_password_default;
        }
    } elsif ($role eq "examaccount") {
        # Exam Account 12 chars to avoid login 
        $password=&create_plain_password(12,@password_chars);
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




# others
######################################################################
# error, when options are not given correctly
sub  check_options{
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
