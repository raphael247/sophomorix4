#!/usr/bin/make
# This is the sophomorix Makefile
# for Debian packaging (make DESTDIR=/root/sophomorix)
DESTDIR=

# Installing from this Makefile
#====================================
# if you use this Makefile to install sophomorix (instead of 
# installing the debian-Package) you will miss:
#   1. html-documentation
#   2. manpages
# This is because debian has scripts to install 1. and 2. VERY easily
# see debian/rules -> dh_installman, dh-installdocs



# Debian
#====================================

# Homes
#HOME=$(DESTDIR)/home

# Developement
#USERROOT=$(DESTDIR)/root

# Data
LIBDIR=$(DESTDIR)/var/lib/sophomorix

# Cache
#CACHEDIR=$(DESTDIR)/var/cache/sophomorix

# Logs
LOGDIR=$(DESTDIR)/var/log/sophomorix

# Perl modules
PERLMOD=$(DESTDIR)/usr/share/perl5/Sophomorix

# Dokumentation
#DOCDEBDIR=$(DESTDIR)/usr/share/doc

# configs
CONF=$(DESTDIR)/etc/linuxmuster/sophomorix

# Schema
SCHEMA=$(DESTDIR)/usr/share/sophomorix/schema

# Developer configs
DEVELCONF=$(DESTDIR)/usr/share/sophomorix

# Migration conf
DUMPCONF=$(DESTDIR)/usr/share/sophomorix-dump
VAMPIRECONF=$(DESTDIR)/usr/share/sophomorix-vampire

# Encoding-data
ENCODING=$(DESTDIR)/usr/share/sophomorix/encoding-data

# Language
LANGUAGE=$(DESTDIR)/usr/share/sophomorix/lang

# Latex
LATEX=$(DESTDIR)/usr/share/sophomorix/lang/latex

# Filter
FILTER=$(DESTDIR)/usr/share/sophomorix/filter

# SAMBADEBCONFDIR für Debian 
#SAMBADEBCONFDIR=$(DESTDIR)/etc/samba

# SAMBA Debian 
#SAMBADIR=$(DESTDIR)/var/lib/samba
#SAMBAROOTPREEXEC=$(DESTDIR)/etc/linuxmuster/samba/root-preexec.d
#SAMBAROOTPOSTEXEC=$(DESTDIR)/etc/linuxmuster/samba/root-postexec.d

# Config-templates
#CTEMPDIR=$(DESTDIR)/usr/share/sophomorix/config-templates

# Testfiles
DEVELOPERDIR=$(DESTDIR)/usr/share/sophomorix-developer
TESTDATA=$(DESTDIR)/usr/share/sophomorix-developer/testdata

# sophomorix-virusscan
#VIRUSSCAN=$(DESTDIR)/usr/share/sophomorix-virusscan

# Tools
#TOOLS=$(DESTDIR)/root/sophomorix-developer


all: install-sophomorix-samba install-virusscan install-developer install-vampire install-dump install-belwue-mail

help:
	@echo ' '
	@echo 'Most common options of this Makefile:'
	@echo '-------------------------------------'
	@echo ' '
	@echo '   make help'
	@echo '      show this help'
	@echo ' '
	@echo '   make | make all'
	@echo '      make an installation of files to the local ubuntu xenial'
	@echo ' '
	@echo '   make install-virusscan'
	@echo '      create a debian package'
	@echo ' '
	@echo '   make install-sophomorix-samba'
	@echo '      create a debian package'
	@echo ' '
	@echo '   make install-developer'
	@echo '      create a debian package'
	@echo ' '
	@echo '   make deb'
	@echo '      create a debian package for ubuntu xenial'
	@echo ' '


deb:
	### Prepare to build an ubuntu xenial package
	@echo 'Did you do a dch -i ?'
	@sleep 2
	dpkg-buildpackage -tc -uc -us -sa -rfakeroot
	@echo ''
	@echo 'Do not forget to tag this version with: git tag V-x.y.z'
	@echo ''

#clean: clean-doc clean-debian
clean: clean-debian

clean-debian:
	rm -rf  debian/sophomorix4
#	rm -rf  debian/sophomorix4-virusscan

# sophomorix-samba
install-sophomorix-samba:
	### install-samba
# some dirs
	@install -d -m700 -oroot -groot $(LIBDIR)
	@install -d -m700 -oroot -groot $(LIBDIR)/tmp
	@install -d -m700 -oroot -groot $(LIBDIR)/lock
	@install -d -m700 -oroot -groot $(LIBDIR)/print-data
	@install -d -m700 -oroot -groot $(LIBDIR)/check-result
#	@install -d -m755 -oroot -groot $(CACHEDIR)
	@install -d -m700 -oroot -groot $(LOGDIR)
	@install -d -m700 -oroot -groot $(LOGDIR)/user
#	@install -d -m700 -oroot -groot $(CTEMPDIR)
#	@install -d -m700 -oroot -groot $(CTEMPDIR)/samba/netlogon
#	@install -d -m700 -oroot -groot $(CTEMPDIR)/apache
# Install the scripts
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-samba/scripts/sophomorix-*[a-z1-9] $(DESTDIR)/usr/sbin
# Install the modules
	@install -d -m755 -oroot -groot $(PERLMOD)
	@install -oroot -groot --mode=0644 sophomorix-samba/modules/Sophomorix*[a-z1-9.]pm $(PERLMOD)
# install schema
	@install -d -m755 -oroot -groot $(SCHEMA)/
	@install -oroot -groot --mode=0644 sophomorix-samba/schema/1_sophomorix-attributes.ldif $(SCHEMA)/
	@install -oroot -groot --mode=0644 sophomorix-samba/schema/2_sophomorix-classes.ldif $(SCHEMA)/
	@install -oroot -groot --mode=0644 sophomorix-samba/schema/3_sophomorix-aux.ldif $(SCHEMA)/
	@install -oroot -groot --mode=0755 sophomorix-samba/schema/sophomorix_schema_add.sh $(SCHEMA)/
#	@install -oroot -groot --mode=0755 sophomorix-samba/schema/samba-backup $(SCHEMA)/
#	@install -oroot -groot --mode=0755 sophomorix-samba/schema/samba-restore $(SCHEMA)/
#	@install -oroot -groot --mode=0755 sophomorix-samba/schema/samba-schema-load $(SCHEMA)/
# group owner is changed in postinst-script to lehrer
#	@install -oroot -groot --mode=4750 sophomorix-base/scripts-teacher/sophomorix-*[a-z1-9] $(DESTDIR)/usr/bin
# installing configs for root
	@install -d -m755 -oroot -groot $(CONF)
#	@install -d -m755 -oroot -groot $(CONF)/user
#	old
#	@install -oroot -groot --mode=0644 sophomorix-samba/config/sophomorix.conf $(CONF)/user
#	@install -oroot -groot --mode=0644 sophomorix-samba/config/sophomorix-schools.conf $(CONF)/user
#	# New, temporary
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/sophomorix.conf.template.ini $(CONF)/sophomorix.conf
	@install -d -m755 -oroot -groot $(CONF)/default-school
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/school.conf.template.ini $(CONF)/default-school/school.conf
	@install -d -m755 -oroot -groot $(CONF)/abc
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/abc.school.conf.template.ini $(CONF)/abc/abc.school.conf
	@install -d -m755 -oroot -groot $(CONF)/bsz
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/bsz.school.conf.template.ini $(CONF)/bsz/bsz.school.conf
	@install -d -m755 -oroot -groot $(CONF)/uni
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/uni.school.conf.template.ini $(CONF)/uni/uni.school.conf
	@install -d -m755 -oroot -groot $(CONF)/lin
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/lin.school.conf.template.ini $(CONF)/lin/lin.school.conf
	@install -d -m755 -oroot -groot $(CONF)/ghs
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/ghs.school.conf.template.ini $(CONF)/ghs/ghs.school.conf
	@install -d -m755 -oroot -groot $(CONF)/test
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/test.school.conf.template.ini $(CONF)/test/test.school.conf
	@install -d -m755 -oroot -groot $(CONF)/ltg
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/ltg.school.conf.template.ini $(CONF)/ltg/ltg.school.conf
#	@install -oroot -groot --mode=0600 sophomorix-samba/config/quota.txt $(CONF)/user
#	@install -oroot -groot --mode=0600 sophomorix-samba/config/mailquota.txt $(CONF)/user
#	@install -d -m755 -oroot -groot $(CONF)/project
	@install -d -m755 -oroot -groot $(CONF)/device
#	@install -oroot -groot --mode=0644 sophomorix-samba/config/projects.create $(CONF)/project
#	@install -oroot -groot --mode=0644 sophomorix-samba/config/projects.update $(CONF)/project
# config-templates
#	@install -oroot -groot --mode=0600 sophomorix-samba/config-templates/*.txt $(CTEMPDIR)
#	@install -oroot -groot --mode=0600 sophomorix-samba/config-templates/*.map $(CTEMPDIR)
#	@install -oroot -groot --mode=0600 sophomorix-samba/config/sophomorix.conf $(CTEMPDIR)
# configs for developers
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/sophomorix-devel.conf $(DEVELCONF)/devel
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/sophomorix.ini $(DEVELCONF)/devel
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/README.repdir $(DEVELCONF)/devel
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/master
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/master/school.conf.master $(DEVELCONF)/devel/master
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/master/sophomorix.conf.master $(DEVELCONF)/devel/master
# repdir files
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.linux $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.global $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.school $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.project $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.globaladministrator_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.schooladministrator_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.teacherclass $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.teacher_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.adminclass $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.student_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.examuser_home $(DEVELCONF)/devel/repdir
#	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/acl
#	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/acl/*acl.template $(DEVELCONF)/devel/acl
# ntacls
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/ntacl
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/ntacl/*ntacl.template $(DEVELCONF)/devel/ntacl
# language stuff
	@install -d -m755 -oroot -groot $(LANGUAGE)
	@install -oroot -groot --mode=0644 sophomorix-samba/lang/sophomorix-lang.*[a-z] $(LANGUAGE)
	@install -oroot -groot --mode=0644 sophomorix-samba/lang/errors.*[a-z] $(LANGUAGE)
#	@install -d -m755 -oroot -groot $(LANGUAGE)/latex-templates
#	@install -oroot -groot --mode=0644 sophomorix-base/latex-templates/*.tex $(LANGUAGE)/latex-templates
# latex stuff
	@install -d -m755 -oroot -groot $(LATEX)
	@install -d -m755 -oroot -groot $(LATEX)/templates
	@install -oroot -groot --mode=0644 sophomorix-samba/lang/latex/README.latextemplates $(LATEX)
	@install -oroot -groot --mode=0644 sophomorix-samba/lang/latex/templates/*[a-z0-9-]-template.tex $(LATEX)/templates
# Encoding-data
	@install -d -m755 -oroot -groot $(ENCODING)
	@install -oroot -groot --mode=0644 sophomorix-samba/encoding-data/*.txt $(ENCODING)
# filter scripts
	@install -d -m755 -oroot -groot $(FILTER)
	@install -oroot -groot --mode=0755 sophomorix-samba/filter/*.filter $(FILTER)
# for samba
#	@install -d -m700 -oroot -groot $(DESTDIR)/home/samba/netlogon
#	@install -oroot -groot --mode=0600 sophomorix-base/samba/netlogon/*.bat.template $(CTEMPDIR)/samba/netlogon
#	@install -d -m700 -oroot -groot $(SAMBAROOTPREEXEC)
#	@install -oroot -groot --mode=0700 sophomorix-base/samba/root-preexec/sophomorix-root-preexec $(SAMBAROOTPREEXEC)
#	@install -d -m700 -oroot -groot $(SAMBAROOTPOSTEXEC)
#	@install -oroot -groot --mode=0700 sophomorix-base/samba/root-postexec/sophomorix-root-postexec $(SAMBAROOTPOSTEXEC)


install-virusscan:
	### install-virusscan
#	@install -d -m755 -oroot -groot $(CONF)/virusscan
#	@install sophomorix-virusscan/config/sophomorix-virusscan.conf $(CONF)/virusscan
#	@install sophomorix-virusscan/config/sophomorix-virusscan-excludes.conf $(CONF)/virusscan
#	@install -d $(DESTDIR)/usr/sbin
#	@install -oroot -groot --mode=0744 sophomorix-virusscan/scripts/sophomorix-virusscan $(DESTDIR)/usr/sbin


#install-janitor:
#	### install-janitor
#	@install -d $(DESTDIR)/usr/sbin
#	@install -oroot -groot --mode=0744 sophomorix-base/scripts/sophomorix-janitor $(DESTDIR)/usr/sbin

install-vampire:
	### install-vampire
	@install -d -m755 -oroot -groot $(VAMPIRECONF)
	@install -oroot -groot --mode=0644 sophomorix-vampire/config-dump-vampire-common/migration-6-to-7.conf $(VAMPIRECONF)
	@install -oroot -groot --mode=0644 sophomorix-vampire/ldif/ldif-pwdload.ldif.template $(VAMPIRECONF)

	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-vampire/scripts/sophomorix-vampire $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-vampire/scripts/sophomorix-vampire-pwdconvert $(DESTDIR)/usr/sbin

install-dump:
	### install-dump
	@install -d -m755 -oroot -groot $(DUMPCONF)
	@install -oroot -groot --mode=0644 sophomorix-vampire/config-dump-vampire-common/migration-6-to-7.conf $(DUMPCONF)
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-dump/scripts/sophomorix-dump $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-dump/scripts/sophomorix-dump-postgres-views.sh $(DESTDIR)/usr/sbin

install-belwue-mail:
	### install-belwue-mail
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-belwue/scripts/sophomorix-belwue $(DESTDIR)/usr/sbin




install-developer:
	### install-developer
### installing test scripts
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-*[0-9] $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-workflow $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-errorfiles $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-infoscripts $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-exammode $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-JSON-example $(DESTDIR)/usr/sbin
# copying perl developer modules
	@install -d -m755 -oroot -groot $(PERLMOD)
	@install -oroot -groot --mode=0644 sophomorix-developer/modules/SophomorixTest.pm $(PERLMOD)
# installing  examples
	@install -d $(DEVELOPERDIR)
# installing  testdata
	@install -d $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-firstname $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-lastname $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-birthdate $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-class $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-30 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-40 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-exammode $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.update-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-30 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-40 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-exammode $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/uni.students.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/uni.teachers.csv-1 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-2 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-2 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-2 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-2 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-4 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-4 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-4 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-4 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-5 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-5 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-5 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-5 $(TESTDATA)
	@install -d $(TESTDATA)/transfer-testdata
	@install -d $(TESTDATA)/transfer-testdata/subdir1-level1
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir1-level2
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir2-level2
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir1-level2/subdir1-level3
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir3-level2
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/file* $(TESTDATA)/transfer-testdata

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/subdir1-level1/file* $(TESTDATA)/transfer-testdata/subdir1-level1
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/subdir2-level1/file* $(TESTDATA)/transfer-testdata/subdir2-level1
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/subdir2-level1/subdir1-level2/file* $(TESTDATA)/transfer-testdata/subdir2-level1/subdir1-level2

# installing sources.list examples
#	@install -d $(TOOLS)/apt/s-lists
#	@install -oroot -groot --mode=0644 sophomorix-developer/tools/apt/s-lists/*sources.list $(TOOLS)/apt/s-lists


#clean-doc:
#	### clean-doc
#	rm -rf sophomorix-doc/html

# you need to: 
#       apt-get install docbook-utils
# on debian to create documentation
#doc:
#	### doc
## Creating html-documentation
#	cd ./sophomorix-doc/source/sgml; docbook2html --nochunks --output ../../html  sophomorix.sgml
## Creating html-manpages
#	./buildhelper/sopho-man2html
## Creating changelog
#	./buildhelper/sopho-changelog


