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

# etc
ETC=$(DESTDIR)/etc
SYSTEMD=$(DESTDIR)/run/systemd

all: install

help:
	@echo ' '
	@echo 'Most common options of this Makefile:'
	@echo '-------------------------------------'
	@echo ' '
	@echo '   make help'
	@echo '      show this help'
	@echo ' '
	@echo '   make | make install'
	@echo '      make installation of config files'
	@echo ' '


# 
install:
	### install client
	@install -osystemd-resolve -gsystemd-resolve --mode=0644 templates/resolv.conf.template $(SYSTEMD)/resolve/stub-resolv.conf


