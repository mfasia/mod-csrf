#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# mod_csrf - Cross-site request forgery protection module for
#            the Apache web server
#
# Copyright (C) 2012 Christoph Steigmeier, Pascal Buchbinder
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

cd `dirname $0`
TOP=`pwd`

APACHE_VER=2.2.22

echo "build Apache $APACHE_VER"
if [ ! -d httpd-${APACHE_VER} ]; then
  gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
fi
rm -f httpd
ln -s httpd-${APACHE_VER} httpd

rm -rf httpd/modules/csrf
mkdir -p httpd/modules/csrf
ln -s `pwd`/httpd_src/modules/csrf/mod_csrf.c httpd/modules/csrf
ln -s `pwd`/httpd_src/modules/csrf/config.m4 httpd/modules/csrf
ln -s `pwd`/httpd_src/modules/csrf/Makefile.in httpd/modules/csrf

ADDMOD=""

CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -g -Wall -DI_INSIST_ON_EXTRA_CYCLES_FOR_CLF_COMPLIANCE"
export CFLAGS 

cd httpd
./buildconf
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

./configure --with-mpm=worker --enable-so --enable-csrf=shared --enable-proxy=shared --enable-ssl --enable-status=shared --enable-info=shared --enable-static-support --enable-unique-id --enable-unique-id=shared --enable-dumpio=shared $ADDMOD
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

# patch ...
sed <build/rules.mk > build/rules.mk.2 \
 -e "s;LINK     = \$(LIBTOOL) --mode=link \$(CC) \$(ALL_CFLAGS)  \$(LT_LDFLAGS);LINK     = \$(LIBTOOL) --mode=link \$(CC) \$(ALL_CFLAGS) -static \$(LT_LDFLAGS);g"
mv build/rules.mk.2 build/rules.mk

make
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

cd ..

echo "END"
