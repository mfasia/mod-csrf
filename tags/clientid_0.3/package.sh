#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#

cd `dirname $0`
TOP=`pwd`
VERSION=`grep "char g_revision" httpd_src/modules/csrf/mod_csrf.c | awk '{print $6}' | awk -F'"' '{print $2}'`
echo "build mod_csrf version $VERSION distribution package"

#TAGV=`echo $VERSION | awk -F'.' '{print "REL_" $1 "_" $2}'`
#echo "check release tag $TAGV ..."
#if [ "`cvs -q diff -r $TAGV 2>&1`" = "" ]; then
#  echo ok
#else
#  echo "FAILED"
#  exit 1
#fi
if [ `grep -c "Version $VERSION" doc/CHANGES.txt` -eq 0 ]; then
  echo "CHANGES.txt check FAILED"
  exit 1
fi
grep \\$\\$\\$ ./httpd_src/modules/csrf/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$' in module"
  exit 1
fi
grep FIXME ./httpd_src/modules/csrf/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern 'FIXME' in module"
  exit 1
fi

set -e
set -u

rm -rf mod_csrf-${VERSION}*
mkdir -p mod_csrf-${VERSION}/doc
mkdir -p mod_csrf-${VERSION}/htdocs
mkdir -p mod_csrf-${VERSION}/apache2

echo "install documentation"
cp doc/README.TXT mod_csrf-${VERSION}
cp doc/LICENSE.txt mod_csrf-${VERSION}/doc
cp doc/CHANGES.txt mod_csrf-${VERSION}/doc
sed <doc/index.html >mod_csrf-${VERSION}/doc/index.html \
 -e "s/0\.00/${VERSION}/g"
cp doc/csrf.jpg mod_csrf-${VERSION}/doc/
cp test/htdocs/csrf.js mod_csrf-${VERSION}/htdocs/

echo "install source"
cp httpd_src/modules/csrf/mod_csrf.c mod_csrf-${VERSION}/apache2/
cp httpd_src/modules/csrf/config.m4 mod_csrf-${VERSION}/apache2/
cp httpd_src/modules/csrf/Makefile.in mod_csrf-${VERSION}/apache2/

echo "package: mod_csrf-${VERSION}.tar.gz"
tar cf mod_csrf-${VERSION}.tar --owner root --group bin mod_csrf-${VERSION}
gzip mod_csrf-${VERSION}.tar
rm -r mod_csrf-${VERSION}

echo "normal end"
