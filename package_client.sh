#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#

cd `dirname $0`
TOP=`pwd`
VERSION=`grep "char g_revision" httpd_src/modules/clientid/mod_clientid.c | awk '{print $6}' | awk -F'"' '{print $2}'`
echo "build mod_clientid version $VERSION distribution package"
echo "svn copy -m \"\" svn+ssh://pbuchbinder@svn.code.sf.net/p/mod-csrf/code/trunk svn+ssh://pbuchbinder@svn.code.sf.net/p/mod-csrf/code/tags/clientid_${VERSION}"

#TAGV=`echo $VERSION | awk -F'.' '{print "REL_" $1 "_" $2}'`
#echo "check release tag $TAGV ..."
#if [ "`cvs -q diff -r $TAGV 2>&1`" = "" ]; then
#  echo ok
#else
#  echo "FAILED"
#  exit 1
#fi
#if [ `grep -c "Version $VERSION" doc/CHANGES.txt` -eq 0 ]; then
#  echo "CHANGES.txt check FAILED"
#  exit 1
#fi
grep \\$\\$\\$ ./httpd_src/modules/clientid/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$' in module"
  exit 1
fi
grep FIXME ./httpd_src/modules/clientid/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern 'FIXME' in module"
  exit 1
fi

set -e
set -u

rm -rf mod_clientid-${VERSION}*
mkdir -p mod_clientid-${VERSION}/doc
mkdir -p mod_clientid-${VERSION}/apache2

echo "install documentation"
cp doc/LICENSE.txt mod_clientid-${VERSION}/doc/
cp doc/clientid.html mod_clientid-${VERSION}/doc/index.html
cp doc/clientid.png mod_clientid-${VERSION}/doc
mkdir -p mod_clientid-${VERSION}/doc/htdocs/res/
cp test/htdocs/error/check mod_clientid-${VERSION}/doc/htdocs/res/clchk
cp test/htdocs/cookie.html mod_clientid-${VERSION}/doc/htdocs/res/

echo "install source"
cp httpd_src/modules/clientid/mod_clientid.c mod_clientid-${VERSION}/apache2/
cp httpd_src/modules/clientid/config.m4 mod_clientid-${VERSION}/apache2/
cp httpd_src/modules/clientid/Makefile.in mod_clientid-${VERSION}/apache2/

echo "package: mod_clientid-${VERSION}.tar.gz"
tar cf mod_clientid-${VERSION}.tar --owner root --group bin mod_clientid-${VERSION}
gzip mod_clientid-${VERSION}.tar
rm -r mod_clientid-${VERSION}

echo "normal end"
