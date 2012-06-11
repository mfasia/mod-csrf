#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

ROOT=`pwd`
CUID=`id`
CUID_STR=`expr "$CUID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
CUID=`expr "$CUID" : 'uid=\([0-9]*\)'`
CUID=`expr $CUID '*' 10`
CUID=`expr $CUID '%' 100`
PORT_BASE=`expr ${CUID} + 5400`
PORT_BASE1=`expr ${PORT_BASE} + 1`
PORT_BASE2=`expr ${PORT_BASE} + 2`
PORT_BASE3=`expr ${PORT_BASE} + 4`

mkdir -p logs
mkdir -p htdocs/doc
rm htdocs/doc/*
ln -s `pwd`/../doc/*.html htdocs/doc/
ln -s `pwd`/../doc/*jpg htdocs/doc/

FILES="conf/httpd.conf"
for E in $FILES; do
  sed <${E}.tmpl >${E} \
    -e "s;##ROOT##;$ROOT;g" \
    -e "s;##USR##;$CUID_STR;g" \
    -e "s;##PORT_BASE##;$PORT_BASE;g" \
    -e "s;##PORT_BASE1##;$PORT_BASE1;g" \
    -e "s;##PORT_BASE2##;$PORT_BASE2;g" \
    -e "s;##PORT_BASE3##;$PORT_BASE3;g"

done

echo "SET PORT_BASE=$PORT_BASE"    >  scripts/ports
echo "SET PORT_BASE1=$PORT_BASE1" >>  scripts/ports
echo "SET PORT_BASE1=$PORT_BASE2" >>  scripts/ports
echo "SET PORT_BASE1=$PORT_BASE3" >>  scripts/ports
