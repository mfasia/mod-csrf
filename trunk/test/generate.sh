#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

ROOT=`pwd`
CUID=`id`
CUID_STR=`expr "$CUID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
CUID=`expr "$CUID" : 'uid=\([0-9]*\)'`
CUID=`expr $CUID '*' 10`
CUID=`expr $CUID '%' 100`
PORT_BASE=`expr ${CUID} + 5400`

mkdir -p logs

FILES="conf/httpd.conf"
for E in $FILES; do
  sed <${E}.tmpl >${E} \
    -e "s;##ROOT##;$ROOT;g" \
    -e "s;##USR##;$CUID_STR;g" \
    -e "s;##PORT_BASE##;$PORT_BASE;g"

done

echo "SET PORT_BASE=$PORT_BASE"   >  scripts/ports
