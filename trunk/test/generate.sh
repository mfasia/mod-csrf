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
PORT_BASE3=`expr ${PORT_BASE} + 3`
PORT_BASE4=`expr ${PORT_BASE} + 4`
PORT_BASE5=`expr ${PORT_BASE} + 5`

mkdir -p logs
mkdir -p htdocs/doc
rm -f htdocs/doc/*
ln -s `pwd`/../doc/*.html htdocs/doc/
ln -s `pwd`/../doc/*jpg htdocs/doc/

FILES="conf/httpd.conf htdocs/index.html"
for E in $FILES; do
  sed <${E}.tmpl >${E} \
    -e "s;##ROOT##;$ROOT;g" \
    -e "s;##USR##;$CUID_STR;g" \
    -e "s;##PORT_BASE##;$PORT_BASE;g" \
    -e "s;##PORT_BASE1##;$PORT_BASE1;g" \
    -e "s;##PORT_BASE2##;$PORT_BASE2;g" \
    -e "s;##PORT_BASE3##;$PORT_BASE3;g" \
    -e "s;##PORT_BASE4##;$PORT_BASE4;g" \
    -e "s;##PORT_BASE5##;$PORT_BASE5;g"

done

echo "SET PORT_BASE=$PORT_BASE"    >  scripts/ports
echo "SET PORT_BASE1=$PORT_BASE1" >>  scripts/ports
echo "SET PORT_BASE2=$PORT_BASE2" >>  scripts/ports
echo "SET PORT_BASE3=$PORT_BASE3" >>  scripts/ports
echo "SET PORT_BASE4=$PORT_BASE4" >>  scripts/ports
echo "SET PORT_BASE5=$PORT_BASE5" >>  scripts/ports

if [ ! -d ssl ]; then
  mkdir -p ssl
  cd ssl
  touch index.txt
  echo 01 > serial
  openssl req -config ../conf/openssl.conf -new -x509 -days 3650 -nodes \
   -keyout cakey.pem -out cacert.pem

  # certs
  CERTS="server1 localhost"
  for E in $CERTS; do
    sed <../conf/openssl.conf >../conf/openssl2.conf \
     -e "s;csrf ca;$E;g"
    openssl req -config ../conf/openssl2.conf -new -nodes \
     -keyout $E.key.pem \
     -out $E.req.pem
    openssl ca  -config ../conf/openssl2.conf -batch -policy policy_anything \
     -out $E.cert.pem \
     -infiles $E.req.pem
    rm $E.req.pem
    rm ../conf/openssl2.conf
  done
  rm -f 0*.pem
fi
