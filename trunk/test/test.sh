#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

if [ `ps -ef | grep -v grep | grep -c "tee test.log"` -eq 0 ]; then
  $0 | tee test.log
  exit $?
fi

ulimit -c unlimited
./generate.sh

ERRORS=0
WARNINGS=0

# delete the access log file since it is used to generate permit rules
./ctl.sh stop 1>/dev/null
sleep 1
rm -f logs/*
./ctl.sh start 1>/dev/null

for E in `ls scripts/*htt`; do
  ./run.sh -s $E
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $E"
  fi
done

./ctl.sh stop 1>/dev/null

CFS=`find . -name "*core*"`
if [ -n "$CFS" ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED found core file"
fi

grep \\$\\$\\$ ../httpd_src/modules/csrf/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$'"
fi

LINES=`grep fprintf ../httpd_src/modules/csrf/mod_csrf.c | grep -v "NOT FOR PRODUCTIVE USE" | grep -v "requires OpenSSL, compile Apache using" | wc -l | awk '{print $1}'`
if [ $LINES != "0" ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern 'fprintf'"
fi

if [ $WARNINGS -ne 0 ]; then
    echo "ERROR: got $WARNINGS warnings and $ERRORS errors"
    exit 1
fi

if [ $ERRORS -ne 0 ]; then
    echo "ERROR: end with $ERRORS errors"
    exit 1
fi

echo "normal end"
exit 0
