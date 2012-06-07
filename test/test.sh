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
./ctl.sh stop
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

CFS=`find . -name "*core*"`
if [ -n "$CFS" ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED found core file"
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
