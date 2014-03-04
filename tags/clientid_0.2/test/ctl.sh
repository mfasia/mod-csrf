#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-

COMMAND=$1
shift
ADDARGS=$@
case "$COMMAND" in
  start)
         ulimit -c unlimited
	 if [ "$ADDARGS" = "" ]; then
	    ../httpd/httpd -d `pwd`
	 else
	    ../httpd/httpd -d `pwd` $ADDARGS
	 fi
	 COUNT=0
	 while [ $COUNT -lt 20 ]; do
	   if [ -f logs/apache.pid ]; then
             COUNT=20
           else
             let COUNT=$COUNT+1
	      sleep 1
           fi
         done
	 ADDR=`grep VirtualHost conf/httpd.conf | head -1 | awk '{print $2}' | awk -F'>' '{print $1}'`
	 echo "server http://${ADDR}/ pid=`cat logs/apache.pid`"
	 ;;
  stop)
         if [ -f logs/apache.pid ]; then
           echo "kill server `cat logs/apache.pid`"
	   kill `cat logs/apache.pid`
         fi
	 COUNT=0
	 while [ $COUNT -lt 20 ]; do
	   if [ -f logs/apache.pid ]; then
             let COUNT=$COUNT+1
	      sleep 1
           else
             COUNT=20
           fi
         done
	 ;;
  graceful)
         if [ -f logs/apache.pid ]; then
           echo "sigusr1 server `cat logs/apache.pid`"
	   touch logs/apache.pid.graceful
	   kill -USR1 `cat logs/apache.pid`
	   COUNTER=0
	   while [ $COUNTER -lt 4 ]; do
	     NEWER=`find logs/apache.pid -newer logs/apache.pid.graceful`
	     if [ "$NEWER" = "logs/apache.pid" ]; then
	       COUNTER=10
	     else
	       sleep 1
	     fi
	     COUNTER=`expr $COUNTER + 1`
	   done
	   rm logs/apache.pid.graceful
         fi
	 ;;
  restart)
    $0 stop
    $0 start $ADDARGS
esac

exit 0
