#!/bin/sh

bytes=`cat logs/access_log | awk '{print $11}'|  awk '{total+=$0} END{print total}'`
lines=`wc -l logs/access_log | awk '{print $1}'`
kbytes=`expr $bytes / 1024`
mbytes=`expr $kbytes / 1024`

start=`head -1 logs/access_log | awk '{print $4}' | awk -F'[' '{print $2}'`
end=`tail -1 logs/access_log | awk '{print $4}' | awk -F'[' '{print $2}'`

echo "$start to $end"
echo "$mbytes mbytes $lines requests"
