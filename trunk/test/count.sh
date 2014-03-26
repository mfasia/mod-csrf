#!/bin/sh

bytes=`cat logs/access_log | awk '{print $11}'|  awk '{total+=$0} END{print total}'`
lines=`wc -l logs/access_log | awk '{print $1}'`
kbytes=`expr $bytes / 1024`
mbytes=`expr $kbytes / 1024`

echo "$mbytes mbytes $lines requests"

