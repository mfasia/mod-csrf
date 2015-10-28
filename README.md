## mod_csrf: Apache2 module for Cross-Site Request Forgery (CSRF) prevention
### Modified from http://mod-csrf.sourceforge.net/ for handling XML content type and controlling CSRF token validation
---
## How to install dependencies (mod_parp)
```bash
# wget http://downloads.sourceforge.net/project/parp/mod_parp-0.15-src.tar.gz
# tar -zxvf tar -zxvf mod_parp-0.15-src.tar.gz
# cd cd mod_parp-0.15/apache2/
# apxs -i -c mod_parp.c
# cp -p /etc/httpd/conf.modules.d/00-base.conf /etc/httpd/conf.modules.d/00-base.conf.bak
# echo "LoadModule parp_module modules/mod_parp.so" >> /etc/httpd/conf.modules.d/00-base.conf
# systemctl restart httpd
```

## How to install
```sh
# wget https://github.com/mfasia/mod-csrf/archive/master.zip
# unzip master.zip
# cd mod-csrf-master/httpd_src/modules/csrf/
# apxs -i -c mod_csrf.c -lcrypto
# echo "LoadModule parp_module modules/mod_csrf.so" >> /etc/httpd/conf.modules.d/00-base.conf
# cp ../../../test/htdocs/csrf.js /var/www/
# systemctl restart httpd
```

## How to insert CSRF token in XML response
### In any XML document add an empty tag ```<csrf_token></csrf_token>``` then the module will fill in this tag with CSRF token

## Example Apache configuration (/etc/httpd/conf.modules.d/11-csrf.conf)
```xml
SetEnvIf Request_URI /* CSRF_IGNORE=yes
SetEnvIf X-Forwarded-For (.*) CSRF_ATTRIBUTE=$1
# SetEnvIf Request_Method GET CSRF_IGNORE_VALIDATION=yes
#<IfModule mod_csrf.c>
#  CSRF_Enable 'on'
#  CSRF_ScriptPath /csrf.js
#</IfModule>
#SetEnvIf   Request_URI   .*dwsrun.*    !parp

<IfModule mod_parp.c>
        PARP_ExitOnError         200
</IfModule>
```
