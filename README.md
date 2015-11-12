# Overview
mod_csrf - Cross-site request forgery protection module for the Apache web server.
Cloned from: http://mod-csrf.sourceforge.net/

Modified for handling XML content type and controlling CSRF token validation.

# License
```
Copyright (C) 2012-2014 Christoph Steigmeier, Pascal Buchbinder

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Please refer to ./doc/index.html for further information.
```

# Dependencies
[mod_parp](https://github.com/mfasia/mod-parp) - A POST/GET parameter parser to enable apache modules to validate form parameter send from client.

# Building
1. Update version number `g_revision` in: `httpd_src/modules/csrf/mod_csrf.c`
2. Update release notes: `doc/CHANGES.txt`
3. Update doc: `doc/index.html`
4. Update release number `Release:` in: `httpd_src/modules/csrf/mod_csrf.spec`
5. Commit last changes
6. Run `sh package.sh`
7. Run `rpmbuild -ta mod_csrf-${version}.tar.gz`

# Distributing
- Upload `mod_csrf-${version}-${release}.x86_64.rpm` to http://repo1.metafour.com/yumrepo/centos/7/extras/RPMS/x86_64/
- Upload `mod_csrf-${version}-${release}.src.rpm` to http://repo1.metafour.com/yumrepo/centos/7/extras/SRPMS/

# Usage
1.  Copy `/usr/share/doc/mod_csrf-${version}/csrf.js` to DocumentRoot (e.g. `/var/www/html`)
2.  Configure Apache (e.g. `/etc/httpd/conf.modules.d/11-csrf.conf`)
```xml
# Load and configure the PARP module
LoadModule parp_module modules/mod_parp.so
<IfModule mod_parp.c>
  # Ignore parser errors:
  PARP_ExitOnError         200
</IfModule>

# Load and configure the CSRF module
LoadModule csrf_module modules/mod_csrf.so
SetEnvIf Request_URI /* CSRF_IGNORE=yes
SetEnvIf X-Forwarded-For (.*) CSRF_ATTRIBUTE=$1
# SetEnvIf Request_Method GET CSRF_IGNORE_VALIDATION=yes
#<IfModule mod_csrf.c>
#  CSRF_Enable 'on'
#  CSRF_ScriptPath /csrf.js
#</IfModule>
#SetEnvIf   Request_URI   .*dwsrun.*    !parp
```
3. To insert CSRF token in any XML response add an empty tag in the XML document.
```xml
<csrf_token></csrf_token>
```

