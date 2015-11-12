%define aversion %(rpm -q httpd-devel --qf '%{RPMTAG_VERSION}' | tail -1)
%define rversion 0.00-1M4

Summary: Apache module to prevent cross-site request forgery.
Name: mod_csrf
Version: 0.00
Release: 1M4
License: GNU Lesser General Public License
Group: System Environment/Daemons
URL: https://github.com/mfasia/mod-csrf

Packager: Faqueer Tanvir Ahmed <tanvir@metafour.com>
Vendor: Christoph Steigmeier, Pascal Buchbinder

Source: http://sourceforge.net/projects/mod-csrf/files/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/root-%{name}-%{version}
Prefix: %{_prefix}

BuildRequires: zlib-devel, httpd-devel
Requires: httpd >= %{aversion}

%description
Cross-site request forgery (CSRF) attacks try to force a user to send 
data to a Web application in which the user has currently an authenticated 
session (the user has logged on) in order to execute actions the used did 
not want. These kind of attacks are sometimes performed by sending somebody 
a manipulated hyperlink by email or by storing malicious HTML links within 
a Web site, e.g., a public forum or blog.

The mod_csrf project implements protection measurements against CSRF attacks. 
It can be installed on your Apache Web server to help to protect your users 
from such an attack. The project provides two components:

* A JavaScript which injects a unique (per user/per session) request 
identifier to HTTP request. The identifier is added to evey HTML form, 
hyperlink ("a" tag by default/list of attributes may be extended), as well 
as Ajax request.

* An Apache module which may be used to verify that HTTP requests do 
contain this unique identifier injected by the JavaScript. The module 
can also be configured to validate the HTTP referer header in addition.
mod_csrf is an open source software licensed under the GNU Lesser 
General Public License. Downloads are handled by SourceForge.net.

For more documentation, see the README file.

%prep
%setup -n %{name}-%{version}

%{__cat} <<'EOF' >apache2/mod_csrf.conf
LoadModule csrf_module modules/mod_csrf.so
<IfModule mod_csrf.c>
  # Enables or disables the module on a per server or location basis. 
  # Default is 'on'.
  CSRF_Enable 'on'|'off' 

  # mod_csrf may deny requests whose HTTP Host and Referer header do not 
  # contain the very same hostname. This referer header check is enabled 
  # by default.
  #CSRF_EnableReferer 'on'|'off' 

  # Defines the action to take when a request does violates the configured 
  # rules. 
  # Default is 'deny'.
  #CSRF_Action 'deny'|'log' 

  # Used to encrypt the mod_csrf request identifier. 
  # Default is a non-persistent random passphrase.
  #CSRF_PassPhrase <string> 

  # The validity period of the csrf request identifier injected by the 
  # JavaScript.
  # Default is 3600 seconds.
  #CSRF_Timeout <seconds> 

  # URL path to the JavaScript to include to each HTML which is then 
  # used to inject the mod_csrf request identifier. 
  # Default path is /csrf.js.
  #CSRF_ScriptPath <path> 
</IfModule>
EOF

%build
cd apache2
#%{__make} %{?_smp_mflags} APXS="%{_sbindir}/apxs"
%{__make}

%install
cd apache2
%{__rm} -rf %{buildroot}
%{__install} -d -m0755 %{buildroot}%{_libdir}/httpd/modules/ \
                        %{buildroot}%{_sysconfdir}/httpd/conf.d/
%{__install} -m0755 .libs/mod_csrf.so %{buildroot}%{_libdir}/httpd/modules/
%{__install} -m0644 mod_csrf.conf %{buildroot}%{_sysconfdir}/httpd/conf.d/

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%doc doc/csrf.jpg doc/LICENSE.txt doc/CHANGES.txt doc/index.html htdocs/csrf.js
%config(noreplace) %{_sysconfdir}/httpd/conf.d/mod_csrf.conf
%{_libdir}/httpd/modules/mod_csrf.so

%changelog
* Fri Nov 6 2015 Nadim Jahangir <nadim@metafour.com> - 0.5.1
- Modified for handling XML content type and controlling CSRF 
  token validation
