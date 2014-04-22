Name:		fcgiwrap
Version:	1.1
Release:	1%{?dist}
Summary:	Simple FastCGI wrapper for CGI scripts

Group:		System Environment/Daemons
License:	BSD
URL:		http://nginx.localdomain.pl/wiki/FcgiWrap
Source0:	fcgiwrap-1.1.tar.gz

BuildRequires:	autoconf fcgi-devel
Requires:	fcgi

%description
Simple FastCGI wrapper for CGI scripts w/ following features:
 - very lightweight (84KB of private memory per instance)
 - fixes broken CR/LF in headers
 - handles environment in a sane way (CGI scripts get HTTP-related env. vars
   from FastCGI parameters and inherit all the others from ``fcgiwrap``'s
   environment)
 - no configuration, so you can run several sites off the same ``fcgiwrap``
   pool
 - passes CGI stderr output to ``fcgiwrap``'s stderr or FastCGI stderr stream


%prep
%setup -q


%build
autoreconf -i
%configure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_sbindir}/fcgiwrap
#TODO: figure out why the manpage file is compressed automatically
%doc %{_mandir}/man8/fcgiwrap.8.gz


%changelog

