Name:		6bed4
Version:	0.0.1
Release:	0.1%{?dist}
Summary:	IPv6 tunneling technique over UDP and IPv4

Group:		Applications/Internet
License:	BSD
URL:		http://devel.0cpm.org/6bed4/
Source0:	6bed4-%{version}.tar.bz2
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	cmake

%description
Given the limited resources available to a lot of embedded systems,
dual-stack solutions are not always feasible for such hosts.  A
mechanism that supports a direct transition from IPv4-only to
IPv6-only may prove beneficial in getting the smallest hosts to make
a transition to IPv6 at a much earlier stage than would otherwise be
possible.  This calls for tunnels, but no current tunnel technique
appears to be optimal for embedded systems.

This specification details an IPv6 tunneling technique over UDP and
IPv4.  The technique is specifically designed to benefit embedded
systems, and to work without end user configuration.  The working
principle for obtaining a routable IPv6 address is through stateless
autoconfiguration from an anycast tunnel service.

%prep
%setup -q


%build
%cmake .
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc HISTORY LICENSE doc
%{_sbindir}/6bed4peer
%{_sbindir}/6bed4router
%{_mandir}/man8/*

%changelog
* Thu mar  8 2012 Rick van Rein
- rearranged command and man file names

* Sat Oct 22 2011 François Kooman - 0.0.1-0.1
- initial version


