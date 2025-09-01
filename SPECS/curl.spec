# XCP-ng build condition (enabled by default)
%bcond_without xcpng
%if %{with xcpng}
# Disable libcurl-minimal build for xcpng build
%bcond_with build_minimal
%else
%bcond_without build_minimal
%endif

Summary: A utility for getting files from remote servers (FTP, HTTP, and others)
Name: curl
Version: 8.9.1
Release: 5.1%{?dist}
License: curl
Source0: https://curl.se/download/%{name}-%{version}.tar.xz
Source1: https://curl.se/download/%{name}-%{version}.tar.xz.asc
# The curl download page ( https://curl.se/download.html ) links
# to Daniel's address page https://daniel.haxx.se/address.html for the GPG Key,
# which points to the GPG key as of April 7th 2016 of https://daniel.haxx.se/mykey.asc
Source2: mykey.asc

# fix crashes with transmission due to SIGPIPE
Patch001: 0001-curl-8.9.1-sigpipe-init-the-struct-so-that-first-apply-ignores.patch

# patch making libcurl multilib ready
Patch101: 0101-curl-7.32.0-multilib.patch

# do not fail on warnings in the upstream test driver
Patch102: 0102-curl-7.88.0-tests-warnings.patch

%if %{with xcpng}
# Patches ported from the XS package
Patch300: 0300-curl-8.6.0-nss-compat.patch
Patch301: 0301-curl-8.6.0-tests.patch

# Backported from upstream patch
Patch1001: CVE-2024-8096-gtls-fix-OCSP-stapling-management.patch
%endif

Provides: curl-full = %{version}-%{release}
# do not fail when trying to install curl-minimal after drop
Provides: curl-minimal = %{version}-%{release}
Provides: webclient
URL: https://curl.se/

# The reason for maintaining two separate packages for curl is no longer valid.
# The curl-minimal is currently almost identical to curl-full, so let's drop curl-minimal.
# For more details, see https://bugzilla.redhat.com/show_bug.cgi?id=2262096
Obsoletes: curl-minimal < 8.6.0-4

BuildRequires: automake
%if %{without xcpng}
BuildRequires: brotli-devel
%endif
BuildRequires: coreutils
BuildRequires: gcc
BuildRequires: groff
BuildRequires: krb5-devel
%if %{without xcpng}
BuildRequires: libidn2-devel
BuildRequires: libnghttp2-devel
BuildRequires: libpsl-devel
BuildRequires: libssh-devel
%else
BuildRequires: libidn-devel
BuildRequires: libssh2-devel
%endif
BuildRequires: libtool
BuildRequires: make
BuildRequires: openldap-devel
BuildRequires: openssh-clients
BuildRequires: openssh-server
BuildRequires: openssl-devel
BuildRequires: perl-interpreter
BuildRequires: pkgconfig
%if %{without xcpng}
BuildRequires: python-unversioned-command
%endif
BuildRequires: python3-devel
BuildRequires: sed
BuildRequires: zlib-devel

# For gpg verification of source tarball
BuildRequires: gnupg2

# needed to compress content of tool_hugehelp.c after changing curl.1 man page
BuildRequires: perl(IO::Compress::Gzip)

# needed for generation of shell completions
BuildRequires: perl(Getopt::Long)
BuildRequires: perl(Pod::Usage)
BuildRequires: perl(strict)
BuildRequires: perl(warnings)

%if %{without xcpng}
# needed for test1560 to succeed
BuildRequires: glibc-langpack-en
%endif

# gnutls-serv is used by the upstream test-suite
BuildRequires: gnutls-utils

# hostname(1) is used by the test-suite but it is missing in armv7hl buildroot
BuildRequires: hostname

%if %{without xcpng}
# nghttpx (an HTTP/2 proxy) is used by the upstream test-suite
BuildRequires: nghttp2
%endif

# perl modules used in the test suite
BuildRequires: perl(B)
BuildRequires: perl(base)
BuildRequires: perl(constant)
BuildRequires: perl(Cwd)
BuildRequires: perl(Digest::MD5)
BuildRequires: perl(Digest::SHA)
BuildRequires: perl(Exporter)
BuildRequires: perl(File::Basename)
BuildRequires: perl(File::Copy)
BuildRequires: perl(File::Spec)
BuildRequires: perl(IPC::Open2)
BuildRequires: perl(List::Util)
BuildRequires: perl(Memoize)
BuildRequires: perl(MIME::Base64)
BuildRequires: perl(POSIX)
BuildRequires: perl(Storable)
BuildRequires: perl(Time::HiRes)
BuildRequires: perl(Time::Local)
BuildRequires: perl(vars)

%if 0%{?fedora}
# needed for upstream test 1451
BuildRequires: python3-impacket
%endif

# The test-suite runs automatically through valgrind if valgrind is available
# on the system.  By not installing valgrind into mock's chroot, we disable
# this feature for production builds on architectures where valgrind is known
# to be less reliable, in order to avoid unnecessary build failures (see RHBZ
# #810992, #816175, and #886891).  Nevertheless developers are free to install
# valgrind manually to improve test coverage on any architecture.
%ifarch x86_64
BuildRequires: valgrind
%endif

# stunnel is used by upstream tests but it does not seem to work reliably
# on aarch64/s390x and occasionally breaks some tests (mainly 1561 and 1562)
%ifnarch aarch64 s390x
BuildRequires: stunnel
%endif

# using an older version of libcurl could result in CURLE_UNKNOWN_OPTION
Requires: libcurl%{?_isa} >= %{version}-%{release}

# require at least the version of libnghttp2 that we were built against,
# to ensure that we have the necessary symbols available (#2144277)
%global libnghttp2_version %(pkg-config --modversion libnghttp2 2>/dev/null || echo 0)

# require at least the version of libpsl that we were built against,
# to ensure that we have the necessary symbols available (#1631804)
%global libpsl_version %(pkg-config --modversion libpsl 2>/dev/null || echo 0)

# require at least the version of libssh that we were built against,
# to ensure that we have the necessary symbols available (#525002, #642796)
%if %{without xcpng}
%global libssh_version %(pkg-config --modversion libssh 2>/dev/null || echo 0)
%else
%global libssh_version %(pkg-config --modversion libssh2 2>/dev/null || echo 0)
%endif

# require at least the version of openssl-libs that we were built against,
# to ensure that we have the necessary symbols available (#1462184, #1462211)
# (we need to translate 3.0.0-alpha16 -> 3.0.0-0.alpha16 and 3.0.0-beta1 -> 3.0.0-0.beta1 though)
%global openssl_version %({ pkg-config --modversion openssl 2>/dev/null || echo 0;} | sed 's|-|-0.|')

%description
curl is a command line tool for transferring data with URL syntax, supporting
FTP, FTPS, HTTP, HTTPS, SCP, SFTP, TFTP, TELNET, DICT, LDAP, LDAPS, FILE, IMAP,
SMTP, POP3 and RTSP.  curl supports SSL certificates, HTTP POST, HTTP PUT, FTP
uploading, HTTP form based upload, proxies, cookies, user+password
authentication (Basic, Digest, NTLM, Negotiate, kerberos...), file transfer
resume, proxy tunneling and a busload of other useful tricks. 

%bcond openssl_engine %[!(0%{?rhel} >= 10)]

%package -n libcurl
Summary: A library for getting files from web servers
%if %{without xcpng}
Requires: libnghttp2%{?_isa} >= %{libnghttp2_version}
Requires: libpsl%{?_isa} >= %{libpsl_version}
Requires: libssh%{?_isa} >= %{libssh_version}
%else
Requires: libssh2%{?_isa} >= %{libssh_version}
%endif
Requires: openssl-libs%{?_isa} >= 1:%{openssl_version}
Provides: libcurl-full = %{version}-%{release}
Provides: libcurl-full%{?_isa} = %{version}-%{release}

%description -n libcurl
libcurl is a free and easy-to-use client-side URL transfer library, supporting
FTP, FTPS, HTTP, HTTPS, SCP, SFTP, TFTP, TELNET, DICT, LDAP, LDAPS, FILE, IMAP,
SMTP, POP3 and RTSP. libcurl supports SSL certificates, HTTP POST, HTTP PUT,
FTP uploading, HTTP form based upload, proxies, cookies, user+password
authentication (Basic, Digest, NTLM, Negotiate, Kerberos4), file transfer
resume, http proxy tunneling and more.

%package -n libcurl-devel
Summary: Files needed for building applications with libcurl
Requires: libcurl%{?_isa} = %{version}-%{release}

Provides: curl-devel = %{version}-%{release}
Provides: curl-devel%{?_isa} = %{version}-%{release}
Obsoletes: curl-devel < %{version}-%{release}

%description -n libcurl-devel
The libcurl-devel package includes header files and libraries necessary for
developing programs which use the libcurl library. It contains the API
documentation of the library, too.

%if %{with build_minimal}
%package -n libcurl-minimal
Summary: Conservatively configured build of libcurl for minimal installations
Requires: libnghttp2%{?_isa} >= %{libnghttp2_version}
Requires: openssl-libs%{?_isa} >= 1:%{openssl_version}
Provides: libcurl = %{version}-%{release}
Provides: libcurl%{?_isa} = %{version}-%{release}
Conflicts: libcurl%{?_isa}
RemovePathPostfixes: .minimal
# needed for RemovePathPostfixes to work with shared libraries
%undefine __brp_ldconfig

%description -n libcurl-minimal
This is a replacement of the 'libcurl' package for minimal installations.  It
comes with a limited set of features compared to the 'libcurl' package.  On the
other hand, the package is smaller and requires fewer run-time dependencies to
be installed.
%endif

%prep
%if %{without xcpng}
%{gpgverify} --keyring='%{SOURCE2}' --signature='%{SOURCE1}' --data='%{SOURCE0}'
%endif
%autosetup -p1

# test3026: avoid pthread_create() failure due to resource exhaustion on i386
%ifarch %{ix86}
sed -e 's|NUM_THREADS 1000$|NUM_THREADS 256|' \
    -i tests/libtest/lib3026.c
%endif

# adapt test 323 for updated OpenSSL
sed -e 's|^35$|35,52|' -i tests/data/test323

# use localhost6 instead of ip6-localhost in the curl test-suite
(
    # avoid glob expansion in the trace output of `bash -x`
    { set +x; } 2>/dev/null
    cmd="sed -e 's|ip6-localhost|localhost6|' -i tests/data/test[0-9]*"
    printf "+ %s\n" "$cmd" >&2
    eval "$cmd"
)

%if %{without xcpng}
# disable test for NSS cipher compatibility
printf "4001\n" >> tests/data/DISABLED
%endif

# regenerate the configure script and Makefile.in files
autoreconf -fiv

%build

%if %{without openssl_engine}
export CPPFLAGS="$CPPFLAGS -DOPENSSL_NO_ENGINE"
%endif

mkdir build-{full,minimal}
export common_configure_opts="          \
    --cache-file=../config.cache        \
    --disable-manual                    \
    --disable-static                    \
    --enable-hsts                       \
    --enable-ipv6                       \
    --enable-symbol-hiding              \
    --enable-threaded-resolver          \
    --without-zstd                      \
    --with-gssapi                       \
    --with-libidn2                      \
%if %{without xcpng}
    --with-nghttp2                      \
%else
    --without-nghttp2                   \
    --enable-nss-cipher-compat          \
%endif
    --with-ssl --with-ca-bundle=%{_sysconfdir}/pki/tls/certs/ca-bundle.crt \
    --with-zsh-functions-dir"

%global _configure ../configure

%if %{with build_minimal}
# configure minimal build
(
    cd build-minimal
    %configure $common_configure_opts   \
        --disable-dict                  \
        --disable-gopher                \
        --disable-imap                  \
        --disable-ldap                  \
        --disable-ldaps                 \
        --disable-mqtt                  \
        --disable-ntlm                  \
        --disable-ntlm-wb               \
        --disable-pop3                  \
        --disable-rtsp                  \
        --disable-smb                   \
        --disable-smtp                  \
        --disable-telnet                \
        --disable-tftp                  \
        --disable-tls-srp               \
        --disable-websockets            \
        --without-brotli                \
        --without-libpsl                \
        --without-libssh
)
%endif

# configure full build
(
    cd build-full
    %configure $common_configure_opts   \
        --enable-dict                   \
        --enable-gopher                 \
        --enable-imap                   \
        --enable-ldap                   \
        --enable-ldaps                  \
%if %{without xcpng}
        --enable-mqtt                   \
%else
        --disable-mqtt                  \
%endif
        --enable-ntlm                   \
%if %{without xcpng}
        --enable-ntlm-wb                \
%else
        --disable-ntlm-wb               \
%endif
        --enable-pop3                   \
        --enable-rtsp                   \
%if %{without xcpng}
        --enable-smb                    \
%else
        --disable-smb                   \
%endif
        --enable-smtp                   \
        --enable-telnet                 \
        --enable-tftp                   \
%if %{without xcpng}
        --enable-tls-srp                \
        --enable-websockets             \
        --with-brotli                   \
        --with-libpsl                   \
        --with-libssh
%else
        --disable-tls-srp               \
        --disable-websockets            \
        --disable-alt-svc               \
        --without-brotli                \
        --without-libpsl                \
        --with-libssh2
%endif
)

# avoid using rpath
sed -e 's/^runpath_var=.*/runpath_var=/' \
    -e 's/^hardcode_libdir_flag_spec=".*"$/hardcode_libdir_flag_spec=""/' \
%if %{with build_minimal}
    -i build-{full,minimal}/libtool
%else
    -i build-full/libtool
%endif

%if %{with build_minimal}
%make_build V=1 -C build-minimal
%endif
%make_build V=1 -C build-full

%check
# compile upstream test-cases
%if %{with build_minimal}
%make_build V=1 -C build-minimal/tests
%endif
%make_build V=1 -C build-full/tests

# relax crypto policy for the test-suite to make it pass again (#1610888)
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE=XXX
export OPENSSL_CONF=

# make runtests.pl work for out-of-tree builds
export srcdir=../../tests

# prevent valgrind from being extremely slow (#1662656)
# https://fedoraproject.org/wiki/Changes/DebuginfodByDefault
unset DEBUGINFOD_URLS

# run the upstream test-suite for both curl-minimal and curl-full
%if %{with build_minimal}
for size in minimal full; do (
%else
for size in full; do (
%endif
    cd build-${size}

    # we have to override LD_LIBRARY_PATH because we eliminated rpath
    export LD_LIBRARY_PATH="${PWD}/lib/.libs"

    cd tests
    perl -I../../tests ../../tests/runtests.pl -a -p -v '!flaky'
)
done


%install
%if %{with build_minimal}
# install and rename the library that will be packaged as libcurl-minimal
%make_install -C build-minimal/lib
rm -f ${RPM_BUILD_ROOT}%{_libdir}/libcurl.{la,so}
for i in ${RPM_BUILD_ROOT}%{_libdir}/*; do
    mv -v $i $i.minimal
done
%endif

# install libcurl.m4
install -d $RPM_BUILD_ROOT%{_datadir}/aclocal
install -m 644 docs/libcurl/libcurl.m4 $RPM_BUILD_ROOT%{_datadir}/aclocal

# install the executable and library that will be packaged as curl and libcurl
cd build-full
%make_install

# install zsh completion for curl
# (we have to override LD_LIBRARY_PATH because we eliminated rpath)
LD_LIBRARY_PATH="$RPM_BUILD_ROOT%{_libdir}:$LD_LIBRARY_PATH" \
    %make_install -C scripts

# do not install /usr/share/fish/completions/curl.fish which is also installed
# by fish-3.0.2-1.module_f31+3716+57207597 and would trigger a conflict
rm -rf ${RPM_BUILD_ROOT}%{_datadir}/fish

rm -f ${RPM_BUILD_ROOT}%{_libdir}/libcurl.la

# Don't install man for mk-ca-bundle it's upstream bug
# should be fixed in next release https://github.com/curl/curl/pull/12843
rm -f ${RPM_BUILD_ROOT}%{_mandir}/man1/mk-ca-bundle.1*

%ldconfig_scriptlets -n libcurl

%if %{with build_minimal}
%ldconfig_scriptlets -n libcurl-minimal
%endif

%files
%doc CHANGES
%doc README
%doc docs/BUGS.md
%doc docs/FAQ
%doc docs/FEATURES.md
%doc docs/TODO
%doc docs/TheArtOfHttpScripting.md
%{_bindir}/curl
%{_mandir}/man1/curl.1*
%{_datadir}/zsh

%files -n libcurl
%license COPYING
%{_libdir}/libcurl.so.4
%{_libdir}/libcurl.so.4.[0-9].[0-9]

%files -n libcurl-devel
%doc docs/examples/*.c docs/examples/Makefile.example docs/INTERNALS.md
%doc docs/CONTRIBUTE.md docs/libcurl/ABI.md
%{_bindir}/curl-config*
%{_includedir}/curl
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_mandir}/man1/curl-config.1*
%{_mandir}/man3/*
%{_datadir}/aclocal/libcurl.m4

%if %{with build_minimal}
%files -n libcurl-minimal
%license COPYING
%{_libdir}/libcurl.so.4.minimal
%{_libdir}/libcurl.so.4.[0-9].[0-9].minimal
%endif

%changelog
* Mon Apr 28 2025 Thierry Escande <thierry.escande@vates.tech> - 8.9.1-5.1
- Restore changes from original fc40 specfile
- Add %bcond xcpng for specific XCP-ng build directives
- Add %bcond build_minimal to disable libcurl-minimal package build
- Update to curl v8.9.1 from el10 srpm
- Port NSS cipher compat list patch and tests from XS8
- Backport patch for CVE 2024-8096
- *** Upstream changelog ***
  * Tue Oct 29 2024 Troy Dawson <tdawson@redhat.com> - 8.9.1-5
  - Bump release for October 2024 mass rebuild:
    Resolves: RHEL-64018
  * Mon Aug 19 2024 Jacek Migacz <jmigacz@redhat.com> - 8.9.1-4
  - correct indentation in test plan
  * Fri Aug 02 2024 Jacek Migacz <jmigacz@redhat.com> - 8.9.1-3
  - fix libcurl and libcurl-minimal conflict in test plan (RHEL-52103)
  * Fri Aug 02 2024 Jacek Migacz <jmigacz@redhat.com> - 8.9.1-2
  - add gating configuration (RHEL-52103)
  - sigpipe: init the struct so that first apply ignores (RHEL-53327)
  * Wed Jul 31 2024 Jacek Migacz <jmigacz@redhat.com> - 8.9.1-1
  - new upstream release (RHEL-50806)
  * Tue Jul 9 2024 Jacek Migacz <jmigacz@redhat.com> - 8.6.0-8
  - disable OpenSSL Engine API support (RHEL-30436)
  - setopt: Fix disabling all protocols (CVE-2024-2004)
  - http2: push headers better cleanup (CVE-2024-2398)
  * Mon Jun 24 2024 Troy Dawson <tdawson@redhat.com> - 8.6.0-7
  - Bump release for June 2024 mass rebuild
  * Mon Feb 12 2024 Jan Macku <jamacku@redhat.com> - 8.6.0-6
  - revert "receive max buffer" + add test case
  - temporarily disable test 0313
  - remove suggests of libcurl-minimal in curl-full
  * Mon Feb 12 2024 Jan Macku <jamacku@redhat.com> - 8.6.0-5
  - add Provides to curl-minimal
  * Wed Feb 07 2024 Jan Macku <jamacku@redhat.com> - 8.6.0-4
  - drop curl-minimal subpackage in favor of curl-full (#2262096)
  * Mon Feb 05 2024 Jan Macku <jamacku@redhat.com> - 8.6.0-3
  - ignore response body to HEAD requests

* Wed Aug 07 2024 Thierry Escande <thierry.escande@vates.tech> - 8.6.0-2.2
- Backported CVEs 2024-2004, 2024-2379, 2024-2398, 2024-2466, 2024-6197, and 2024-7264

* Fri May 31 2024 Gael Duperrey <gduperrey@vates.tech> - 8.6.0-2.1
- Synced from curl-8.6.0-2.xs8.src.rpm
- Removed xenserver-specific test of the dist macro

* Thu Mar 07 2024 Frediano Ziglio <frediano.ziglio@cloud.com> - 8.6.0-2
- Update release;
- Add compatibility patch for NSS cipher list support.

* Thu Feb 22 2024 Frediano Ziglio <frediano.ziglio@cloud.com> - 7.85.0-2
- Fix typo in series file

* Tue Jul 18 2023 Lin Liu <lin.liu@citrix.com> - 7.85.0-1
- First imported release

