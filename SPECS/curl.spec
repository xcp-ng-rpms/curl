Summary: A utility for getting files from remote servers (FTP, HTTP, and others)
Name: curl
Version: 8.12.1
Release: 1%{?dist}
License: MIT
Source0: curl-8.12.1.tar.gz
#Patch0: 0001-curl-8.6.0-remove-duplicate-content.patch # Merged upstream
#Patch1: 0002-curl-8.6.0-ignore-response-body-to-HEAD.patch # Merged upstream
#Patch2: 0003-curl-8.6.0-vtls-revert-receive-max-buffer-add-test-case.patch # Merged upstream
#Patch3: 0004-curl-8.6.0-http_chunks-fix-the-accounting-of-consumed-bytes.patch # Merged upstream
Patch4: 0101-curl-8.12.1-multilib.patch
Patch5: 0102-curl-7.84.0-test3026.patch
#Patch6: 0104-curl-7.88.0-tests-warnings.patch # Merged upstream
#Patch7: 0200-curl-8.6.0-ntml_wb-fix-buffer-type-typo.patch # Merged upstream
Patch8: 0300-curl-8.12.1-nss-compat.patch
Patch9: 0301-curl-8.12.1-tests.patch

Provides: curl-full = %{version}-%{release}
Provides: webclient
URL: https://curl.se/
BuildRequires: automake
BuildRequires: coreutils
BuildRequires: gcc
BuildRequires: groff
BuildRequires: krb5-devel
%if 0%{?xenserver} > 8
BuildRequires: libidn2-devel
%global libssh libssh
%else
BuildRequires: libidn-devel
%global libssh libssh2
%endif
BuildRequires: %{libssh}-devel
BuildRequires: libtool
BuildRequires: make
BuildRequires: openldap-devel
BuildRequires: openssh-clients
BuildRequires: openssh-server
BuildRequires: openssl-devel
BuildRequires: perl-interpreter
BuildRequires: pkgconfig
%if 0%{?xenserver} > 8
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

%if 0%{?xenserver} > 8
# needed for test1560 to succeed
BuildRequires: glibc-langpack-en
%endif

# gnutls-serv is used by the upstream test-suite
BuildRequires: gnutls-utils

# hostname(1) is used by the test-suite but it is missing in armv7hl buildroot
BuildRequires: hostname

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
%global libssh_version %(pkg-config --modversion %{libssh} 2>/dev/null || echo 0)

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

%package -n libcurl
Summary: A library for getting files from web servers
Requires: %{libssh}%{?_isa} >= %{libssh_version}
Requires: openssl-libs%{?_isa} >= %{openssl_version}
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

%prep
%autosetup -p1

# temporarily disable test 0313
# <https://bugzilla.redhat.com/show_bug.cgi?id=2263877>
# <https://github.com/curl/curl/pull/11531>
# disable test 1801
# <https://github.com/bagder/curl/commit/21e82bd6#commitcomment-12226582>
printf "313\n1801\n" >> tests/data/DISABLED

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

%if 0%{?xenserver} > 8
# disable test for NSS cipher compatibility
printf "4001\n" >> tests/data/DISABLED
%endif

# regenerate the configure script and Makefile.in files
autoreconf -fiv

%build
mkdir build-full
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
    --without-nghttp2                   \
    --with-zsh-functions-dir            \
%if 0%{?xenserver} <= 8
    --enable-nss-cipher-compat          \
%endif
    --with-ssl --with-ca-bundle=%{_sysconfdir}/pki/tls/certs/ca-bundle.crt"

%global _configure ../configure

# configure full build
(
    cd build-full
    %configure $common_configure_opts   \
        --enable-dict                   \
        --enable-gopher                 \
        --enable-imap                   \
        --enable-ldap                   \
        --enable-ldaps                  \
        --disable-mqtt                  \
        --enable-ntlm                   \
        --disable-ntlm-wb               \
        --enable-pop3                   \
        --enable-rtsp                   \
        --disable-smb                   \
        --enable-smtp                   \
        --enable-telnet                 \
        --enable-tftp                   \
        --disable-tls-srp               \
        --disable-websockets            \
        --disable-alt-svc               \
        --disable-tls-srp               \
        --without-brotli                \
        --without-libpsl                \
        --with-${libssh}
)

# avoid using rpath
sed -e 's/^runpath_var=.*/runpath_var=/' \
    -e 's/^hardcode_libdir_flag_spec=".*"$/hardcode_libdir_flag_spec=""/' \
    -i build-full/libtool

%make_build V=1 -C build-full

%check
# compile upstream test-cases
%make_build V=1 -C build-full/tests

# relax crypto policy for the test-suite to make it pass again (#1610888)
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE=XXX
export OPENSSL_CONF=

# make runtests.pl work for out-of-tree builds
export srcdir=../../tests

# prevent valgrind from being extremely slow (#1662656)
# https://fedoraproject.org/wiki/Changes/DebuginfodByDefault
unset DEBUGINFOD_URLS

# run the upstream test-suite
for size in full; do (
    cd build-${size}

    # we have to override LD_LIBRARY_PATH because we eliminated rpath
    export LD_LIBRARY_PATH="${PWD}/lib/.libs"

    cd tests
    perl -I../../tests ../../tests/runtests.pl -a -p -v '!flaky'
)
done


%install
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

%files
%doc CHANGES.md
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

%changelog
* Thu Mar 20 2025 Thierry Escande <thierry.escande@vates.tech> - 8.12.1-1
- Import curl-8.12.1.tar.gz
- Remove upstream patches and CVEs
- Backport needed patches

* Wed Aug 07 2024 Thierry Escande <thierry.escande@vates.tech> - 8.6.0-2.2
- Backported CVEs 2024-2004, 2024-2379, 2024-2398, 2024-2466, 2024-6197, and 2024-7264

* Wed May 31 2024 Gael Duperrey <gduperrey@vates.tech> - 8.6.0-2.1
- Synced from curl-8.6.0-2.xs8.src.rpm
- Removed xenserver-specific test of the dist macro

* Thu Mar 07 2024 Frediano Ziglio <frediano.ziglio@cloud.com> - 8.6.0-2
- Update release;
- Add compatibility patch for NSS cipher list support.

* Thu Feb 22 2024 Frediano Ziglio <frediano.ziglio@cloud.com> - 7.85.0-2
- Fix typo in series file

* Tue Jul 18 2023 Lin Liu <lin.liu@citrix.com> - 7.85.0-1
- First imported release

