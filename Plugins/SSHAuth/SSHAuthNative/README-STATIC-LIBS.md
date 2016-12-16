This plugin generates a single DLL which contains all of the native
code needed for SSH authentication.  Since we use libssh2, which
relies on OpenSSL and Zlib, the extension must be linked with these
static libraries.

The static libraries included here are derived from the following
versions of their respective sources, all compiled using Visual Studio
Community 2015 version 14.0.25431 Update 3:

libssh2 1.8.0 available from https://www.libssh2.org/
	libssh2/libssh2.lib (sha1 d68728102f6ffaecb9352117604021ff84dcf3ee)

OpenSSL 1.1.0c available from https://www.openssl.org/
     openssl/libcrypto.lib (sha1 ae73061248641da3b4542e412e29fed5e95a20c3)
     openssl/libssl.lib (sha1 33b2fa1090faa232b02c7f67914062ebf037467d)

Zlib 1.2.8 available from http://www.zlib.net/
     zlib/zlibstat.lib (sha1 a032c7e4a0cbbaf6e441815ddf4d300783847883)
