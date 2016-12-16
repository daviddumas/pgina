#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <Windows.h>
#include "libssh2/libssh2.h"

// Add dependencies that VS cannot infer from source:
// 1. Windows static libraries with crypto and socket functions referenced by openssl
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"crypt32.lib")
// 2. Static libraries needed for libssh2: zlib, openssl
#pragma comment(lib,"zlib/zlibstat.lib")
#pragma comment(lib,"openssl/libssl.lib")
#pragma comment(lib,"openssl/libcrypto.lib")
// 3. libssh2 itself
#pragma comment(lib,"libssh2/libssh2.lib")

using namespace std;

extern "C" {
	__declspec(dllexport) int ssh_connect_and_pw_auth(const char *host, const char *port, const char *user, const char *password, char *errmsg, const int errlen)
	{
		int rc = 0;
		WSADATA wsa_data;
		LIBSSH2_SESSION *ssh_session = NULL;
		ADDRINFO *addr_info = NULL;
		SOCKET sock;
		char *ssh_err_desc;

		rc = WSAStartup(WINSOCK_VERSION, &wsa_data);
		if (rc != 0) {
			snprintf(errmsg, errlen, "WSAStartup failed");
			return 1;
		}

		rc = getaddrinfo(host, port, NULL, &addr_info);
		if (rc) {
			snprintf(errmsg, errlen, "Host name resolution failure (%d)", rc);
			if (addr_info != NULL)
				freeaddrinfo(addr_info);
			return 1;
		}

		// TODO support iteration over entire list returned by getaddrinfo
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == INVALID_SOCKET) {
			snprintf(errmsg, errlen, "Failed to open socket");
			return 1;
		}

		rc = connect(sock, addr_info->ai_addr, addr_info->ai_addrlen);
		if (rc == SOCKET_ERROR) {
			snprintf(errmsg, errlen, "Failed to open TCP connection");
			closesocket(sock);
			freeaddrinfo(addr_info);
			return 1;
		}

		rc = libssh2_init(0);
		if (rc) {
			snprintf(errmsg, errlen, "libssh2 initialization failed (%d)\n", rc);
			closesocket(sock);
			freeaddrinfo(addr_info);
			return 1;
		}

		ssh_session = libssh2_session_init();
		if (ssh_session == NULL) {
			snprintf(errmsg, errlen, "Failed to allocate SSH session data structure (libssh2_session_init returned %d)", rc);
			closesocket(sock);
			freeaddrinfo(addr_info);
			return 1;
		}

		rc = libssh2_session_handshake(ssh_session, (int)sock);
		if (rc) {
			libssh2_session_last_error(ssh_session, &ssh_err_desc, NULL, 0);
			snprintf(errmsg, errlen, "Failed SSH handshake (%d=%s)", rc, ssh_err_desc);
			libssh2_session_free(ssh_session);
			closesocket(sock);
			freeaddrinfo(addr_info);
			return 1;
		}

		rc = libssh2_userauth_password(ssh_session, user, password);
		// now rc == 0 iff successful authentication; do cleanup and return this code.

		if (rc) {
			// retrieve error details (likely, incorrect password)
			libssh2_session_last_error(ssh_session, &ssh_err_desc, NULL, 0);
			snprintf(errmsg, errlen, "SSH authentication failed for user %s (%d: %s)", user, rc, ssh_err_desc);
		}

		libssh2_session_disconnect(ssh_session, "Finished");
		libssh2_session_free(ssh_session);
		closesocket(sock);
		freeaddrinfo(addr_info);
		return rc;
	}
};