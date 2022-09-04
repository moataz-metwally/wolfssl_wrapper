/**
* @file   wolfssl_wrapper.h
* @brief  This file is the header for the application wolfssl_wrapper.
*
* This wrapper allows any application to create an encrypted TLS session
* with another client or server, using the lightweight wolfSSL API.
*/

#ifndef WOLFSSL_WRAPPER_H_
#define WOLFSSL_WRAPPER_H_

#include "wolfssl/ssl.h"
#include <stdbool.h>
#include <stdint.h>

/*
 * CONSTANTS AND MACROS
 */

#define CLIENT_CERT_FILE "/ca.pem"
#define SERVER_CERT_FILE "/server.pem"
#define KEY_FILE  "/server.key"

#define PATH_SIZE 256
#define SERVER_PENDING_CONNECTIONS 5

typedef int8_t E_RETURN;

/*
 * ENUMS AND TYPEDEFS
 */

enum eWrapperErrors {
    E_NULL_POINTER = -15,
    E_NULL_STRUCT = -14,
    E_CIPHER = -13,
    E_READ = -12,
    E_WRITE = -11,
    E_WOLFSSL_CONNECT = -10,
    E_ACCEPT = -9,
    E_LISTEN = -8,
    E_BIND = -7,
    E_FAILED_CERT_LOAD = -6,
    E_WOLFSSL_SET_FD = -5,
    E_WOLFSSL_NEW = -4,
    E_CONNECT = -3,
    E_INET_PTON = -2,
    E_SSL_CTX = -1,
    E_SUCCESS = 0,
};

typedef struct {
    /*User Variables*/
    unsigned int port;
    WOLFSSL_METHOD* (*wolfSSLMethod)(void);
    int16_t sockFd;
    bool wolfSSLDebug;
    /*Only for PSK*/
    unsigned int ( *wolfSSLClientCallback)(WOLFSSL*, const char*,char*, unsigned int, unsigned char*,unsigned int );
    unsigned int ( *wolfSSLServerCallback)(WOLFSSL*, const char*, unsigned char*, unsigned int );
    /*PSK Server Only*/
    char cipherList[512];
    char identityHint[64];
    /*Only for Cert*/
    char certFullPath[PATH_SIZE];

    /*Internal*/
    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;
    int16_t connd;
    struct sockaddr_in clientAddr;
    socklen_t clientSize;
}TLSConnection;

/*
 * PROTOTYPES
 */

 /**
 * @brief   Sets all required parameters to start a PSK Client.
 *
 * @param   connection   An empty TLSConnection struct.
 * @param   ipAddress    Server's IP address.
 * @param   port         Server's port.
 * @param   wolfSSLMethod WolfSSL method to be used.
 * @param   sockFd       Socket file descriptor.
 * @param   wolfSSLClientCallback Callback pointer to set up PSK and identity.
 * @param   wolfSSLDebug Set to true to enable wolfSSL debug.
 */
E_RETURN setPSKClient( TLSConnection * pConnection, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const uint16_t sockFd, unsigned int ( *wolfSSLClientCallback)(WOLFSSL*, const char*,char*, unsigned int, unsigned char*,unsigned int ), bool wolfSSLDebug );
/**
* @brief   Sets all required parameters to start a PSK Server.
*
* @param   connection   An empty TLSConnection struct.
* @param   port         Server's port.
* @param   wolfSSLMethod WolfSSL method to be used.
* @param   sockFd       Socket file descriptor.
* @param   wolfSSLServerCallback Callback pointer to set up PSK and identity.
* @param   wolfSSLDebug Set to true to enable wolfSSL debug.
*/
E_RETURN setPSKServer( TLSConnection * pConnection, const uint16_t port, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const uint16_t sockFd, unsigned int ( *wolfSSLServerCallback)(WOLFSSL*, const char*, unsigned char*, unsigned int ), const char *cipherList, const char *identityHint, bool wolfSSLDebug );

/**
* @brief   Sets all required parameters to start a Certificate Client.
*
* @param   connection   An empty TLSConnection struct.
* @param   ipAddress    Server's IP address.
* @param   port         Server's port.
* @param   wolfSSLMethod WolfSSL method to be used.
* @param   certFullPath Path to certificate directory.
* @param   sockFd       Socket file descriptor.
* @param   wolfSSLDebug Set to true to enable wolfSSL debug.
*/
E_RETURN setCertificatesClient( TLSConnection * pConnection, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const char * certFullPath, const uint16_t sockFd, bool wolfSSLDebug );
/**
* @brief   Sets all required parameters to start a Certificate Server.
*
* @param   connection   An empty TLSConnection struct.
* @param   port         Server's port.
* @param   wolfSSLMethod WolfSSL method to be used.
* @param   certFullPath Path to certificate directory.
* @param   sockFd       Socket file descriptor.
* @param   wolfSSLDebug Set to true to enable wolfSSL debug.
*/
E_RETURN setCertificatesServer( TLSConnection * pConnection, const uint16_t port, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const char * certFullPath, const uint16_t sockFd, bool wolfSSLDebug );

/**
* @brief   Initiates a client and a TLS connection with a server using PSK.
* @details This function will initiate a client's TLS connection to a server
* using PSK. It requires the TLSConnection struct to be assigned with the server's
* IP address, the server's port,the wolfSSL method, the previsously created
* socket fd and a pointer to the wolfSSL PSK callback (where identity and key
* are set).
*
* @param   connection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initTLSClientPSK( TLSConnection * pConnection );
/**
* @brief   Initiates a server and a TLS connection with a client using PSK.
* @details This function will initiate a server's TLS connection to a client
* using PSK. It requires the TLSConnection struct to be assigned with the client's
* IP address, the client's port,the wolfSSL method, the previsously created
* socket fd and a pointer to the wolfSSL PSK callback (where identity and key
* are set).
*
* @param   connection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initAndAcceptTLSServerPSK( TLSConnection * pConnection );

/**
* @brief   Initiates a client and a TLS connection with a server using Certificates.
* @details This function will initiate a client's TLS connection to a server
* using Certificates. It requires the TLSConnection struct to be assigned with the
* server's IP address, the server's port,the wolfSSL method, the previsously created
* socket fd and the full path to the certificates directory.
*
* @param   connection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initTLSClientCert( TLSConnection * pConnection );
/**
* @brief   Initiates a server and a TLS connection with a client using Certificates.
* @details This function will initiate a server's TLS connection to a client
* using Certificates. It requires the TLSConnection struct to be assigned with the client's
* IP address, the client's port,the wolfSSL method, the previsously created
* socket fd and the full path to the certificate's directory.
*
* @param   connection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initAndAcceptTLSServerCert( TLSConnection * pConnection );

/**
* @brief   Writes to the TLS connection.
* @details This function will write into the respective encrypted TLS connection.
*
* @param    connection  A TLSConnection struct with the connection parameters.
* @param    data        Data to be sent.
* @param    size        Size of data to be written.
*/
E_RETURN writeToTLSConnection( TLSConnection * pConnection , const void* data, int32_t size );
/**
* @brief   Reads from the TLS connection.
* @details This function will block and read from the respective encrypted TLS connection.
*
* @param    pConnection  A TLSConnection struct with the connection parameters.
* @param    data        Pointer to buffer where read data will be stored.
* @param    size        Number of bytes to be read.
* @param    pReceivedBytes Actual number of received bytes.
*/
E_RETURN readFromTLSConnection( TLSConnection * pConnection , void* data, int32_t size, int32_t * pReceivedBytes );

/**
* @brief   Disconnects the server from the TLS connection.
* @details This function must be called to disconnect the server from the TLS
* connection and clean and free the respective resources.
*
* @param    connection  A TLSConnection struct with the connection parameters.
*/
E_RETURN disconnectTLSServer( TLSConnection * pConnection );
/**
* @brief   Disconnects the client from the TLS connection.
* @details This function must be called to disconnect the client from the TLS
* connection and clean and free the respective resources.
*
* @param    connection  A TLSConnection struct with the connection parameters.
*/
E_RETURN disconnectTLSClient( TLSConnection * pConnection );

#endif // WOLFSSL_WRAPPER_H_
