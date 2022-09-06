/**
* @file   wolfssl_wrapper.c
* @brief  This file is the source code for the application wolfssl_wrapper.
*
* This wrapper allows any application to create an encrypted TLS session
* with another client or server, using the lightweight wolfSSL API.
*/

#include "wolfssl/ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include "wolfssl_wrapper.h"

/*
* GLOBAL DATA
*/

static bool WolfSSLInitialized = false;

/*
* CODE
*/

/**
* @brief   Sets all required parameters to start a PSK Client.
*
* @param   pConnection   An empty TLSConnection struct.
* @param   ipAddress    Server's IP address.
* @param   port         Server's port.
* @param   wolfSSLMethod WolfSSL method to be used.
* @param   sockFd       Socket file descriptor.
* @param   wolfSSLClientCallback Callback pointer to set up PSK and identity.
* @param   wolfSSLDebug Set to true to enable wolfSSL debug.
*/
E_RETURN setPSKClient( TLSConnection * pConnection, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const uint16_t sockFd, unsigned int ( *wolfSSLClientCallback)(WOLFSSL*, const char*,char*, unsigned int, unsigned char*,unsigned int ), bool wolfSSLDebug )
{
    if( pConnection ){
        pConnection->wolfSSLMethod = wolfSSLMethod;
        pConnection->sockFd = sockFd;
        pConnection->wolfSSLClientCallback = wolfSSLClientCallback;
        pConnection->wolfSSLDebug = wolfSSLDebug;
    }else{
        return E_NULL_STRUCT;
    }
    return E_SUCCESS;
}

/**
* @brief   Sets all required parameters to start a PSK Server.
*
* @param   pConnection   An empty TLSConnection struct.
* @param   port         Server's port.
* @param   wolfSSLMethod WolfSSL method to be used.
* @param   sockFd       Socket file descriptor.
* @param   wolfSSLServerCallback Callback pointer to set up PSK and identity.
* @param   wolfSSLDebug Set to true to enable wolfSSL debug.
*/
E_RETURN setPSKServer( TLSConnection * pConnection, const uint16_t port, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const uint16_t sockFd, unsigned int ( *wolfSSLServerCallback)(WOLFSSL*, const char*, unsigned char*, unsigned int ), const char *cipherList, const char *identityHint, bool wolfSSLDebug )
{
    if( pConnection ){
        pConnection->port = port;
        pConnection->wolfSSLMethod = wolfSSLMethod;
        pConnection->sockFd = sockFd;
        pConnection->wolfSSLServerCallback = wolfSSLServerCallback;
        strncpy( pConnection->cipherList, cipherList, sizeof( pConnection->cipherList ) );
        strncpy( pConnection->identityHint, identityHint, sizeof( pConnection->identityHint ) );
        pConnection->wolfSSLDebug = wolfSSLDebug;
    }else{
        return E_NULL_STRUCT;
    }
    return E_SUCCESS;
}

/**
* @brief   Sets all required parameters to start a Certificate Client.
*
* @param   pConnection   An empty TLSConnection struct.
* @param   ipAddress    Server's IP address.
* @param   port         Server's port.
* @param   wolfSSLMethod WolfSSL method to be used.
* @param   certFullPath Path to certificate directory.
* @param   sockFd       Socket file descriptor.
* @param   wolfSSLDebug Set to true to enable wolfSSL debug.
*/
E_RETURN setCertificatesClient( TLSConnection * pConnection, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const char * certFullPath, const uint16_t sockFd, bool wolfSSLDebug )
{
    if( pConnection ){
        pConnection->wolfSSLMethod = wolfSSLMethod;
        pConnection->sockFd = sockFd;
        strncpy( pConnection->certFullPath, certFullPath, sizeof( pConnection->certFullPath ) );
        pConnection->wolfSSLDebug = wolfSSLDebug;
    }else{
        return E_NULL_STRUCT;
    }
    return E_SUCCESS;
}

/**
* @brief   Sets all required parameters to start a Certificate Server.
*
* @param   pConnection   An empty TLSConnection struct.
* @param   port         Server's port.
* @param   wolfSSLMethod WolfSSL method to be used.
* @param   certFullPath Path to certificate directory.
* @param   sockFd       Socket file descriptor.
* @param   wolfSSLDebug Set to true to enable wolfSSL debug.
*/
E_RETURN setCertificatesServer( TLSConnection * pConnection, const uint16_t port, WOLFSSL_METHOD* (*wolfSSLMethod)(void), const char * certFullPath, const uint16_t sockFd, bool wolfSSLDebug )
{
    if( pConnection ){
        pConnection->port = port;
        pConnection->wolfSSLMethod = wolfSSLMethod;
        pConnection->sockFd = sockFd;
        strncpy( pConnection->certFullPath, certFullPath, sizeof( pConnection->certFullPath ) );
        pConnection->wolfSSLDebug = wolfSSLDebug;
    }else{
        return E_NULL_STRUCT;
    }
    return E_SUCCESS;
}

/**
* @brief   Initiates a client and a TLS connection with a server using PSK.
* @details This function will initiate a client's TLS connection to a server
* using PSK. It requires the TLSConnection struct to be assigned with the server's
* IP address, the server's port,the wolfSSL method, the previsously created
* socket fd and a pointer to the wolfSSL PSK callback (where identity and key
* are set).
*
* @param   pConnection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initTLSClientPSK( TLSConnection * pConnection )
{
    int32_t ret;

    if( !pConnection ){
        return E_NULL_STRUCT;
    }

    if( !WolfSSLInitialized ){
        /* Initialize wolfSSL */
        wolfSSL_Init();
        WolfSSLInitialized = true;
    }

    if( pConnection->wolfSSLDebug ){
        wolfSSL_Debugging_ON();
    }else{
        wolfSSL_Debugging_OFF();
    }

    /* Create and initialize WOLFSSL_CTX structure */
    if ( ( pConnection->ctx = wolfSSL_CTX_new( pConnection->wolfSSLMethod() ) ) == NULL ) {
        fprintf( stderr, "ERROR: SSL_CTX_new error.\n" );
        return E_SSL_CTX;
    }

    /* Set up pre shared keys */
    wolfSSL_CTX_set_psk_client_callback( pConnection->ctx, pConnection->wolfSSLClientCallback );


    /* Creat wolfssl object after each tcp connct */
    if ( ( pConnection->ssl = wolfSSL_new( pConnection->ctx ) ) == NULL ) {
        fprintf( stderr, "wolfSSL_new error.\n" );
        return E_WOLFSSL_NEW;
    }

    /* Associate the file descriptor with the session */
    ret = wolfSSL_set_fd( pConnection->ssl, pConnection->sockFd );

    if ( ret != SSL_SUCCESS ) {
        return E_WOLFSSL_SET_FD;
    }

    return E_SUCCESS;
}

/**
* @brief   Initiates a server and a TLS connection with a client using PSK.
* @details This function will initiate a server's TLS connection to a client
* using PSK. It requires the TLSConnection struct to be assigned with the client's
* IP address, the client's port,the wolfSSL method, the previsously created
* socket fd and a pointer to the wolfSSL PSK callback (where identity and key
* are set).
*
* @param   pConnection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initAndAcceptTLSServerPSK( TLSConnection * pConnection )
{
    struct sockaddr_in   servAddr;

    if( !pConnection ){
        return E_NULL_STRUCT;
    }

    if( !WolfSSLInitialized ){
        /* Initialize wolfSSL */
        wolfSSL_Init();
        WolfSSLInitialized = true;
    }

    if( pConnection->wolfSSLDebug ){
        wolfSSL_Debugging_ON();
    }else{
        wolfSSL_Debugging_OFF();
    }

    if( ( pConnection->ctx = wolfSSL_CTX_new( pConnection->wolfSSLMethod() )) == NULL ) {
        fprintf( stderr, "ERROR: wolfSSL_CTX_new error.\n" );
        return E_SSL_CTX;
    }

    /* Use psk suite for security */
    wolfSSL_CTX_set_psk_server_callback( pConnection->ctx, pConnection->wolfSSLServerCallback );
    wolfSSL_CTX_use_psk_identity_hint( pConnection->ctx, pConnection->identityHint );
    if (wolfSSL_CTX_set_cipher_list( pConnection->ctx, pConnection->cipherList ) != SSL_SUCCESS ) {
        fprintf( stderr, "ERROR: server can't set cipher list.\n" );
        return E_CIPHER;
    }

    /* Set up server address and port */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl( INADDR_ANY );
    servAddr.sin_port        = htons( pConnection->port );

    if ( bind( pConnection->sockFd, ( struct sockaddr * ) &servAddr, sizeof(servAddr)) < 0) {
        fprintf( stderr, "ERROR: bind error.\n" );
        return E_BIND;
    }

    /* listen to the socket */
    if ( listen( pConnection->sockFd, SERVER_PENDING_CONNECTIONS ) < 0) {
        fprintf( stderr, "ERROR: listen error.\n");
        return 1;
    }

    pConnection->clientSize = sizeof(pConnection->clientAddr);
    pConnection->connd = accept( pConnection->sockFd, (struct sockaddr *) &pConnection->clientAddr, &pConnection->clientSize);
    if ( pConnection->connd < 0 ) {
        fprintf( stderr, "ERROR: accept error.\n" );
        return E_ACCEPT;
    }

    /* Create WOLFSSL object */
    if ( ( pConnection->ssl = wolfSSL_new( pConnection->ctx ))  == NULL ) {
        fprintf( stderr, "ERROR: wolfSSL_new error.\n" );
        return E_WOLFSSL_NEW;
    }

    wolfSSL_set_fd( pConnection->ssl, pConnection->connd );

    return E_SUCCESS;
}

/**
* @brief   Initiates a client and a TLS connection with a server using Certificates.
* @details This function will initiate a client's TLS connection to a server
* using Certificates. It requires the TLSConnection struct to be assigned with the
* server's IP address, the server's port,the wolfSSL method, the previsously created
* socket fd and the full path to the certificates directory.
*
* @param   pConnection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initTLSClientCert( TLSConnection * pConnection )
{
    char clientCertPath[PATH_SIZE];

    if( !pConnection ){
        return E_NULL_STRUCT;
    }

    if(!WolfSSLInitialized){
        /* Initialize wolfSSL */
        wolfSSL_Init();
        WolfSSLInitialized = true;
    }

    if( pConnection->wolfSSLDebug ){
        wolfSSL_Debugging_ON();
    }else{
        wolfSSL_Debugging_OFF();
    }

    /* Create and initialize WOLFSSL_CTX */
    if ( ( pConnection->ctx = wolfSSL_CTX_new( pConnection->wolfSSLMethod() ) ) == NULL ) {
        fprintf( stderr, "ERROR: failed to create WOLFSSL_CTX\n" );
        return E_SSL_CTX;
    }

    /* Load client certificates into WOLFSSL_CTX */
    memset( clientCertPath, 0, PATH_SIZE );
    memcpy( clientCertPath, pConnection->certFullPath, strlen( pConnection->certFullPath ) );
    strcat( clientCertPath, CLIENT_CERT_FILE );
    if ( wolfSSL_CTX_load_verify_locations( pConnection->ctx, clientCertPath, NULL ) != SSL_SUCCESS ) {
        fprintf( stderr, "ERROR: failed to load %s, please check the file.\n", clientCertPath );
        return E_FAILED_CERT_LOAD;
    }

    /* Create a WOLFSSL object */
    if ( ( pConnection->ssl = wolfSSL_new( pConnection->ctx ) ) == NULL ) {
        fprintf( stderr, "ERROR: failed to create WOLFSSL object\n" );
        return E_WOLFSSL_NEW;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd( pConnection->ssl, pConnection->sockFd );

    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect( pConnection->ssl ) != SSL_SUCCESS ) {
        fprintf( stderr, "ERROR: failed to connect to wolfSSL\n" );
        return E_WOLFSSL_CONNECT;
    }

    return E_SUCCESS;
}

/**
* @brief   Initiates a server and a TLS connection with a client using Certificates.
* @details This function will initiate a server's TLS connection to a client
* using Certificates. It requires the TLSConnection struct to be assigned with the client's
* IP address, the client's port,the wolfSSL method, the previsously created
* socket fd and the full path to the certificate's directory.
*
* @param   pConnection   A TLSConnection struct with the connection parameters.
*/
E_RETURN initAndAcceptTLSServerCert( TLSConnection * pConnection )
{
    struct sockaddr_in servAddr;
    char serverCertPath[PATH_SIZE];
    char serverKeyPath[PATH_SIZE];

    if( !pConnection ){
        return E_NULL_STRUCT;
    }

    pConnection->clientSize = sizeof(pConnection->clientAddr);

    if(!WolfSSLInitialized){
        /* Initialize wolfSSL */
        wolfSSL_Init();
        WolfSSLInitialized = true;
    }

    if( pConnection->wolfSSLDebug ){
        wolfSSL_Debugging_ON();
    }else{
        wolfSSL_Debugging_OFF();
    }

    /* Create and initialize WOLFSSL_CTX */
    if ( ( pConnection->ctx = wolfSSL_CTX_new( pConnection->wolfSSLMethod() ) ) == NULL ) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return E_SSL_CTX;
    }

    /* Load server certificates into WOLFSSL_CTX */
    memset( serverCertPath, 0, PATH_SIZE );
    memcpy( serverCertPath, pConnection->certFullPath, strlen( pConnection->certFullPath ) );
    strcat( serverCertPath, SERVER_CERT_FILE );
    if (wolfSSL_CTX_use_certificate_file( pConnection->ctx, serverCertPath, SSL_FILETYPE_PEM ) != SSL_SUCCESS) {
        fprintf( stderr, "ERROR: failed to load %s, please check the file.\n", serverCertPath );
        return E_FAILED_CERT_LOAD;
    }

    /* Load server key into WOLFSSL_CTX */
    memset( serverKeyPath, 0, PATH_SIZE );
    memcpy( serverKeyPath, pConnection->certFullPath, strlen( pConnection->certFullPath ) );
    strcat( serverKeyPath, KEY_FILE );
    if (wolfSSL_CTX_use_PrivateKey_file( pConnection->ctx, serverKeyPath, SSL_FILETYPE_PEM ) != SSL_SUCCESS ) {
        fprintf( stderr, "ERROR: failed to load %s, please check the file.\n", serverKeyPath );
        return E_FAILED_CERT_LOAD;
    }

    /* Initialize the server address struct with zeros */
    memset( &servAddr, 0, sizeof( servAddr ) );

    /* Fill in the server address */
    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons( pConnection->port ); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

    /* Bind the server socket to our port */
    if ( bind( pConnection->sockFd, ( struct sockaddr* )&servAddr, sizeof( servAddr ) ) == -1 ) {
        fprintf( stderr, "ERROR: failed to bind\n" );
        return E_BIND;
    }

    /* Listen for a new connection, allow 5 pending connections */
    if ( listen( pConnection->sockFd, SERVER_PENDING_CONNECTIONS ) == -1 ) {
        fprintf(stderr, "ERROR: failed to listen\n");
        return E_LISTEN;
    }

    /* Accept client connections */
    if ( ( pConnection->connd = accept( pConnection->sockFd, ( struct sockaddr* )&pConnection->clientAddr, &pConnection->clientSize ) ) == -1) {
        fprintf( stderr, "ERROR: failed to accept the connection\n" );
        return E_ACCEPT;
    }

    /* Create a WOLFSSL object */
    if ( ( pConnection->ssl = wolfSSL_new( pConnection->ctx ) ) == NULL ) {
        fprintf( stderr, "ERROR: failed to create WOLFSSL object\n" );
        return E_WOLFSSL_NEW;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd( pConnection->ssl, pConnection->connd );

    return E_SUCCESS;
}

/**
* @brief   Writes to the TLS connection.
* @details This function will write into the respective encrypted TLS connection.
*
* @param    pConnection A TLSConnection struct with the connection parameters.
* @param    data        Data to be sent.
* @param    size        Size of data to be written.
*/
E_RETURN writeToTLSConnection( TLSConnection * pConnection , const void* data, int32_t size )
{
    int16_t ret;
    int16_t err;
    char errBuffer[80];

    if( !pConnection ){
        return E_NULL_STRUCT;
    }
    /* Write */
    if ( ( ret = wolfSSL_write(pConnection->ssl, data, size) ) != size ) {
        fprintf( stderr, "ERROR: Writing data.");
        if( ret == 0 || ret == SSL_FATAL_ERROR ){
            err = wolfSSL_get_error( pConnection->ssl, 0 );
            wolfSSL_ERR_error_string( err, errBuffer );
            fprintf( stderr, "Error %d: %s", err, errBuffer );
        }
        fprintf( stderr, "\n" );
        return E_READ;
    }
    return E_SUCCESS;
}

/**
* @brief   Reads from the TLS connection.
* @details This function will block and read from the respective encrypted TLS connection.
*
* @param    pConnection  A TLSConnection struct with the connection parameters.
* @param    data        Pointer to buffer where read data will be stored.
* @param    size        Number of bytes to be read.
* @param    pReceivedBytes Actual number of received bytes.
*/
E_RETURN readFromTLSConnection( TLSConnection * pConnection , void* data, int32_t size, int32_t * pReceivedBytes )
{
    int16_t err;
    char errBuffer[80];

    if( !pConnection ){
        return E_NULL_STRUCT;
    }

    if( !pReceivedBytes ){
        return E_NULL_POINTER;
    }

    if( ( *pReceivedBytes = wolfSSL_read( pConnection->ssl, data, size ) ) <= 0 ){
        fprintf( stderr, "ERROR: Reading data.");
        if( *pReceivedBytes == 0 || *pReceivedBytes == SSL_FATAL_ERROR ){
            err = wolfSSL_get_error( pConnection->ssl, 0 );
            wolfSSL_ERR_error_string( err, errBuffer );
            fprintf( stderr, "Error %d: %s", err, errBuffer );
        }
        fprintf( stderr, "\n" );
        return E_READ;
    }
    return E_SUCCESS;
}

/**
* @brief   Disconnects the server from the TLS connection.
* @details This function must be called to disconnect the server from the TLS
* connection and clean and free the respective resources.
*
* @param    pConnection  A TLSConnection struct with the connection parameters.
*/
E_RETURN disconnectTLSServer( TLSConnection * pConnection )
{
    if( !pConnection ){
        return E_NULL_STRUCT;
    }
    /* Free the wolfSSL object */
    wolfSSL_free( pConnection->ssl );
    /* Close the connection to the client */
    close( pConnection->connd );
    close( pConnection->sockFd );
    /* Cleanup and return */
    /* Free the wolfSSL context object  */
    wolfSSL_CTX_free( pConnection->ctx );
    /* Cleanup the wolfSSL environment */
    wolfSSL_Cleanup();

    return E_SUCCESS;
}

/**
* @brief   Disconnects the client from the TLS connection.
* @details This function must be called to disconnect the client from the TLS
* connection and clean and free the respective resources.
*
* @param    pConnection  A TLSConnection struct with the connection parameters.
*/
E_RETURN disconnectTLSClient( TLSConnection * pConnection )
{
    if( !pConnection ){
        return E_NULL_STRUCT;
    }
    /* Cleanup */
    wolfSSL_free(pConnection->ssl);
    close( pConnection->sockFd );
    /* When completely done using SSL/TLS, free the
    * wolfssl_ctx object */
    wolfSSL_CTX_free(pConnection->ctx);
    wolfSSL_Cleanup();

    return E_SUCCESS;
}
