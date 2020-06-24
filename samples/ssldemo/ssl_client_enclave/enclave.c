#include "sgx_trts.h"
#include "mbedtls/md5.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"

#include "sgx_tsyscall_utility.h"

#define mbedtls_printf printf
#define mbedtls_exit return
#define mbedtls_free       free
#define mbedtls_snprintf   snprintf

#define DFL_REQUEST_SIZE        -1
#define DFL_REQUEST_PAGE        "/"

int do_mbed_test()
{
	int i, ret;
	unsigned char digest[16];
	char str[] = "Hello, world!";

	mbedtls_printf("\n MD5('%s') = ", str);
	
	ret = mbedtls_md5_ret((unsigned char *)str, 13, digest);
	if (ret != 0)
		mbedtls_exit(-1);

	for (i = 0; i < 16; i++)
		mbedtls_printf("%02x", digest[i]);

	mbedtls_printf("\n\n");

	return 0;
}

#define ECPARAMS    MBEDTLS_ECP_DP_SECP192R1

#define GET_REQUEST "GET %s HTTP/1.0\r\nExtra-header: "
#define GET_REQUEST_END "\r\n\r\n"

static unsigned char peer_crt_info[1024];

static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ )
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    mbedtls_printf( "\n" );
}

static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

int my_ctr_drbg_random( void *p_rng, unsigned char *output,
                             size_t output_len )
{    
    sgx_read_rand(output, output_len);
    return 0;
}

int my_entropy_func( void *data, unsigned char *output, size_t len )
{
    sgx_read_rand(output, len);
    return 0;
}

int do_ecdsa_test()
{
	int ret = 1;
	int exit_code = -1;
	mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
	unsigned char message[256];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";

	mbedtls_ecdsa_init( &ctx_sign );
    mbedtls_ecdsa_init( &ctx_verify );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    memset( sig, 0, sizeof( sig ) );
    memset( message, 0xab, sizeof( message ) );

    mbedtls_printf( " ok\n  . Generating key pair..." );  
  
	if( ( ret = mbedtls_ecdsa_genkey( &ctx_sign, ECPARAMS,
                                my_ctr_drbg_random, &ctr_drbg)) != 0)                              
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok (key size: %d bits)\n", (int) ctx_sign.grp.pbits );

    dump_pubkey( "  + Public key: ", &ctx_sign );

    /*
     * Compute message hash
     */
    mbedtls_printf( "  . Computing message hash..." );

    if( ( ret = mbedtls_sha256_ret( message, sizeof( message ), hash, 0 ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_sha256_ret returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    dump_buf( "  + Hash: ", hash, sizeof( hash ) );

    /*
     * Sign message hash
     */
    mbedtls_printf( "  . Signing message hash..." );    

    if( ( ret = mbedtls_ecdsa_write_signature( &ctx_sign, MBEDTLS_MD_SHA256,
                                       hash, sizeof( hash ),
                                       sig, &sig_len,
                                       my_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_write_signature returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok (signature length = %u)\n", (unsigned int) sig_len );

    dump_buf( "  + Signature: ", sig, sig_len );

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
    mbedtls_printf( "  . Preparing verification context..." );
    // fflush( stdout );

    if( ( ret = mbedtls_ecp_group_copy( &ctx_verify.grp, &ctx_sign.grp ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_copy returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ecp_copy( &ctx_verify.Q, &ctx_sign.Q ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_copy returned %d\n", ret );
        goto exit;
    }

    /*
     * Verify signature
     */
    mbedtls_printf( " ok\n  . Verifying signature..." );
    // fflush( stdout );

    if( ( ret = mbedtls_ecdsa_read_signature( &ctx_verify,
                                      hash, sizeof( hash ),
                                      sig, sig_len ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_read_signature returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

	exit_code = 0;

exit:
	mbedtls_ecdsa_free( &ctx_verify );
    mbedtls_ecdsa_free( &ctx_sign );
    mbedtls_ctr_drbg_free( &ctr_drbg );    

    mbedtls_exit( exit_code );

	return exit_code;
}

void printhex(const unsigned char * output, size_t size)
{
    int i = 0;
    for (i = 0; i < size; i++)
    {
        printf("0x%02x ", output[i]);
    }
    printf("\n");
}

int do_sha256_test()
{
    unsigned char hash[32];
    const char hello_str[] = "Hello, world!";
    const unsigned char * hello_buffer = (const unsigned char *)hello_str;
    const size_t hello_len = strlen(hello_str);

    mbedtls_sha256_context ctx2;

    mbedtls_sha256_init(&ctx2);
    mbedtls_sha256_starts(&ctx2, 0);

    mbedtls_sha256_update(&ctx2, hello_buffer, 1);
    mbedtls_sha256_update(&ctx2, hello_buffer + 1, 1);
    mbedtls_sha256_update(&ctx2, hello_buffer + 2, hello_len - 2);

    mbedtls_sha256_finish(&ctx2, hash);

    printhex(hash, sizeof(hash));

    return 0;
}

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#define MAX_REQUEST_SIZE      20000

typedef struct
{
    mbedtls_ssl_context *ssl;
    mbedtls_net_context *net;
} io_ctx_t;

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */

static int delayed_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }

    ret = mbedtls_net_recv( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

static int delayed_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_WRITE );
    }

    ret = mbedtls_net_send( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

static int recv_cb( void *ctx, unsigned char *buf, size_t len )
{
    io_ctx_t *io_ctx = (io_ctx_t*) ctx;
    size_t recv_len;
    int ret;

    // if( opt.nbio == 2 )
    //     ret = delayed_recv( io_ctx->net, buf, len );
    // else
    ret = mbedtls_net_recv( io_ctx->net, buf, len );
    if( ret < 0 )
        return( ret );
    recv_len = (size_t) ret;

//     if( opt.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
//     {
//         /* Here's the place to do any datagram/record checking
//          * in between receiving the packet from the underlying
//          * transport and passing it on to the TLS stack. */
// #if defined(MBEDTLS_SSL_RECORD_CHECKING)
//         if( ssl_check_record( io_ctx->ssl, buf, recv_len ) != 0 )
//             return( -1 );
// #endif /* MBEDTLS_SSL_RECORD_CHECKING */
//     }

    return( (int) recv_len );
}

static int send_cb( void *ctx, unsigned char const *buf, size_t len )
{
    io_ctx_t *io_ctx = (io_ctx_t*) ctx;

    // if( opt.nbio == 2 )
    //     return( delayed_send( io_ctx->net, buf, len ) );

    return( mbedtls_net_send( io_ctx->net, buf, len ) );
}

int do_ssl_client()
{
    int ret = 0, len, tail_len, i, written, frags, retry_left;
    mbedtls_net_context server_fd;
    io_ctx_t io_ctx;

    unsigned char buf[MAX_REQUEST_SIZE + 1];
    const char *pers = "ssl_client2";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_session saved_session;
    unsigned char *session_data = NULL;
    size_t session_data_len = 0;

    uint32_t flags;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;

    char *p, *q;
    const int *list;

    /*
     * Make sure memory references are valid.
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );

    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &clicert );
    mbedtls_pk_init( &pkey );

    memset( &saved_session, 0, sizeof( mbedtls_ssl_session ) );
    mbedtls_ctr_drbg_init( &ctr_drbg );    

    /*
     * 1.1. Load the trusted CA
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    // fflush( stdout );

    for( i = 0; mbedtls_test_cas[i] != NULL; i++ )
    {
        ret = mbedtls_x509_crt_parse( &cacert,
                                  (const unsigned char *) mbedtls_test_cas[i],
                                  mbedtls_test_cas_len[i] );
        if( ret != 0 )
            break;
    }

    if( ret == 0 )
        for( i = 0; mbedtls_test_cas_der[i] != NULL; i++ )
        {
            ret = mbedtls_x509_crt_parse_der( &cacert,
                         (const unsigned char *) mbedtls_test_cas_der[i],
                         mbedtls_test_cas_der_len[i] );
            if( ret != 0 )
                break;
        }

    /*
     * 1.2. Load own certificate and private key
     *
     * (can be skipped if client authentication is not required)
     */
    mbedtls_printf( "  . Loading the client cert. and key..." );
    ret = mbedtls_x509_crt_parse( &clicert,
                (const unsigned char *) mbedtls_test_cli_crt,
                mbedtls_test_cli_crt_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                        (unsigned int) -ret );
        goto exit;
    }
 
    ret = mbedtls_pk_parse_key( &pkey,
                (const unsigned char *) mbedtls_test_cli_key,
                mbedtls_test_cli_key_len, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned -0x%x\n\n",
                        (unsigned int) -ret );
        goto exit;
    }

    mbedtls_printf( " ok (key type: %s)\n", mbedtls_pk_get_name( &pkey ) );

    /*  
     * 2. Start the connection
     */
    mbedtls_printf( "  . Connecting to %s/%s/%s...",
            "tcp",
            "127.0.0.1", "4433");
    
    if( ( ret = mbedtls_net_connect( &server_fd,
                       "127.0.0.1", "4433",
                       MBEDTLS_NET_PROTO_TCP) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned -0x%x\n\n",
                        (unsigned int) -ret );
        goto exit;
    }

    ret = mbedtls_net_set_block( &server_fd );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! net_set_(non)block() returned -0x%x\n\n",
                        (unsigned int) -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 3. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL/TLS structure..." );    

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n",
                        (unsigned int) -ret );
        goto exit;
    }

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng( &conf, my_ctr_drbg_random, &ctr_drbg );
    
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n",
                        (unsigned int) -ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, "127.0.0.1") ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n",
                        ret );
        goto exit;
    }

    io_ctx.ssl = &ssl;
    io_ctx.net = &server_fd;
    mbedtls_ssl_set_bio( &ssl, &io_ctx, send_cb, recv_cb, NULL);
                         //opt.nbio == 0 ? recv_timeout_cb : NULL );

    mbedtls_printf( " ok\n" );

    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
            ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n",
                            (unsigned int) -ret );
            if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
                mbedtls_printf(
                    "    Unable to verify the server's certificate. "
                        "Either it is invalid,\n"
                    "    or you didn't set ca_file or ca_path "
                        "to an appropriate value.\n"
                    "    Alternatively, you may want to use "
                        "auth_mode=optional for testing purposes.\n" );
            mbedtls_printf( "\n" );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
                    mbedtls_ssl_get_version( &ssl ),
                    mbedtls_ssl_get_ciphersuite( &ssl ) );

    if( ( ret = mbedtls_ssl_get_record_expansion( &ssl ) ) >= 0 )
        mbedtls_printf( "    [ Record expansion is %d ]\n", ret );
    else
        mbedtls_printf( "    [ Record expansion is unknown (compression) ]\n" );

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf( "  . Verifying peer X.509 certificate..." );

    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        mbedtls_printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ),
                                      "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
    }
    else
        mbedtls_printf( " ok\n" );

    mbedtls_printf( "  . Peer certificate information    ...\n" );
    mbedtls_printf( "%s\n", peer_crt_info );

    /*
     * 6. Write the GET request
     */
    retry_left = 2;
send_request:
    mbedtls_printf( "  > Write to server:" );

    len = mbedtls_snprintf( (char *) buf, sizeof( buf ) - 1, GET_REQUEST,
                             DFL_REQUEST_PAGE);
    tail_len = (int) strlen( GET_REQUEST_END );

    // /* Add padding to GET request to reach opt.request_size in length */
    // if( opt.request_size != DFL_REQUEST_SIZE &&
    //     len + tail_len < opt.request_size )
    // {
    //     memset( buf + len, 'A', opt.request_size - len - tail_len );
    //     len += opt.request_size - len - tail_len;
    // }

    strncpy( (char *) buf + len, GET_REQUEST_END, sizeof( buf ) - len - 1 );
    len += tail_len;

  
    written = 0;
    frags = 0;

    do
    {
        while( ( ret = mbedtls_ssl_write( &ssl, buf + written,
                                          len - written ) ) < 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
                ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned -0x%x\n\n",
                                (unsigned int) -ret );
                goto exit;
            }
        }
        
        frags++;
        written += ret;        
    } while( written < len );

    buf[written] = '\0';
    mbedtls_printf( " %d bytes written in %d fragments\n\n%s\n",
                    written, frags, (char *) buf );

    /* Send a non-empty request if request_size == 0 */
    if ( len == 0 )
    {
        //opt.request_size = DFL_REQUEST_SIZE;
        goto send_request;
    }

    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf( "  < Read from server:" );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE )
        {
//             /* For event-driven IO, wait for socket to become available */
//             if( opt.event == 1 /* level triggered IO */ )
//             {
// #if defined(MBEDTLS_TIMING_C)
//                     idle( &server_fd, &timer, ret );
// #else
//                     idle( &server_fd, ret );
// #endif
//                 }
//                 continue;
        }

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );
                    ret = 0;
                    goto exit;

                case 0:
                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf( " connection was reset by peer\n" );
                    ret = 0;
                    goto exit;

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n",
                                        (unsigned int) -ret );
                    goto exit;
            }
        }

        len = ret;
        buf[len] = '\0';
        mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
	
		for (int i = 0; i < len; i++)
    	{
        	printf("0x%02x ", buf[i]);
	        if ((i + 1 % 16) == 0)
    	        printf("\n");
    	}
    	printf("\n");

        /* End of message should be detected according to the syntax of the
         * application protocol (eg HTTP), just use a dummy test here. */
        if( ret > 0 && buf[len-1] == '\n' )
        {
            ret = 0;
            break;
        }
    } while( 1 );
    
exit:
    mbedtls_net_free( &server_fd );
    mbedtls_x509_crt_free( &clicert );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_pk_free( &pkey );

    mbedtls_ssl_session_free( &saved_session );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );    
    if( session_data != NULL )
        mbedtls_platform_zeroize( session_data, session_data_len );
    mbedtls_free( session_data );

    mbedtls_exit( ret );

    return 0;
}
