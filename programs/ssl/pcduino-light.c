/*
 *  SSL client demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
*/
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf


#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <string.h>

/*IoTgo platform*/
#define SERVER_PORT "443"
#define SERVER_NAME "linksprite.io"
#define API_KEY  "\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\","
#define DEVICE_ID "\"xxxxxxxxxxx\","
#define ACTION  "\"query\","
#define QUERY_PARAM  "[\"light\"]"

/*pcDuino GPIO*/
#define MODE_FILE_FORMAT "/sys/devices/virtual/misc/gpio/mode/gpio%d"
#define PIN_FILE_FORMAT  "/sys/devices/virtual/misc/gpio/pin/gpio%d" 
#define LED 13

int main( void )
{
    int ret, len;
    mbedtls_net_context server_fd;
    uint32_t flags;
    const char buf[1024];
    char params[3];
    const char *pers = "pcduino-light";
    FILE *modefile, *pinfile;
    char *jsonStr;
    char *headerStr;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    
    /* Open the GPIO control files */
    sprintf((char *)buf,MODE_FILE_FORMAT,LED);
    modefile = fopen(buf,"w");
  
    if(modefile == NULL)
   {
       mbedtls_fprintf(stderr,"Unable to open mode file: %s\n",buf);
       goto exit;
   }

    sprintf(buf,PIN_FILE_FORMAT,LED);
    pinfile = fopen(buf,"w");
    
    if(pinfile == NULL)
    {
      mbedtls_fprintf(stderr,"Unable to open pin file: %s\n",buf);
       goto exit;
    }
    /* Set the pin to be an output pin */
    fwrite("1",1,1,modefile);
    fwrite("1",1,1,pinfile);
    fflush(pinfile);

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_ssl_init( &ssl );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_printf( "\n  . Seeding the random number generator..." );
    mbedtls_ssl_config_init( &conf );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exittls;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );
    ret = mbedtls_x509_crt_parse_file( &cacert, "./mbedtls.crt" );

    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exittls;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );
    fflush( stdout );

   /* Hostname set here should match CN in server certificate */ 
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exittls;
    }
    /*
     * 2. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
    
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exittls;
    }
    
    mbedtls_printf( " ok\n" );
    
    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exittls;
    }
    

    while(1){
        mbedtls_net_init( &server_fd );
        /*
         * 1. Start the connection
         */
        mbedtls_printf( "  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT );
        fflush( stdout );
    
        if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                                             SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            goto exittls;
        }
    
        mbedtls_printf( " ok\n" );
    
    
        mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
    
        /*
         * 4. Handshake
         */
        mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
        fflush( stdout );
    
        while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
                goto exittls;
            }
        }
    
        mbedtls_printf( " ok\n" );
    
        /*
         * 5. Verify the server certificate
         */
        mbedtls_printf( "  . Verifying peer X.509 certificate..." );
    
        /* In real life, we probably want to bail out when ret != 0 */
        if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
        {
            char vrfy_buf[512];
    
            mbedtls_printf( " failed\n" );
    
            mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
    
            mbedtls_printf( "%s\n", vrfy_buf );
        }
        else
            mbedtls_printf( " ok\n" );
    
        /*
         * 3. Write the POST request
         */
        mbedtls_printf( "  > Write to server:" );
        fflush( stdout );

        jsonStr = "{\"action\":"
                  ACTION
                  "\"deviceid\":" 
                  DEVICE_ID
                  "\"apikey\":"
                  API_KEY
                  "\"params\":"
                  QUERY_PARAM
                  "}\r\n";
        headerStr =
                  "POST /api/http HTTP/1.1\n"
                  "Host: "
                  SERVER_NAME
                  "\nContent-Type: application/json\n"
                  "Content-Length: ";
        len = 0;
        len += sprintf((char *)(buf+len), headerStr);
        len += sprintf((char *)(buf+len), "%d\n\n", strlen(jsonStr));
        len += sprintf((char *)(buf+len), jsonStr);

        while( ( ret = mbedtls_ssl_write( &ssl, (unsigned char *)buf, len ) ) <= 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
                goto exittls;
            }
        }

        len = ret;
        mbedtls_printf( " %d bytes written\n\n%s", len, (char *) buf );
        /*
         * 7. Read the HTTP response
         */
        mbedtls_printf( "  < Read from server:\n" );
        fflush( stdout );
    
        do
        {
            len = sizeof( buf ) - 1;
            memset( (void *)buf, 0, sizeof( buf ) );
            ret = mbedtls_ssl_read( &ssl, (unsigned char *)buf, len );
    
            if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
                continue;
    
            if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
                break;
    
            if( ret < 0 )
            {
                mbedtls_printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
                break;
            }
    
            if( ret == 0 )
            {
                mbedtls_printf( "\n\nEOF\n\n" );
                break;
            }

            if(ret > 0){
                memcpy(params, &buf[231] ,3);

                if(strstr(params, "on")){
                    fwrite("1",1,1,pinfile);
                    fflush(pinfile);
                    printf("Turn on the light!\n");
                }

                if(strstr(params,"off")){
                    fwrite("0",1,1,pinfile);
                    fflush(pinfile);
                    printf("Turn off the light\n");
                }
                break;
            }
 
        }
        while( 1 );
    
         mbedtls_ssl_close_notify( &ssl );
    
    exittls:
/*    
    #ifdef MBEDTLS_ERROR_C
        if( ret != 0 )
        {
            char error_buf[100];
            mbedtls_strerror( ret, error_buf, 100 );
            mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
        }
    #endif
*/    
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free( &server_fd );
    
        sleep(2);
    
    }

    exit:
        printf("Can't write GPIO file...\n");
        fclose(modefile);
        fclose(pinfile);
}
