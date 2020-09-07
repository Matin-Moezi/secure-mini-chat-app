/******************************* Common Definition *********************************/
/******************************* Network Security Course Project ********************************/
/******************************* Matin Moezi #9512058 *******************************************/
/******************************* Spring 2020 ****************************************************/

/******************************* Header File ****************************************************/

#include <stdlib.h>

#include "symm_crypt.h"

#ifndef DEFINITION_H
#define DEFINITION_H

#define HOST "127.0.0.1"		                // Server host ip address
#define PORT 53471								// Server port
#define CHUNK_SIZE 102400                       // Receive block size
#define MAXMSGSIZE 512                          // Maximum message length
#define MAXREQSIZE 102400		     			// Maximum request length
#define MAXSESSIONSIZE 64						// Maximum session entity size
#define MAXFILESIZE 102400   					// Maximum file size (100 KB)
#define ERRORLEN 128                            // Error length


#define PUBKEYTYPE "PUBLICKEY"                  // Public key res/req type
#define SESSIONTYPE "SESSION"                   // Session req/res type
#define MSGTYPE "MESSAGE"                       // Message req/res type
#define FILETYPE "FILE"                         // File req/res type
#define CLIENTLSTYPE "CLIENTLIST"               // Client list req/res type
#define ERRORTYPE "ERROR"                       // Error type

#define PUBKEYTYPELEN 9                         // Public key res/req type words count
#define SESSIONTYPELEN 7                        // Session req/res type words count
#define MSGTYPELEN 7                            // Message req/res type words count
#define FILETYPELEN 4                           // File req/res type words count
#define CLIENTLSTYPELEN 10                      // Client list req/res type words count
#define ERRORTYPELEN 5                          // Error type length

/* Type of Error */
#define SESSIONEXP 1                            // Session expired error
#define MSGFAILED 2                             // Send message failed error
#define FILEFAILED 3                            // Send file failed error
#define CLIENTLSERR 4                           // Send client list failed error
#define CLIENTEXISTERR 5                        // Client doese not exist error

/* Session entity */
typedef struct 
{
	char session_key[AES256_BLOCK_LEN + 1];
	time_t timestamp;
}session_t;

/* File entity */
typedef struct {
    char filename[32];
    long filesize;
    unsigned char filedata[MAXFILESIZE];
}file_t;


#endif