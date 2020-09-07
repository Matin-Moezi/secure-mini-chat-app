/******************************* Secure Messenger ***********************************************/
/******************************* Client-Server Architecture *************************************/
/******************************* Asymmetric Cryptography RSA Algorithm **************************/
/******************************* Network Security Course Project ********************************/
/******************************* Matin Moezi #9512058 *******************************************/
/******************************* Spring 2020 ****************************************************/

/******************************* Client Program *************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <libgen.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "definition.h"
#include "symm_crypt.h"
#include "asym_crypt.h"

int sockfd;
session_t *session = NULL;
size_t pub_len, priv_len;
char *server_pkey, *public_key, *private_key;

pthread_mutex_t clientlist_flag = PTHREAD_MUTEX_INITIALIZER;        // Client list receiving flag
pthread_mutex_t session_flag = PTHREAD_MUTEX_INITIALIZER;           // Session receiving flag
pthread_mutex_t public_key_flag = PTHREAD_MUTEX_INITIALIZER;        // Public key receiving flag


/* Prepare file entity */
int prepare_file(char *filepath, file_t *file)
{
    long size;
    FILE *fp = fopen(filepath, "r");
    if (fp == NULL)
        return -1;
    /* Get file size */
    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    rewind(fp);
    file->filesize = size;

    strcpy(file->filename, basename(filepath));
    fread(file->filedata, 1, size, fp);
    fclose(fp);
    return 0;
}

/* Verify and Retrieve session */
int verify_get_session()
{
    if (session != NULL && session->timestamp - time(NULL) > 0)
        return 0;
    else
    {
        /* Set session flag to wait */
        pthread_mutex_lock(&session_flag);

        /* Encrypt request */
        char *request = SESSIONTYPE;
        char *ciphertext;
        size_t ciphertext_len;
        printf("Waiting for session...\n");
        if (asym_encrypt(server_pkey, request, strlen(request), &ciphertext, &ciphertext_len) == 0)
            if (send(sockfd, ciphertext, ciphertext_len, 0) > 0)
            {
                /* Waiting for session */
                struct timespec tout;
                clock_gettime(CLOCK_REALTIME, &tout);
                tout.tv_sec += 30;                           // set lock timeout to 30 seconds
                if (pthread_mutex_timedlock(&session_flag, &tout) == 0)
                {
                    pthread_mutex_unlock(&session_flag);
                    return 0;
                }
            }
    }
    fprintf(stderr, "Retrieving session failed.\n");
    exit(EXIT_FAILURE);
}

/* Create a socket and connect to the server */
/* Return socket file descriptor */
void sock_connect(const char *host, int port)
{
    // create IPv4 TCP socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("create socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in addr = {
            AF_INET,
            htons(port),
    };

    // convert dot-decimal host address to network byte address
    if (inet_pton(AF_INET, host, &(addr.sin_addr)) == -1)
    {
        perror("server address");
        exit(EXIT_FAILURE);
    }

    // connect socket to the server
    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
    {
        perror("connect socket");
        exit(EXIT_FAILURE);
    }
}

/* Send message to client */
int send_msg(int client_id, char *msg)
{
    printf("Sending...\n");
    /* Create request */
    char request[MAXREQSIZE];
    sprintf(request, "MESSAGE\nCLIENT_%d%s", client_id, msg);

    /* Encrypt request */
    char *ciphertext;
    size_t ciphertext_len;
    if (encrypt_text(session->session_key, request, strlen(request), &ciphertext, &ciphertext_len) == 0)
        /* Send request */
        if (send(sockfd, ciphertext, ciphertext_len, 0) > 0)
        {
            printf("Sent.\n");
            return 0;
        }
    fprintf(stderr, "Sending message failed.\n");
    free(ciphertext);
    return -1;
}

/* Client receiver */
void *receiver_handler()
{
    size_t plaintext_len;
    int recv_size;
    char response[CHUNK_SIZE], *plaintext;
    while ((recv_size = recv(sockfd, response, CHUNK_SIZE, 0)) > 0)
    {
        /* Get the server public key */
        if (strncmp(response, PUBKEYTYPE, PUBKEYTYPELEN) == 0)
        {
            server_pkey = malloc(recv_size - PUBKEYTYPELEN);
            memcpy(server_pkey, response + PUBKEYTYPELEN, recv_size - PUBKEYTYPELEN);
            pthread_mutex_unlock(&public_key_flag);
            continue;
        }

        /* Decrypt response */
        if (asym_decrypt(private_key, response, recv_size, &plaintext, &plaintext_len) == 0)
            /* Session type */
            if (strncmp(plaintext, SESSIONTYPE, SESSIONTYPELEN) == 0)
            {
                char timestamp_str[11] = {'\0'};
                free(session);
                session = (session_t *) malloc(sizeof(session_t));
                sscanf(plaintext + SESSIONTYPELEN, "%[^\n]\n%s", session->session_key, timestamp_str);
                session->timestamp = strtol(timestamp_str, NULL, 10);
                pthread_mutex_unlock(&session_flag);
                continue;
            }

        if (decrypt_text(session->session_key, response, recv_size, &plaintext) == 0)
        {
            if (strncmp(plaintext, ERRORTYPE, ERRORTYPELEN) == 0)
            {
                int err_code, header_size;
                char err_str[ERRORLEN] = {'\0'};
                sscanf(plaintext, "ERROR\n%d\n%n", &err_code, &header_size);
                strcpy(err_str, plaintext + header_size);
                fprintf(stderr, "%s", err_str);
                continue;
            }

                /* Message response type */
            else if (strncmp(plaintext, MSGTYPE, MSGTYPELEN) == 0)
            {
                printf("\033[0;34m");
                printf("%s", plaintext + MSGTYPELEN);
                printf("\033[0;m");
            }
                /* File response type */
            else if (strncmp(plaintext, FILETYPE, FILETYPELEN) == 0)
            {
                int header_size, sender;
                long filesize;
                char filename[32] = {'\0'};
                sscanf(plaintext, "FILEClient_%d%s\n%ld$1101011%n", &sender, filename, &filesize, &header_size);
                FILE *f = fopen(filename, "w");
                fwrite(plaintext + header_size, 1, filesize, f);
                fclose(f);
                printf("File '%s' from client %d saved.\n", filename, sender);
            }
                /* Client list response type */
            else if (strncmp(plaintext, CLIENTLSTYPE, CLIENTLSTYPELEN) == 0)
            {
                if (strlen(plaintext + CLIENTLSTYPELEN) == 0)
                {
                    printf("There is not any client.\n");
                    free(plaintext);
                    exit(EXIT_FAILURE);
                } else
                {
                    printf("Client list:\n%s\n", plaintext + CLIENTLSTYPELEN);
                    pthread_mutex_unlock(&clientlist_flag);
                }
            }
            free(plaintext);
        }
    }
    return NULL;
}

/* Send client list request */
int send_clientlist_req()
{
    char *ciphertext;
    size_t ciphertext_len;
    pthread_mutex_lock(&clientlist_flag);
    if (encrypt_text(session->session_key, CLIENTLSTYPE, CLIENTLSTYPELEN, &ciphertext, &ciphertext_len) == 0)
        if (send(sockfd, ciphertext, ciphertext_len, 0) > 0)
        {
            /* Waiting for client list response */
            struct timespec tout;
            clock_gettime(CLOCK_REALTIME, &tout);
            tout.tv_sec += 30;                      // Waiting 30 seconds for client list
            if (pthread_mutex_timedlock(&clientlist_flag, &tout) == 0)
            {
                pthread_mutex_unlock(&clientlist_flag);
                return 0;
            }
        }
    fprintf(stderr, "Retrieving client list failed.\n");
    return -1;
}

/* Send file */
int send_file(int client_id, file_t *file)
{
    printf("Sending...\n");
    char *response, header[64] = {'\0'};
    /* File response format */
    /* FILE[filename]\n[filesize][filedata] */
    int header_size = sprintf(header, "FILEClient_%d%s\n%ld$1101011", client_id, file->filename, file->filesize);
    response = malloc(file->filesize + header_size);
    memcpy(response, header, header_size);
    memcpy(response + header_size, file->filedata, file->filesize);

    /* Encrypt file */
    char *ciphertext;
    size_t ciphertext_len;
    if (encrypt_text(session->session_key, response, header_size + file->filesize, &ciphertext, &ciphertext_len) == 0)
        if (send(sockfd, ciphertext, ciphertext_len, 0) > 0)
        {
            printf("Sent.\n");
            return 0;
        }
    fprintf(stderr, "Sending file failed.\n");
    return -1;
}

int main(int argc, char *argv[])
{
    /* Lock public key flag */
    pthread_mutex_lock(&public_key_flag);

    /* Connecting to server */
    sock_connect(HOST, PORT);
    if (sockfd < 0)
    {
        fprintf(stderr, "Connecting to server failed.");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Connected to the server.\n");

    /* Create receiver thread */
    pthread_t receiver;
    pthread_create(&receiver, NULL, receiver_handler, NULL);
    pthread_detach(receiver);

    /* Generate public/private key pair */
    gen_key(&public_key, &private_key, &pub_len, &priv_len);
    /* Send public key to the server */
    char *pub_key = malloc(pub_len + PUBKEYTYPELEN);
    strncpy(pub_key, PUBKEYTYPE, PUBKEYTYPELEN);
    memcpy(pub_key + PUBKEYTYPELEN, public_key, pub_len);
    send(sockfd, pub_key, pub_len + PUBKEYTYPELEN, 0);
    free(pub_key);

    /* Wait until retrieving the server public key */
    pthread_mutex_lock(&public_key_flag);

    while (1)
    {
        /* Requesting client list */
        if (verify_get_session() == 0)
        {
            printf("Retrieving clients list...\n");
            if (send_clientlist_req() != 0)
            {
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }

        printf("Which client do you want to contact?\n");
        char client_id[2];
        scanf("%s", client_id);

        /* Choose send message or send file */
        int msgsize;
        char choice, msg[MAXMSGSIZE], filepath[128];
        file_t *file;
        printf("1- Send Message\n2- Send File\n(1) or (2)?\n");
        choice = (char) getchar();
        if (choice == '\n' || choice == '\0')
            choice = (char) getchar();
        switch (choice)
        {
            case '1':
                printf("Type your message (Max. Character 512)(Enter $ to send):\n");
                if (scanf("%[^$] %n", msg, &msgsize) < 0)
                {
                    perror("Invalid text format.\n");
                    break;
                }
                if (msgsize > MAXMSGSIZE)
                {
                    fprintf(stderr, "Invalid input text message.\n");
                    break;
                }
                getchar();
                if (verify_get_session() == 0)
                    send_msg((int) strtol(client_id, NULL, 10), msg);
                break;
            case '2':
                printf("Enter your file path (Max. file size 100 KB):\n");
                scanf("%s", filepath);
                file = (file_t *) malloc(sizeof(file_t));
                if (prepare_file(filepath, file) != 0)
                {
                    fprintf(stderr, "Invalid input file.\n");
                    free(file);
                    break;
                }
                if (verify_get_session() == 0)
                    send_file((int) strtol(client_id, NULL, 10), file);
                break;
            default:
                printf("Invalid option.\n");
                break;
        }
    }
}
