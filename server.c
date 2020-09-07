/******************************* Secure Messenger ***********************************************/
/******************************* Client-Server Architecture *************************************/
/******************************* Asymmetric Cryptography RSA Algorithm **************************/
/******************************* Network Security Course Project ********************************/
/******************************* Matin Moezi #9512058 *******************************************/
/******************************* Spring 2020 ****************************************************/

/******************************* Server Program *************************************************/

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "definition.h"
#include "symm_crypt.h"
#include "asym_crypt.h"

session_t session;
int client_id = 0;

/* Client connection entity */
struct client_conn_t
{
    int id, fd;
    size_t plen, slen;
    char *public_key, *server_pkey, *server_skey;
    struct sockaddr_in addr;
    session_t *session;
    struct client_conn_t *next;
};
typedef struct client_conn_t client_conn_t;

/* Root clients node */
client_conn_t *root_client = NULL;

/* Initialization the server */
/* Create socket and listen */
int init_server()
{
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("create socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    /* Binding address to socket */
    struct sockaddr_in address = {
            AF_INET,
            htons(PORT)};
    int bind_res = bind(sockfd, (struct sockaddr *) &address, sizeof(address));
    if (bind_res != 0)
    {
        perror("Binding address to socket");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

/* Search for clients */
client_conn_t *search_client(int id)
{
    client_conn_t *tmp = root_client;
    while (tmp != NULL)
    {
        if (tmp->id == id)
            return tmp;
        tmp = tmp->next;
    }
    return NULL;
}

/* Update clients list for possible closed connections */
void update_clients_list()
{
    if (root_client == NULL)
        return;
    int i = 0;
    client_conn_t *prev, *tmp = root_client;
    prev = tmp;
    int retval, error = 0;
    socklen_t len = sizeof (error);
    while (tmp != NULL)
    {
        retval = getsockopt (tmp->fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (retval == -1)
        {
            if (i++ == 0)
            {
                i = 0;
                root_client = root_client->next;
                close(tmp->fd);
                free(tmp);
                prev = tmp = root_client;
            } else
            {
                prev->next = tmp->next;
                close(tmp->fd);
                free(tmp);
                tmp = prev->next;
            }
        } else
        {
            prev = tmp;
            tmp = tmp->next;
        }
    }
}

/* Print client list except given client */
void print_clients(struct sockaddr_in exception, char *result)
{
    update_clients_list();
    char name[10];
    client_conn_t *next = root_client;
    strcat(result, CLIENTLSTYPE);
    while (next != NULL)
    {
        if (next->addr.sin_addr.s_addr == exception.sin_addr.s_addr && next->addr.sin_port == exception.sin_port)
        {
            next = next->next;
            continue;
        }
        sprintf(name, "Client_%d\n", next->id);
        strcat(result, name);
        next = next->next;
    }
}

/* Send session key response */
int send_session(client_conn_t *client_conn)
{
    if (client_conn->session == NULL || client_conn->session->timestamp - time(NULL) <= 0)
    {
        /* Generate Session Key */
        free(client_conn->session);
        client_conn->session = (session_t *) malloc(sizeof(session_t));
        bzero(&client_conn->session->session_key, AES256_BLOCK_LEN + 1);
        client_conn->session->timestamp = time(NULL) + 10; // session timeout set to 10 seconds
        generate_random(client_conn->session->session_key, AES256_BLOCK_LEN);
    }

    /* Encrypt session and send to client */
    char session_req[MAXSESSIONSIZE] = {'\0'};
    char *session_type = SESSIONTYPE;
    sprintf(session_req, "%s%s\n%ld", session_type, client_conn->session->session_key, client_conn->session->timestamp);

    char *ciphertext;
    size_t ciphertext_len;
    if (asym_encrypt(client_conn->public_key, session_req, strlen(session_req), &ciphertext, &ciphertext_len) != 0)
    {
        free(client_conn);
        return -1;
    }

    if (send(client_conn->fd, ciphertext, ciphertext_len, 0) < 0)
    {
        perror("sending session key");
        free(client_conn);
        return -1;
    }
    return 0;
}

/* Parse message */
int parse_msg(const char *input, int *id, char *msg)
{
    int n;
    if (sscanf(input, "MESSAGE\nCLIENT_%d\n%n", id, &n) < 1)
        return -1;
    strcpy(msg, input + n);
    return 0;
}

/* Send message to client */
int send_msg(int sender_id, client_conn_t *client, char *msg)
{
    if (client == NULL)
        return -1;

    /* Verify receiver session */
    while(client->session == NULL || client->session->timestamp - time(NULL) <= 0)
        send_session(client);

    char message[MAXMSGSIZE];
    strncpy(message, MSGTYPE, MSGTYPELEN);
    sprintf(message + MSGTYPELEN, "Client_%d:\n\%s\n", sender_id, msg);
    /* Encrypt message */
    char *ciphertext;
    size_t ciphertext_len;
    if (encrypt_text(client->session->session_key, message, strlen(message), &ciphertext, &ciphertext_len) != 0)
        return -1;

    /* Send message */
    if (send(client->fd, ciphertext, ciphertext_len, 0) <= 0)
        return -1;
    return 0;
}

/* Send file */
int send_file(int sender, char *data)
{
    int header_size, receiver_id;
    long filesize;
    char *response, filename[32] = {'\0'}, header[64] = {'\0'};
    sscanf(data, "FILEClient_%d%s\n%ld$1101011%n", &receiver_id, filename, &filesize, &header_size);
    int new_header_size = sprintf(header, "FILEClient_%d%s\n%ld$1101011", sender, filename, filesize);
    response = malloc(header_size + filesize);
    memcpy(response, header, new_header_size);
    memcpy(response + new_header_size, data + header_size, filesize);
    client_conn_t *receiver = search_client(receiver_id);
    if (receiver != NULL)
    {
        /* Verify receiver session */
        while(receiver->session == NULL || receiver->session->timestamp - time(NULL) <= 0)
            send_session(receiver);

        /* Encrypt and send file */
        char *ciphertext;
        size_t ciphertext_len;
        if (encrypt_text(receiver->session->session_key, response, new_header_size + filesize, &ciphertext,
                         &ciphertext_len) == 0)
            if (send(receiver->fd, ciphertext, ciphertext_len, 0) > 0)
                return 0;
    }
    return -1;
}

/* Send error */
int send_error(client_conn_t *client, int err_code, const char *err_str)
{
    size_t ciphertext_len;
    char *ciphertext, error[ERRORLEN] = {'\0'};
    int err_size = sprintf(error, "ERROR\n%d\n%s", err_code, err_str);
    if (encrypt_text(client->session->session_key, error, err_size, &ciphertext, &ciphertext_len) == 0)
        if (send(client->fd, ciphertext, ciphertext_len, 0) > 0)
        {
            free(ciphertext);
            return 0;
        }
    free(ciphertext);
    return -1;
}

/* Send public key to client */
int send_pkey(client_conn_t client)
{
    char *msg = malloc(client.plen + PUBKEYTYPELEN);
    strncpy(msg, PUBKEYTYPE, PUBKEYTYPELEN);
    memcpy(msg + PUBKEYTYPELEN, client.server_pkey, client.plen);
    if (send(client.fd, msg, client.plen + PUBKEYTYPELEN, 0) > 0)
    {
        free(msg);
        return 0;
    }
    free(msg);
    return -1;
}

/* Handle each client connection */
void *connection_handler(void *arg)
{
    client_conn_t *client_conn = (client_conn_t *) arg;
    int client_port = ntohs(client_conn->addr.sin_port);
    char client_host[INET_ADDRSTRLEN];

    /* Retrieve client socket address */
    /* convert network byte address to dot-decimal hostname */
    if (inet_ntop(AF_INET, &(client_conn->addr.sin_addr), client_host, INET_ADDRSTRLEN) == NULL)
    {
        perror("connection handler");
        return NULL;
    }
    printf("client %s %d connected.\n", client_host, client_port);

    /* Generate public/private key pair */
    gen_key(&client_conn->server_pkey, &client_conn->server_skey, &client_conn->plen, &client_conn->slen);
    /* Send public key to the client */
    if (send_pkey(*client_conn) != 0)
        goto terminate;

    /* Listening for client request */
    size_t plaintext_len;
    int recv_size, error;
    char *plaintext, *ciphertext, request[MAXREQSIZE], err_str[ERRORLEN] = {'\0'};
    size_t ciphertext_len;
    while ((recv_size = recv(client_conn->fd, request, MAXREQSIZE, 0)) > 0)
    {
        if (strncmp(request, PUBKEYTYPE, PUBKEYTYPELEN) == 0)
        {
            client_conn->public_key = malloc(recv_size - PUBKEYTYPELEN);
            memcpy(client_conn->public_key, request + PUBKEYTYPELEN, recv_size - PUBKEYTYPELEN);
            continue;
        }

        /* Decrypt request message with passphrase */
        if (asym_decrypt(client_conn->server_skey, request, recv_size, &plaintext, &plaintext_len) == 0)
            /* Request for session key */
            if (strncmp(plaintext, SESSIONTYPE, SESSIONTYPELEN) == 0)
            {
                /* Send session */
                if (send_session(client_conn) == 0)
                {
                    printf("send session\n");
                    continue;
                }
                else
                    goto terminate;
            }

        /* Verify session */
        if (client_conn->session == NULL || client_conn->session->timestamp - time(NULL) <= 0)
        {
            send_error(client_conn, SESSIONEXP, "Session expired.\n");
            continue;
        }

        /* Decrypt request message with session key */
        if (decrypt_text(client_conn->session->session_key, request, recv_size, &plaintext) == 0)
        {
            /* Request for client list */
            if (strncmp(plaintext, CLIENTLSTYPE, CLIENTLSTYPELEN) == 0)
            {
                error = CLIENTLSERR;
                strcpy(err_str, "Retrieving client list failed.\n");
                char list[128] = {'\0'};
                print_clients(client_conn->addr, list);
                /* Encrypt response */
                if (encrypt_text(client_conn->session->session_key, list, strlen(list), &ciphertext, &ciphertext_len) ==
                    0)
                    /* Send response */
                    if (send(client_conn->fd, ciphertext, ciphertext_len, 0) > 0)
                    {
                        printf("send client list\n");
                        continue;
                    }
            }

                /* Request for sending message */
            else if (strncmp(plaintext, MSGTYPE, MSGTYPELEN) == 0)
            {
                error = MSGFAILED;
                int id = 0;
                char msg[MAXMSGSIZE];
                if (parse_msg(plaintext, &id, msg) == 0)
                {
                    sprintf(err_str, "Send message to client %d failed.\n", id);
                    if (search_client(id) == NULL)
                    {
                        sprintf(err_str, "Client %d not exist.\n", id);
                        error = CLIENTEXISTERR;
                    } else if (send_msg(client_conn->id, search_client(id), msg) == 0)
                        continue;
                }
            }

                /* Request for sending file */
            else if (strncmp(plaintext, FILETYPE, FILETYPELEN) == 0)
            {
                error = FILEFAILED;
                int receiver_id, header_size;
                char filename[32] = {'\0'};
                long filesize;
                sscanf(plaintext, "FILEClient_%d%s\n%ld$1101011%n", &receiver_id, filename, &filesize, &header_size);
                sprintf(err_str, "Send file to client %d failed.\n", receiver_id);
                if (send_file(client_conn->id, plaintext) == 0)
                    continue;
            }

            /* Send back error to client */
            send_error(client_conn, error, err_str);
            free(plaintext);
        }
    }
    terminate:
    fprintf(stderr, "Client %s %d disconnected.\n", client_host, client_port);
    close(client_conn->fd);
    return NULL;
}

int main()
{
    int client_sockfd, sockfd = init_server();
    struct sockaddr_in client_addr;
    if (sockfd == -1)
        return -1;

    /* Listening to income request */
    if (listen(sockfd, SOMAXCONN) == -1)
    {
        perror("listen");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Listening on port %d...\n", PORT);

    // waiting for incoming request
    int len = sizeof(client_addr);
    while ((client_sockfd = accept(sockfd, (struct sockaddr *) &client_addr, (socklen_t *) &len)))
    {
        pthread_t conn;
        client_conn_t *handler_arg = (client_conn_t *) malloc(sizeof(client_conn_t));
        handler_arg->id = ++client_id;
        handler_arg->fd = client_sockfd;
        handler_arg->addr = client_addr;
        handler_arg->next = NULL;
        if (root_client == NULL)
            root_client = handler_arg;
        else
        {
            client_conn_t *tmp = root_client;
            while (tmp->next != NULL)
                tmp = tmp->next;
            tmp->next = handler_arg;
        }

        // create a thread for each client socket
        pthread_create(&conn, NULL, connection_handler, (void *) handler_arg);
        pthread_detach(conn);
    }
    return 0;
}
