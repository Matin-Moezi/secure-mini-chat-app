# Secure Mini Chat App in C

### Introduction

This chat app is a server-client chat app based on TCP protocol and secured with end-to-end encryption.
This secure mini chat app can transfer text and file (up to 10MB) between maximum 10 clients at a same time.

We have used SHA-256 asymmetric cryptography as a protocol for transfer session key between clients and the server.
For end-to-end encryption, we have implemented AES symmetric cryptography.

### Dependencies

We have used Libgcrypt as a cryptography library to encryption the data and session key. For more information visit gnupg.org/software/libgcrypt/index.html.

### Run

In the root directory run the following commands:

    $ mkdir build && cd build
    $ cmake ..
    $ make
