cmake_minimum_required(VERSION 3.16)
project(server)
add_executable(server server.c symm_crypt.c symm_crypt.h asym_crypt.c asym_crypt.h)
target_link_libraries(server -pthread -lgcrypt)
project(client)
add_executable(client client.c symm_crypt.c symm_crypt.h asym_crypt.c asym_crypt.h)
target_link_libraries(client -pthread -lgcrypt)

