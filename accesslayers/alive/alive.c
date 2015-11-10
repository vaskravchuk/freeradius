#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>


int main(int argc, char* argv[])
{
    pid_t process_id = 0;
    pid_t sid = 0;

    int socket_desc , client_sock , c , *new_sock;
    int port;
    struct sockaddr_in server , client;

    if (argc<2) {
	printf("Keep alive checked for radius server\n");
	printf("    Usage: \n");
	printf("    live 9999\n");
	printf("\n");
	exit(0);
    }

    port = 9999;
    if ( argc > 1 ) {
	port = atoi( argv[1] );
    }

    process_id = fork();
    if (process_id < 0)
    {
	printf("fork failed!\n");
	exit(1);
    }
    if (process_id > 0)
    {
	printf("process_id of child process %d \n", process_id);
	exit(0);
    }
    umask(0);
    sid = setsid();
    if (sid < 0)
    {
	exit(1);
    }

    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        perror("error: could not create socket");
    }
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( port );
 
    if (bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("bind failed. Error\n");
        return 1;
    }

    listen(socket_desc , 3);

    printf("ready for incoming connections on port %d\n", port);

    c = sizeof(struct sockaddr_in);

    while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
	close(client_sock);
    }

    if (client_sock < 0)
    {
        printf("accept failed\n");
        return 1;
    }

    return (0);
}
