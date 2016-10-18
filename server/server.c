/*
** selectserver.c -- a cheezy multiperson chat server
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>


#define PORT "34408"   // port we're listening on
#define MAX_CLIENT 10
#define FILE_BUF_SIZE 1024
enum ClientStatus{
	None,
	Connected,
	NotLogin,
	Login,
	Port,
	Pasv,
	File,
    Retr
};
enum CreateFdMode{
	ConnectMode,
	BindMode
};
int clientStatus[100];
char fileIP[100][16];
char filePort[100][16];
char fileName[100][32];
int filefd[100];

char PATH[] = "";

int ServerCreateFileDescriptor(char* port, void* ip, int fdMode);

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void GetRecvMsgReq(char* msg, char* req){
	int length  = strlen(msg);
	int i = 0;
	if(length < 3){
		req[0] = '\0';
	}
	else{
		while(msg[i]>='A' && msg[i]<='Z' && i < length)
			++i;
		if((i < length && msg[i] == ' ') || i == length){
			strncpy(req, msg, i);
			req[i] = '\0';
		}
		else{
			req[0] = '\0';
		}
	}
}

int RecordPassAddress(char* msg, int clientfd){
	int length = strlen(msg);
	int j, i = 0;
	int count = 0;
	int num1, num2;
	char buf1[32], buf2[32];
	num1 = 0;
	num2 = 0;
	for(i = 0; i < length; ++i){
		if(msg[i] == ','){
			if(count == 3){
				fileIP[clientfd][i] = '\0';
				break;
			}
			count++;
			fileIP[clientfd][i] = '.';
		}
	else{
			fileIP[clientfd][i] = msg[i];
		}
	}
	for(j = i+1; j < length; ++j){
		if(msg[j] == ','){
			break;
		}
	}
	if( i >= length || j >= length){
		return -1;
	}
	strncpy(buf1, msg+i+1, j-i-1);
	buf1[j-i-1] = '\0';
	num1 = strtol(buf1, NULL, 10);
	strncpy(buf2, msg+j+1, length-j-1);
	buf2[j-i-1] = '\0';
	num2 = strtol(buf2, NULL, 10);
	sprintf(filePort[clientfd], "%d", num1*256+num2);
	return 0;
}

int RandomPasvPort(int clientfd, char* num1, char* num2){
	int r;
	srand(time(NULL));
	r = rand()%(65535-20000)+20000;
	sprintf(filePort[clientfd], "%d", r);
	sprintf(num1, "%d", (r-r%256)/256);
	sprintf(num2, "%d", r%256);
	return r;
}

int ServerSendFile(FILE* pfile, int clientfd){
	long length;
	long readlength = 1;
	char buf[FILE_BUF_SIZE];

    sleep(1);

    fseek(pfile, 0, SEEK_END);
    length = ftell(pfile);
    fseek(pfile, 0, SEEK_SET);

    while ((readlength > 0) && (length > 0)){
        readlength = fread(buf, sizeof(char), FILE_BUF_SIZE-1, pfile);

        if (readlength > 0){
			buf[readlength] = '\0';
            send(clientfd, buf, readlength, 0);
            length -= readlength;
        }
        printf("# %ld\n", readlength);
    }
	return 1;
}

int ServerRecvFile(FILE* pfile, int clientfd){
	return 1;
}

int ServerRetrSendFile(int clientfd, int clientfd2){
    char filename[128];
    char msg[128];
    FILE* pfile;

    if(clientfd2 == -1){
        return -1;
    }
    pfile = fopen(fileName[clientfd], "rb+");
    if(pfile == NULL){
        char badmsg[] = "451 no such file\r\n";
        send(clientfd, badmsg, strlen(badmsg), 0);
        return 1;
    }
    if(ServerSendFile(pfile, clientfd2) == -1){
        char badmsg[] = "451 RETR failed\r\n";
        send(clientfd, badmsg, strlen(badmsg), 0);
        fclose(pfile);	//close the dest file
        return 2;
    }
    fclose(pfile);	//close the dest file
    msg[0] = '\0';
    strcat(msg, "226 RETR success\r\n");
    send(clientfd, msg, strlen(msg), 0);
    return 3;
}

void ServerHandleMsg(int clientfd, char* buf, int nbytes){
	char req[16];
	GetRecvMsgReq(buf, req);
	if(strlen(req) == 0){
		char msg[] = "503 command format is \'REQUEST optional_parameter\'\r\n";
		send(clientfd, msg, strlen(msg), 0);
		return;
	}

	switch(clientStatus[clientfd]){
	case Connected:
		if(strcmp(buf, "USER anonymous") == 0){
			clientStatus[clientfd] = NotLogin;
			char msg[] = "331 Guest login ok, send your complete e-mail address as password.\r\n";
			send(clientfd, msg, strlen(msg), 0);
		}
		else{
			char msg[] = "503 your first request must be \'USER anonymous\'\r\n";
			send(clientfd, msg, strlen(msg), 0);
		}
		break;
	case NotLogin:
		if(strcmp(req, "PASS") == 0){
			char msg[] = "230 Congratulations!\r\n";
			send(clientfd, msg, strlen(msg), 0);
			clientStatus[clientfd] = Login;
		}
		else{
			char msg[] = "503 you should login first by using \'PASS yourpassword\'\r\n";
			send(clientfd, msg, strlen(msg), 0);
		}
		break;
	default:
		if(strcmp(req, "PORT") == 0){
			char tmp[64];
			char msg[] = "200 PORT success\r\n";

			clientStatus[clientfd] = Port;

			strncpy(tmp, buf+5, strlen(buf)-5);
			tmp[strlen(buf)-5] = '\0';
			if(RecordPassAddress(tmp, clientfd) == -1){
				char badmsg[] = "503 bad PORT request\r\n";
				send(clientfd, badmsg, strlen(badmsg), 0);
				break;
			}
			send(clientfd, msg, strlen(msg), 0);
		}
		else if(strcmp(req, "PASV") == 0){
			char num1[16];
			char num2[16];
			char msg[128];
            int originfd = filefd[clientfd];
			clientStatus[clientfd] = Pasv;

			RandomPasvPort(clientfd, num1, num2);
			fileIP[clientfd][0] = '\0';
			strcat(fileIP[clientfd], "127.0.0.1");

			filefd[clientfd] = ServerCreateFileDescriptor(filePort[clientfd], NULL, BindMode);
            clientStatus[filefd[clientfd]] = File;
            printf("open file socket %d\n", filefd[clientfd]);
            if(originfd != 0){
                close(originfd);
                clientStatus[originfd] = None;
                printf("close file socket %d\n", originfd);
            }

			msg[0] = '\0';
			strcat(msg, "227 Pasv success 127,0,0,1,");
			strcat(msg, num1);
			strcat(msg, ",");
			strcat(msg, num2);
			strcat(msg, "\r\n\0");
			send(clientfd, msg, strlen(msg), 0);
		}
		else if(strcmp(req, "RETR") == 0){
			char msg[128] = "150 RETR starting...\r\n";

			if(clientStatus[clientfd] != Pasv && clientStatus[clientfd] != Port){
				char badmsg[] = "425 PORT or PASV first\r\n";
				send(clientfd, badmsg, strlen(badmsg), 0);
				return;
			}

            fileName[clientfd][0] = '\0';
            strncpy(fileName[clientfd], PATH, strlen(PATH));
            fileName[clientfd][strlen(PATH)] = '\0';
            strcat(fileName[clientfd], buf+5);

            send(clientfd, msg, strlen(msg), 0);

            if(clientStatus[clientfd] == Port){

                int clientfd2 = ServerCreateFileDescriptor(filePort[clientfd], fileIP[clientfd], ConnectMode);

                if(ServerRetrSendFile(clientfd, clientfd2) != -1){
                    close(clientfd2);
                    clientStatus[clientfd] = Login;
                }
            }
            else{
                clientStatus[clientfd] = Retr;
            }
		}
		else if(strcmp(req, "SYST") == 0){
			char msg[] = "215 UNIX Type: L8\r\n";
			send(clientfd, msg, strlen(msg), 0);
		}
        else{
            char msg[] = "503 Undefined request\r\n";
			send(clientfd, msg, strlen(msg), 0);
        }
		break;
	}
}

int ServerCreateFileDescriptor(char* port, void* ip, int fdMode){
	struct addrinfo hints, *servinfo, *p;
	int sockfd;
	int rv;
	int yes=1;        // for setsockopt() SO_REUSEADDR, below

	// get us a socket and bind it
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if(ip == NULL)
		hints.ai_flags = AI_PASSIVE;
	if ((rv = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}
	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}
		if (fdMode == ConnectMode &&  connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}
		if (fdMode == BindMode && bind(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
			close(sockfd);
			continue;
		}
		break;
	}
	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (fdMode == BindMode && listen(sockfd, 10) == -1) {
        perror("listen");
        exit(3);
    }

	return sockfd;
}


int main(void){
    fd_set master;    // master file descriptor list
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number

    int listener;     // listening socket descriptor
    int newfd;        // newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen;

    char buf[256];    // buffer for client data
    int nbytes;

	char remoteIP[INET6_ADDRSTRLEN];

    int i, j;

	for(i = 0; i < 100; i++){
		clientStatus[i] = None;
	}
    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);

	//
	listener = ServerCreateFileDescriptor(PORT, NULL, BindMode);

    // add the listener to the master set
    FD_SET(listener, &master);

    // keep track of the biggest file descriptor
    fdmax = listener; // so far, it's this one

    // main loop
    for(;;) {
		printf("############\n");
        read_fds = master; // copy it
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(4);
        }
        // run through the existing connections looking for data to read
        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if (i == listener) {
                    // handle new connections
                    addrlen = sizeof remoteaddr;
					newfd = accept(listener,(struct sockaddr *)&remoteaddr,&addrlen);

					if (newfd == -1) {
						perror("accept");
                    }
					else {
                        FD_SET(newfd, &master); // add to master set
                        if (newfd > fdmax) {    // keep track of the max
                            fdmax = newfd;
                        }
						// send greeting message
						char str[] = "220 Anonymous FTP server ready.\r\n";
						send(newfd, str, strlen(str), 0);
						// set status to Connected
						clientStatus[newfd] = Login;
                        printf("selectserver: new connection from %s on socket %d\n",
							   inet_ntop(remoteaddr.ss_family,get_in_addr((struct sockaddr*)&remoteaddr),remoteIP, INET6_ADDRSTRLEN),newfd);
                    }
                }
                else if(clientStatus[i] == File){
                    int j, clientfd2;

                    for(j = 0; j <= fdmax; ++j){
                        if(filefd[j] == i){
                            break;
                        }
                    }
                    clientfd2 = accept(i, (struct sockaddr *)&remoteaddr, &addrlen);

                    if(ServerRetrSendFile(j, clientfd2) != -1){
                        close(clientfd2);
                        close(i);
                        FD_CLR(i, &master);
                        clientStatus[i] = None;
                        filefd[j] = 0;// close file fd
                        clientStatus[j] = Login;
                    }
                }
				else {
                    // handle data from a client
					nbytes = recv(i, buf, sizeof buf, 0);
                    if (nbytes <= 0) {
                        // got error or connection closed by client
                        if (nbytes == 0) {
                            // connection closed
                            printf("selectserver: socket %d hung up\n", i);
                        }
						else {
                            perror("recv");
                        }
                        close(i); // bye!
                        FD_CLR(i, &master); // remove from master set
						if(clientStatus[i] == Pasv || clientStatus[i] == Retr){
							close(filefd[i]);
							FD_CLR(filefd[i], &master);//
							clientStatus[filefd[i]] = None;
                            printf("close file socket %d\n", filefd[i]);
							filefd[i] = 0;
						}
						clientStatus[i] = None; // reset client status to none
                    }
					else {
						int originfd = filefd[i];
						buf[nbytes] = '\0';
						ServerHandleMsg(i, buf, nbytes);
						if(clientStatus[i] == Pasv && originfd != filefd[i]){
							FD_SET(filefd[i], &master);//
                            printf("fd set %d\n", filefd[i]);
							if (filefd[i] > fdmax) {    // keep track of the max
	                            fdmax = filefd[i];
	                        }
							if(originfd > 0){
								FD_CLR(originfd, &master);//
							}
						}
                    }
                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END for(;;)--and you thought it would never end!

    return 0;
}
