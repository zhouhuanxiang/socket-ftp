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
#include <errno.h>
#include <time.h>


#define PORT 21111   // port we're listening on
#define MAX_FD 50
#define MAX_CLIENT 10
#define BUF_SIZE 1024
enum ClientStatus{
	None,
	Connected,
	NotLogin,
	Login,
	Port,
	Pasv,
	File,
	Retr,
	Stor
};
enum CreateFdMode{
	ConnectMode,
	BindMode
};
int clientStatus[MAX_FD];
char fileIP[MAX_FD][16];
int filePort[MAX_FD];
char fileName[MAX_FD][32];
int filefd[MAX_FD];

char PATH[] = "";

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//get first three capital char of req message form client
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

//as client
int ServerRecvMsg(int sockfd, char* buf){
	int nbytes;
	if ((nbytes = recv(sockfd, buf, BUF_SIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}
	buf[nbytes] = '\0';
	return nbytes;
}

//for PORT mode
//client deliver a ',' type address
//extract ip('.' type) and port(char type)
int GetFileAddr(char* msg, int clientfd){
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
	filePort[clientfd] = num1*256+num2;
	return 0;
}

//
int RandomPasvPort(int clientfd, char* num1, char* num2){
	int r;
	srand(time(NULL));
	r = rand()%(65535-20000)+20000;
	filePort[clientfd] = r;
	sprintf(num1, "%d", (r-r%256)/256);
	sprintf(num2, "%d", r%256);
	return r;
}

// as client
int ServerSendFile(FILE* pfile, int filefd){
	long length;
	long readlength = 1;
	char buf[BUF_SIZE];

    //sleep(1);

    fseek(pfile, 0, SEEK_END);
    length = ftell(pfile);
    fseek(pfile, 0, SEEK_SET);

    while ((readlength > 0) && (length > 0)){
        readlength = fread(buf, sizeof(char), BUF_SIZE-1, pfile);

        if (readlength > 0){
			buf[readlength] = '\0';
            send(filefd, buf, readlength, 0);
            length -= readlength;
        }
        printf("# %ld\n", readlength);
    }
	return 1;
}

//as client
int ServerRecvFile(FILE* pfile, int filefd){
	char buffer[BUF_SIZE];
	bzero(buffer, BUF_SIZE);
	int file_block_length = 0;
	while ((file_block_length = ServerRecvMsg(filefd, buffer)) > 0)
	{
		if (file_block_length < 0)
		{
			printf("Recieve Data From Client Failed!\n");
		}
		printf("# %d\n", file_block_length);
		int write_length = fwrite(buffer, sizeof(char), file_block_length, pfile);
		if (write_length < file_block_length){
			printf("Write Failed\n");
			break;
		}
		bzero(buffer, BUF_SIZE);
	}
	return 1;
}

int ServerTransferFile(int clientfd, int clientfd2){
    char filename[128];
    char msg[] = "226 RETR success\r\n";
    FILE* pfile;

    if(clientfd2 == -1){
        return -1;
    }
	if(clientStatus[clientfd] == Retr){
		pfile = fopen(fileName[clientfd], "rb+");
	}
	else if(clientStatus[clientfd] == Stor){
		pfile = fopen(fileName[clientfd], "w+");
	}
    if(pfile == NULL){
        char badmsg[] = "451 file handle failed\r\n";
        send(clientfd, badmsg, strlen(badmsg), 0);
        return -1;
    }
    if((clientStatus[clientfd] == Retr && ServerSendFile(pfile, clientfd2) == -1) ||
	   (clientStatus[clientfd] == Stor && ServerRecvFile(pfile, clientfd2) == -1)){
        char badmsg[32];
		badmsg[0] = '\0';
		if(clientStatus[clientfd] == Retr){
			strcat(badmsg, "451 RETR failed\r\n");
		}
		else{
			strcat(badmsg, "451 Stor failed\r\n");
		}
        send(clientfd, badmsg, strlen(badmsg), 0);
        fclose(pfile);	//close the dest file
        return -1;
    }

    fclose(pfile);	//close the dest file
    send(clientfd, msg, strlen(msg), 0);
    return 1;
}

//as client
int ServerCreateFileDescriptor(int port, void* ip, int fdMode){
	int sockfd;
	struct sockaddr_in addr;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		printf("Error socket(): %s(%d)\n", strerror(errno), errno);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if(ip == NULL || fdMode == BindMode){
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

		if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
			printf("Error bind(): %s(%d)\n", strerror(errno), errno);
			return -1;
		}

		if (listen(sockfd, 10) == -1) {
			printf("Error listen(): %s(%d)\n", strerror(errno), errno);
			return -1;
		}
	}
	else{
		if (inet_pton(AF_INET, ip, &addr.sin_addr) < 0) {
			printf("Error inet_pton(): %s(%d)\n", strerror(errno), errno);
			return -1;
		}

		if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
			printf("Error connect(): %s(%d)\n", strerror(errno), errno);
			return -1;
		}
	}
	return sockfd;
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
			char tmp[BUF_SIZE];
			char msg[] = "200 PORT success\r\n";
			strncpy(tmp, buf+5, strlen(buf)-5);
			tmp[strlen(buf)-5] = '\0';
			if(GetFileAddr(tmp, clientfd) == -1){
				char badmsg[] = "503 bad PORT request\r\n";
				send(clientfd, badmsg, strlen(badmsg), 0);
				break;
			}
			send(clientfd, msg, strlen(msg), 0);
			clientStatus[clientfd] = Port;
		}
		else if(strcmp(req, "PASV") == 0){
			char num1[16];
			char num2[16];
			char msg[BUF_SIZE];
            int originfd = filefd[clientfd];

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
			clientStatus[clientfd] = Pasv;
		}
		else if(strcmp(req, "RETR") == 0 || strcmp(req, "STOR") == 0){
			char msg[32];
			int originStatus = clientStatus[clientfd];
			if(clientStatus[clientfd] != Pasv && clientStatus[clientfd] != Port){
				char badmsg[] = "425 PORT or PASV first\r\n";
				send(clientfd, badmsg, strlen(badmsg), 0);
				return;
			}
			msg[0] = '\0';
			if(strcmp(req, "RETR") == 0){
				strcat(msg, "150 RETR starting...\r\n");
				clientStatus[clientfd] = Retr;
			}
			else if(strcmp(req, "STOR") == 0){
				strcat(msg, "150 STOR starting...\r\n");
				clientStatus[clientfd] = Stor;
			}
			send(clientfd, msg, strlen(msg), 0);

            fileName[clientfd][0] = '\0';
            strncpy(fileName[clientfd], PATH, strlen(PATH));
            fileName[clientfd][strlen(PATH)] = '\0';
            strcat(fileName[clientfd], buf+5);
            if(originStatus == Port){
                int clientfd2 = ServerCreateFileDescriptor(filePort[clientfd], fileIP[clientfd], ConnectMode);
                if(ServerTransferFile(clientfd, clientfd2) != -1){
                    close(clientfd2);
                    clientStatus[clientfd] = Login;
                }
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

int main(int argc, char *argv[]){
    fd_set master;    // master file descriptor list
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number

    int sockfd;     // listening socket descriptor
    int newfd;        // newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen = sizeof remoteaddr;

    char buf[BUF_SIZE];    // buffer for client data
    int nbytes;
    int i, j;

	//initialize
	for(i = 0; i < MAX_FD; i++){
		clientStatus[i] = None; //set all fd status to none
	}
    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);
	sockfd = ServerCreateFileDescriptor(PORT, NULL, BindMode);//sockfd for send mark msg to client and recv req
    FD_SET(sockfd, &master);// add the sockfd to the master set
    fdmax = sockfd;// keep track of the biggest file descriptor

    // main loop
    for(;;) {
        read_fds = master;
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(4);
        }
        // run through the existing connections looking for data to read
        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if (i == sockfd) {
					newfd = accept(sockfd,(struct sockaddr *)&remoteaddr,&addrlen);// handle new connections

					if (newfd == -1) {
						perror("accept");
                    }
					else {
                        FD_SET(newfd, &master); // add to master set
                        if (newfd > fdmax) {    // keep track of the max
                            fdmax = newfd;
                        }
						char str[] = "220 Anonymous FTP server ready.\r\n";// send greeting message
						send(newfd, str, strlen(str), 0);
						clientStatus[newfd] = Login;// set status to Connected
                    }
                }
                else if(clientStatus[i] == File){//transfer file, only PASV mode
                    int clientfd2;

                    for(j = 0; j <= fdmax; ++j){
                        if(filefd[j] == i){       //clienfd j is the caller of filefd i
                            break;
                        }
                    }

                    clientfd2 = accept(i, (struct sockaddr *)&remoteaddr, &addrlen);//clientfd j open a socket clientfd2
																					//accept it
                    if(ServerTransferFile(j, clientfd2) != -1){//transfer success, reset all to normal
                        close(clientfd2);
                        close(i);
                        FD_CLR(i, &master);
                        clientStatus[i] = None;
                        filefd[j] = 0;
                        clientStatus[j] = Login;
                    }
                }
				else {				  // handle data from a client
					nbytes = ServerRecvMsg(i, buf);
                    if (nbytes <= 0) {// got error or connection closed by client
                        if (nbytes == 0) {
                            printf("selectserver: socket %d hung up\n", i);// connection closed
                        }
						else {
                            perror("recv");
                        }
                        close(i);
                        FD_CLR(i, &master); // remove from master set
						clientStatus[i] = None; // reset client status to none
						if(clientStatus[i] == Pasv || clientStatus[i] == Retr){
							close(filefd[i]);
							FD_CLR(filefd[i], &master);
							clientStatus[filefd[i]] = None;
                            printf("close file socket %d\n", filefd[i]);
							filefd[i] = 0;
						}
                    }
					else if(clientStatus[i] != Retr && clientStatus[i] != Stor){
						int originfd = filefd[i];
						ServerHandleMsg(i, buf, nbytes);
						if(clientStatus[i] == Pasv && originfd != filefd[i]){
							FD_SET(filefd[i], &master);
                            printf("fd set %d\n", filefd[i]);
							if (filefd[i] > fdmax) {    // keep track of the max
	                            fdmax = filefd[i];
	                        }
							if(originfd > 0){
								FD_CLR(originfd, &master);
							}
						}
                    }
                }
            }
        }
    }
    return 0;
}
