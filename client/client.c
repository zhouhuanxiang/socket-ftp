/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define BUF_SIZE 1024

#define serverPort "21"
char serverIP[] = "127.0.0.1";

enum ClientStatus{
	None,
	Connected,
	NotLogin,
	Login,
	Port,
	Pasv
};

enum CreateFdMode{
	ConnectMode,
	BindMode
};

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//get first three capital char of return message form server
void GetSendMsgReq(char* msg, char* req){
	int length  = strlen(msg);
	int i = 0;
	if(length < 3){
		req[0] = '\0';
	}
	else{
		while(msg[i]>='A' && msg[i]<='Z' && i < length)
		{
			req[i] = msg[i];
			++i;
		}
		req[i] = '\0';
	}
}

//receiev msg form server
//from sockfd and store in buf
int ClientRecvMsg(int sockfd, char* buf){
	int nbytes;
	if ((nbytes = recv(sockfd, buf, BUF_SIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}
	buf[nbytes] = '\0';
	return nbytes;
}

//store client input in msg
int ClientUserInputMsg(char* msg){
	int length;
	fgets(msg, BUF_SIZE, stdin);
	length = strlen(msg);
	return (length-1);
}

//for PASV mode
//server deliver a ',' type address
//extract ip('.' type) and port(char type)
void GetFileAddr(char* msg, char* fileIP, char* filePort){
	int i, j;
	int count = 0;
	int length = strlen(msg);
	int num1, num2;
	char buf1[32], buf2[32];
	for(i = 3; i < length; ++i){
		if(msg[i]>='0' && msg[i] <= '9'){
			break;
		}
	}
	for(j = i; j < length; ++j){
		if(msg[j] == ','){
			count++;
			if(count == 4){
				break;
			}
			fileIP[j-i] = '.';
			continue;
		}
		fileIP[j-i] = msg[j];
	}
	fileIP[j-i] = '\0';
	i = j;
	for(j = i+1; j < length; ++j){
		if(msg[j] == ','){
			break;
		}
	}
	strncpy(buf1, msg+i+1, j-i-1);
	buf1[j-i-1] = '\0';
	num1 = strtol(buf1, NULL, 10);
	strncpy(buf2, msg+j+1, length-j-1);
	buf2[length-j-1] = '\0';
	num2 = strtol(buf2, NULL, 10);
	sprintf(filePort, "%d", num1*256+num2);
}

//bind to a server socket or open a new socket
//bind     fdMode = BindMode
//connect  fdMode = ConnectMode
int ClientCreateFileDescriptor(char* port, void* ip, int fdMode){
	struct addrinfo hints, *servinfo, *p;
	int sockfd;
	int rv;
	int yes=1;

	// get us a socket and bind it or connect to it
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
		// lose the pesky "address already in use" error message
    	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
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

//send file to server socket
//from file *pfile
void ClientSendFile(FILE* pfile, int filefd){
	long length;
	long readlength = 1;
	char buf[BUF_SIZE];

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
    }
}

//recv file from server socket
//store it in *pfile
void ClientRecvFile(FILE* pfile, int filefd){
	char buffer[BUF_SIZE];
	bzero(buffer, BUF_SIZE);
	int file_block_length = 0;
	while ((file_block_length = ClientRecvMsg(filefd, buffer)) > 0)
	{
		if (file_block_length < 0)
		{
			printf("Recieve Data From Client Failed!\n");
		}
		int write_length = fwrite(buffer, sizeof(char), file_block_length, pfile);
		if (write_length < file_block_length){
			printf("Write Failed\n");
			break;
		}
		bzero(buffer, BUF_SIZE);
	}
}

int main(int argc, char *argv[])
{
	int sockfd;
	int filefd, portfd;//filefd : file transfer
					   //portfd : port mode
	int status = None;

	char sendMsg[BUF_SIZE];
	char recvMsg[BUF_SIZE];
	char filePort[BUF_SIZE];
	char fileIP[BUF_SIZE];

	//bind to server & get its fd in sockfd
	//only for send req and recv msg
	sockfd = ClientCreateFileDescriptor(serverPort, serverIP, ConnectMode);
	//recv greeting msg from server
	ClientRecvMsg(sockfd, recvMsg);
	printf("%s", recvMsg);
	for(;;){
		char req[32], mask[32];

		ClientUserInputMsg(sendMsg);
		//empty input
		if(strlen(sendMsg) == 0){
			continue;
		}
		int length = strlen(sendMsg);
		sendMsg[length-1] = '\r';
		sendMsg[length] = '\n';
		sendMsg[length+1] = '\0';
		//get req
		GetSendMsgReq(sendMsg, req);
		if(strcmp(req, "PORT") == 0){
			status = Port;
			GetFileAddr(sendMsg, fileIP, filePort);
			portfd = ClientCreateFileDescriptor(filePort, fileIP, BindMode);
		}
		
		if((strcmp(req, "RETR")==0 || strcmp(req, "STOR")==0) && status == Pasv){
			filefd = ClientCreateFileDescriptor(filePort, fileIP, ConnectMode);
		}
		else{
			send(sockfd, sendMsg, strlen(sendMsg), 0);
		}
		if(strcmp(req, "ABOR") == 0 || strcmp(req, "QUIT") == 0){
			return 1;
		}

		recvMsg[0] = '\0';
		ClientRecvMsg(sockfd, recvMsg);
		if(recvMsg[2] == ' '){
			strncpy(mask, recvMsg, 2);
			mask[2] = '\0';
		}
		else{
			strncpy(mask, recvMsg, 3);
			mask[3] = '\0';
		}

		if(strcmp(req, "USER")==0 && strcmp(mask, "331")==0){
			status = NotLogin;
		}
		else if(strcmp(req, "PASS")==0 && strcmp(mask, "230")==0){
			status = Login;
		}
		else if(strcmp(req, "PASV")==0 && strcmp(mask, "227")==0){
			status = Pasv;
			GetFileAddr(recvMsg, fileIP, filePort);
		}
		else if(strcmp(req, "RETR") == 0 || strcmp(req, "STOR") == 0){
			printf("%s", recvMsg);
			if(strcmp(mask, "150") != 0 && strcmp(mask, "50") != 0){
				status = Login;
				continue;
			}
			else{
				char filename[64];
				FILE* pfile;
				strncpy(filename, sendMsg+5, strlen(sendMsg)-5);
				filename[strlen(sendMsg)-5] = '\0';

				if(strcmp(req, "RETR") == 0){
					pfile = fopen(filename, "w+");
				}
				else if(strcmp(req, "STOR") == 0){
					pfile = fopen(filename, "rb+");
				}
				//pasv mode, connect to aimed socket first
				if(status == Pasv){
					send(sockfd, sendMsg, strlen(sendMsg), 0);
				}
				//oterwise, accept the connect request from server
				else{
					struct sockaddr_storage remoteaddr;
				    socklen_t addrlen = sizeof remoteaddr;
					filefd = accept(portfd,(struct sockaddr *)&remoteaddr,&addrlen);
				}

				if(strcmp(req, "RETR") == 0){
					ClientRecvFile(pfile, filefd);
				}
				else if(strcmp(req, "STOR") == 0){
					ClientSendFile(pfile, filefd);
				}
				fclose(pfile);
				close(filefd);
				if(status == Port){
					close(portfd);
				}
				ClientRecvMsg(sockfd, recvMsg);
				status = Login;
			}
		}
		printf("%s", recvMsg);
	}

	close(sockfd);
	return 0;
}
