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

#define MAXDATASIZE 516 // max number of bytes we can get at once
#define FTP_BUF_SIZE 1024

char serverPort[] = "34408";
char serverIP[] = "127.0.0.1";

enum ClientStatus{
	None,
	Connected,
	NotLogin,
	Login,
	Port,
	Pasv
};

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void GetSendMsgReq(char* msg, char* req){
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

int ClientRecvMsg(int sockfd, char* buf){
	int nbytes;
	if ((nbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}
	buf[nbytes] = '\0';
	return nbytes;
}

int ClientUserInputMsg(char* msg){
	int length;
	fgets(msg, MAXDATASIZE, stdin);
	length = strlen(msg);
	msg[length-1] = '\0';
	return length;
}

int ClientCreateRecvFileDescriptor(char* port, void* ip){
	struct addrinfo hints, *servinfo, *p;
	int sockfd;
	int rv;
	int yes=1;        // for setsockopt() SO_REUSEADDR, below
	char s[INET6_ADDRSTRLEN];

	// printf("%s:%s\n", ip, port);

	// get us a socket and bind it
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
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
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}
		break;
	}
	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	return sockfd;
}

int ClinetCreateSendFileDescriptor(char* port, void* ip){
	struct addrinfo hints, *ai, *p;
	int serverfd;
	int rv;
	int yes=1;        // for setsockopt() SO_REUSEADDR, below

	// get us a socket and bind it
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if(ip == NULL)
		hints.ai_flags = AI_PASSIVE;
	if ((rv = getaddrinfo(ip, port, &hints, &ai)) != 0) {
		fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
		exit(1);
	}

	for(p = ai; p != NULL; p = p->ai_next) {
		serverfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (serverfd < 0) {
			continue;
		}

		// lose the pesky "address already in use" error message
		setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		if (bind(serverfd, p->ai_addr, p->ai_addrlen) < 0) {
			close(serverfd);
			continue;
		}
		break;
	}

	// if we got here, it means we didn't get bound
	if (p == NULL) {
		fprintf(stderr, "selectserver: failed to bind\n");
		exit(2);
	}

	freeaddrinfo(ai); // all done with this

    if (listen(serverfd, 10) == -1) {
        perror("listen");
        exit(3);
    }

	return serverfd;
}


void ClientSendFile(FILE* pfile, int transfd){


}

void ClientRecvFile(FILE* fp, int soc){
	char buffer[FTP_BUF_SIZE];
	bzero(buffer, FTP_BUF_SIZE);
	int file_block_length = 0;
	while ((file_block_length = ClientRecvMsg(soc, buffer)) > 0)
	{
		if (file_block_length < 0)
		{
			printf("Recieve Data From Client Failed!\n");
		}
		printf("# %d\n", file_block_length);
		int write_length = fwrite(buffer, sizeof(char), file_block_length, fp);
		if (write_length < file_block_length){
			printf("Write Failed\n");
			break;
		}
		bzero(buffer, FTP_BUF_SIZE);
	}
	fclose(fp);
	printf("Transfer Finished\n");
}

int main(int argc, char *argv[])
{
	int sockfd, nbytes;
	int filefd, thisfd;
	int status = None;

	char sendMsg[MAXDATASIZE];
	char recvMsg[MAXDATASIZE];
	char filePort[MAXDATASIZE];
	char fileIP[MAXDATASIZE];

	sockfd = ClientCreateRecvFileDescriptor(serverPort, serverIP);

	ClientRecvMsg(sockfd, recvMsg);
	for(;;){
		char req[32], mask[32];

		printf("############\n");
		ClientUserInputMsg(sendMsg);
		if(strlen(sendMsg) == 0){
			continue;
		}
		GetSendMsgReq(sendMsg, req);
		if(strcmp(req, "PORT") == 0){
			status = Port;
			GetFileAddr(sendMsg, fileIP, filePort);
			thisfd = ClinetCreateSendFileDescriptor(filePort, fileIP);
		}
		send(sockfd, sendMsg, strlen(sendMsg), 0);

		recvMsg[0] = '\0';
		ClientRecvMsg(sockfd, recvMsg);
		strncpy(mask, recvMsg, 3);
		mask[3] = '\0';

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
		else if(strcmp(req, "RETR") == 0){
			printf("%s", recvMsg);
			if(strcmp(mask, "150") != 0){
				status = Login;
				continue;
			}
			else{
				char filename[64];
				FILE* pfile;

				strncpy(filename, sendMsg+5, strlen(sendMsg)-5);
				filename[strlen(sendMsg)-5] = '\0';
				pfile = fopen(filename, "w+");
			    if(pfile == NULL){
					ClientRecvMsg(sockfd, recvMsg);
					close(filefd);
					char badmsg[] = "create file failed\r\n";
					printf("%s\n", badmsg);
					continue;
				}

				if(status == Pasv){
					filefd = ClientCreateRecvFileDescriptor(filePort, fileIP);
				}
				else{
					struct sockaddr_storage remoteaddr; // client address
				    socklen_t addrlen = sizeof remoteaddr;
					filefd = accept(thisfd,(struct sockaddr *)&remoteaddr,&addrlen);
				}
				ClientRecvFile(pfile, filefd);
				close(filefd);
				if(status == Port){
					close(thisfd);
				}
				ClientRecvMsg(sockfd, recvMsg);
				status = Login;
			}
		}
		else if(strcmp(req, "STOR") == 0){

		}
		// printf("status: %d\n", status);
		printf("%s", recvMsg);
	}

	close(sockfd);

	return 0;
}
