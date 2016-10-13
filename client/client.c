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

#define PORT "9034" // the port client will be connecting to

#define MAXDATASIZE 516 // max number of bytes we can get at once

enum ClientStatus{
	None,
	Connected,
	NotLogin,
	Login,
	Port,
	Pasv
};

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
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

void ClientRecvMsg(int sockfd, char* buf){
	int nbytes;
	if ((nbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}
	buf[nbytes] = '\0';
}

int ClientUserInputMsg(char* msg){
	int length;
	fgets(msg, MAXDATASIZE, stdin);
	length = strlen(msg);
	msg[length-1] = '\0';
	return length;
}

int main(int argc, char *argv[])
{
	int sockfd, nbytes;
	int status = None;

	char sendMsg[MAXDATASIZE];
	char recvMsg[MAXDATASIZE];
	char filePort[MAXDATASIZE];
	char fileIP[MAXDATASIZE];

	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo)) != 0) {
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

	ClientRecvMsg(sockfd, recvMsg);
	for(;;){
		printf("############\n");
		char req[32], mask[32];
		ClientUserInputMsg(sendMsg);
		if(strlen(sendMsg) == 0){
			continue;
		}
		send(sockfd, sendMsg, strlen(sendMsg), 0);
		GetSendMsgReq(sendMsg, req);
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
		else if(strcmp(req, "PORT")==0 && strcmp(mask, "200")==0){
			status = Port;
			GetFileAddr(sendMsg, fileIP, filePort);
		}
		else if(strcmp(req, "PASV")==0 && strcmp(mask, "227")==0){
			status = Pasv;
			GetFileAddr(recvMsg, fileIP, filePort);
			// printf("%s:%s\n", fileIP, filePort);
		}
		printf("status: %d\n", status);
		printf("%s\n", recvMsg);
	}

	close(sockfd);

	return 0;
}
