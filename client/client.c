/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define BUF_SIZE 1024

int serverPort = 21111;
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

//for PASV mode
//server deliver a ',' type address
//extract ip('.' type) and port(char type)
void GetFileAddr(char* msg, char* fileIP, int filePort){
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
	filePort = num1*256+num2;
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
	msg[length-1] = '\0';
	return length;
}

//bind to a server socket or open a new socket
//bind     fdMode = BindMode
//connect  fdMode = ConnectMode
int ClientCreateFileDescriptor(int port, void* ip, int fdMode){
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
        printf("# %ld\n", readlength);
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
		printf("# %d\n", file_block_length);
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
	int filePort;
	char fileIP[BUF_SIZE];

	//bind to server & get its fd in sockfd
	//only for send req and recv msg
	sockfd = ClientCreateFileDescriptor(serverPort, serverIP, ConnectMode);

	//recv greeting msg from server
	ClientRecvMsg(sockfd, recvMsg);
	for(;;){
		char req[32], mask[32];

		printf("############\n");
		ClientUserInputMsg(sendMsg);
		//empty input
		if(strlen(sendMsg) == 0){
			continue;
		}
		//get req
		GetSendMsgReq(sendMsg, req);
		if(strcmp(req, "PORT") == 0){
			status = Port;
			GetFileAddr(sendMsg, fileIP, filePort);
			portfd = ClientCreateFileDescriptor(filePort, fileIP, BindMode);
		}
		send(sockfd, sendMsg, strlen(sendMsg), 0);
		//get mask
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
		else if(strcmp(req, "RETR") == 0 || strcmp(req, "STOR") == 0){
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

				if(strcmp(req, "RETR") == 0){
					pfile = fopen(filename, "w+");
				}
				else if(strcmp(req, "STOR") == 0){
					pfile = fopen(filename, "rb+");
				}
			    if(pfile == NULL){
					ClientRecvMsg(sockfd, recvMsg);
					char badmsg[] = "file handle failed\r\n";
					printf("%s\n", badmsg);
					continue;
				}
				//pasv mode, connect to aimed socket first
				if(status == Pasv){
					filefd = ClientCreateFileDescriptor(filePort, fileIP, ConnectMode);
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
		else if(strcmp(req, "STOR") == 0){

		}
		printf("%s", recvMsg);
	}

	close(sockfd);
	return 0;
}
