#pragma once
#ifndef WINSOCK_ERROR
#define WINSOCK_ERROR

#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <vector>
#include <cstring>
#include <ctime>
#include <WS2tcpip.h>

#define ECHO_PORT 32768
#define WSA_VERSION 0x0202
#define LOCALHOST "127.0.0.1"
#define BUFF_SIZE 8192
#define BACKLOG 4
#define WAIT_TIME 1
#define INPUT_BUFF 16
#define PACK_FRAME_SIZE 64
#define REPLY_DATA_SIZE 0x100
#define ICMP_ECHO_REQ 8
#define TCP_SOCKET socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
#define UDP_SOCKET socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)
#define ICMP_SOCKET socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)

typedef struct ICMP_hdr
{
	u_char type;
	u_char code;
	WORD checksum;
	WORD id;
	WORD seq;
} ICMP_HDR;

typedef struct echo_request //packet that will be sent through the network
{
	ICMP_HDR icmp_hdr;
	DWORD dw_time;
	char data[PACK_FRAME_SIZE];
} ECHO_REQUEST;

typedef struct ip_hdr
{
	u_char ver_ihl; //4 bit for version, 4 bit for internet header length (in DWORDs)
	u_char dscp_ecn; //DiffServ: 6 bit for dscp (packet priority) and 2 bit ECN (congestion flag); if congestion exists, trancmission rate reduces 
	short tot_len; //length of header + data, 16 bit field
	short id; //for packet fragments identifying (if a packet was fragmented)
	short flag_off; //flags of fragmentation and fragment offset; 1st bit - reserved; 2nd bit - if set, packet won't be fragmented if it need and will be dropped;
	//3rd bit - set for all fragmented packets; fragment offset - 13 bit field, defines a fragment offset relative to the beginnig of original IP datagram; measured in 64 bit blocks
	u_char TTL; //time-to-live, 8 bit field; measured determined bu the number of gateways and hosts packet can traverse
	u_char protocol; //8 bit field; protocol list: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	WORD checksum; //16 bit field; if it hasn't been computed yet, it must be equal to 0
	in_addr src_addr; //32 bit sender IP address
	in_addr dst_addr; //32 bit receiver IP address
} IP_HDR;

typedef struct echo_reply
{
	IP_HDR ip_hdr;
	ECHO_REQUEST echo_request;
	char c_filler[REPLY_DATA_SIZE];
} ECHO_REPLY;

inline WORD IP_checksum(LPWORD data, size_t d_size)
{
	DWORD sum = 0;

	while (d_size > 0)
	{
		sum += *data++;
		d_size--;
	}

	sum += (sum >> 16);

	return (WORD)~sum;
}

inline void output_error(const char* message)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
	std::cerr << message << std::endl;
	std::cerr << "Error code: " << WSAGetLastError() << std::endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

inline void finalize()
{
	WSACleanup();
	system("pause");
}

inline void close_socket(SOCKET sock)
{
	if (closesocket(sock) == SOCKET_ERROR)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "Couldn't close socket: error " << WSAGetLastError() << std::endl;
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	}
}

inline void error_to_close_socket(const char* message, SOCKET sock)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);

	output_error(message);
	close_socket(sock);

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

inline void clear_buffer(char* buffer, const int buff_size)
{
	for (int i = 0; i < buff_size; i++)
		buffer[i] = '\0';
}

#endif
