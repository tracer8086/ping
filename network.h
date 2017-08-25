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

#define VEC_DEL(vec, i) vec.erase(vec.begin()+i)

namespace con_mode
{
	enum mode
	{
		write,
		read,
		input //for client
	};
}

typedef struct async_connection
{
	SOCKET sock;
	USHORT con_port;
	int address_num; //address number in HOSTENT struct
	clock_t con_time;
} async_connection;

typedef struct port_range
{
	USHORT from;
	USHORT to;
	bool error_flag;
	char* error_message;
} port_range;

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

typedef std::vector<async_connection> con_list;

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

inline void enter_message(const char* invitation, char* buffer)
{
	std::cout << invitation;
	std::cin.getline(buffer, BUFF_SIZE);
}

inline void delete_invalid_cons(con_list& cons)
{
	con_list new_cons;

	for (con_list::iterator con = cons.begin(); con != cons.end(); con++)
		if ((*con).sock != INVALID_SOCKET)
		{
			new_cons.push_back(*con);
		}

	cons.clear();
	cons = new_cons;
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

inline void error_to_close_con(const char* message, con_list& cons, const int i)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);

	error_to_close_socket(message, cons[i].sock);
	cons[i].sock = INVALID_SOCKET;
	std::cerr << "Connection reset" << std::endl;

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

inline void error_to_close_con(const char* message, async_connection& con)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);

	error_to_close_socket(message, con.sock);
	con.sock = INVALID_SOCKET;
	std::cerr << "Connection reset" << std::endl;

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

inline void close_con(const char* message, con_list& cons, const int i)
{
	std::cout << message << std::endl;

	shutdown(cons[i].sock, SD_BOTH);
	close_socket(cons[i].sock);
	cons[i].sock = INVALID_SOCKET;
}

inline void error_to_close_cons(const char* message, con_list& cons)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);

	output_error(message);

	for (u_int i = 0; i < cons.size(); i++)
	{
		close_socket(cons[i].sock);
	}

	cons.clear();

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

inline void clear_buffer(char* buffer, const int buff_size)
{
	for (int i = 0; i < buff_size; i++)
		buffer[i] = '\0';
}

inline void parse_input(std::istream& stream, port_range& range, int& wait_time) //port range and waiting time for port scanner
{
	char buffer[INPUT_BUFF];

	range = { 0, 0, false, "" };
	stream.getline(buffer, INPUT_BUFF);

	if (!strcmp(buffer, ""))
	{
		range = { 0, 0, true, "No input" };
		return;
	}

	for (char* c = buffer; *c != '\0'; c++)
		if (*c == '>') //only one port
		{
			char number[INPUT_BUFF];

			c++;
			for (int i = 0; *c != '\0' && *c != ' '; i++, c++)
				if (isalpha(*c) || isblank(*c) || iscntrl(*c) || isspace(*c) || ispunct(*c))
				{
					range = { 0, 0, true, "Unavailable characters in input" };
					break;
				}
				else
					number[i] = *c;

			if (range.error_flag)
				break;

			if (*c == '\0')
			{
				range = { 0, 0, true, "Waiting time isn't specified" };
				break;
			}

			unsigned short temp = (unsigned short)strtoul(number, NULL, 0);
			clear_buffer(number, INPUT_BUFF);

			if (temp > 65535 || temp < 1)
				range = { 0, 0, true, "Incorrect range" };
			else
				range = { temp, temp, false, "" };

			c++;
			for (int i = 0; *c != '\0'; i++, c++)
				if (isalpha(*c) || isblank(*c) || iscntrl(*c) || isspace(*c) || ispunct(*c))
				{
					range = { 0, 0, true, "Unavailable characters in input" };
					break;
				}
				else
					number[i] = *c;

			if (range.error_flag)
				break;

			wait_time = atoi(number);

			break;
		}
		else if (isalpha(*c) || isblank(*c) || iscntrl(*c) || isspace(*c)) //unavailable characters
		{
			range = { 0, 0, true, "Unavailable characters in input" };
			break;
		}
		else if (isdigit(*c))
		{
			char number[INPUT_BUFF];

			for (int i = 0; *c != '\0' && *c != ' '; i++, c++)
				if (*c == '-')
					break;
				else if (isalpha(*c) || isblank(*c) || iscntrl(*c) || isspace(*c) || ispunct(*c))
				{
					range = { 0, 0, true, "Unavailable characters in input" };
					break;
				}
				else
					number[i] = *c;

			if (range.error_flag)
				break;

			range.from = (unsigned short)strtoul(number, NULL, 0);
			clear_buffer(number, INPUT_BUFF);

			if (range.from > 65535 || range.from < 1)
			{
				range = { 0, 0, true, "Incorrect range" };
				break;
			}

			if (*c == '\0')
			{
				range = { 0, 0, true, "Waiting time isn't specified" };
				break;
			}

			if (*c == ' ')
			{
				range.to = range.from;
				range.from = 1;

				c++;
				for (int i = 0; *c != '\0' && *c != ' '; i++, c++)
					if (isalpha(*c) || isblank(*c) || iscntrl(*c) || isspace(*c) || ispunct(*c))
					{
						range = { 0, 0, true, "Unavailable characters in input" };
						break;
					}
					else
						number[i] = *c;

				if (range.error_flag)
					break;

				wait_time = atoi(number);

				break;
			}

			if (*c == '-')
			{
				c++;
				for (int i = 0; *c != '\0' && *c != ' '; i++, c++)
					if (isalpha(*c) || isblank(*c) || iscntrl(*c) || isspace(*c) || ispunct(*c))
					{
						range = { 0, 0, true, "Unavailable characters in input" };
						break;
					}
					else
						number[i] = *c;
			}

			if (range.error_flag)
				break;

			range.to = (unsigned short)strtoul(number, NULL, 0);
			clear_buffer(number, INPUT_BUFF);

			if (range.to > 65535 || range.to < 1 || range.from > range.to)
			{
				range = { 0, 0, true, "Incorrect range" };
				break;
			}

			if (*c == '\0')
			{
				range = { 0, 0, true, "Waiting time isn't specified" };
				break;
			}

			c++;
			for (int i = 0; *c != '\0'; i++, c++)
				if (isalpha(*c) || isblank(*c) || iscntrl(*c) || isspace(*c) || ispunct(*c))
				{
					range = { 0, 0, true, "Unavailable characters in input" };
					break;
				}
				else
					number[i] = *c;

			if (range.error_flag)
				break;

			wait_time = atoi(number);

			break;
		}
}

#endif