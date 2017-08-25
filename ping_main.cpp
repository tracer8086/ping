#include "winsock_error.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)

int main()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	WSADATA filler;

	if (WSAStartup(WSA_VERSION, &filler))
	{
		output_error("Couldn't initialize WSA");
		return EXIT_FAILURE;
	}

	char host_name[MAXGETHOSTSTRUCT];

	enter_message("Please enter a host name: ", host_name);
	std::cout << std::endl;

	LPHOSTENT remote_host_info = gethostbyname(host_name);

	if (remote_host_info == NULL)
	{
		output_error("Couldn't get a host info");
		finalize();

		return EXIT_FAILURE;
	}

	if (remote_host_info->h_addrtype == AF_INET6)
	{
		output_error("Sorry, but R-Scan can't perform scanning of ipv6-hosts");
		finalize();

		return EXIT_SUCCESS;
	}

	//ALIASES SHOWING
	if (remote_host_info->h_aliases[0])
	{
		std::cout << "Server name aliases: " << std::endl;

		for (int i = 0; remote_host_info->h_aliases[i]; i++)
			std::cout << remote_host_info->h_aliases[i] << std::endl;

		std::cout << std::endl;
	}
	else
		std::cout << "Host has no aliases" << std::endl << std::endl;

	in_addr tmp;

	//ADDRESSES SHOWING
	if (remote_host_info->h_addr_list[1])
	{
		std::cout << "Server addresses: " << std::endl;

		for (int i = 0; remote_host_info->h_addr_list[i]; i++)
		{
			tmp.s_addr = *(u_long*)remote_host_info->h_addr_list[i];
			std::cout << inet_ntoa(tmp) << std::endl;
		}

		std::cout << std::endl;
	}
	else
	{
		std::cout << "Server address: ";
		tmp.s_addr = *(u_long*)remote_host_info->h_addr;
		std::cout << inet_ntoa(tmp) << std::endl << std::endl;
	}

	SOCKET sock = ICMP_SOCKET;
	fd_set read;
	sockaddr_in server_data;
	ECHO_REQUEST echo_req;
	ECHO_REPLY echo_rep;
	timeval t_val = { 100, 0 };

	if (sock == INVALID_SOCKET)
	{
		output_error("Couldn't create an ICMP socket");
		finalize();

		return EXIT_FAILURE;
	}

	//SOCKADDR FILLING
	server_data.sin_family = AF_INET;
	server_data.sin_port = 0;
	tmp.s_addr = *(u_long*)remote_host_info->h_addr;
	inet_pton(AF_INET, (PCSTR)inet_ntoa(tmp), &server_data.sin_addr);

	//ICMP HDR AND ECHO_REQUEST STRUCT FILLING
	echo_req.icmp_hdr.type = ICMP_ECHO_REQ;
	echo_req.icmp_hdr.code = 0;
	echo_req.icmp_hdr.id = 0;
	echo_req.icmp_hdr.seq = 0;
	echo_req.icmp_hdr.checksum = 0;
	echo_req.dw_time = GetTickCount();
	memset(echo_req.data, 87, PACK_FRAME_SIZE);
	echo_req.icmp_hdr.checksum = IP_checksum((LPWORD)&echo_req, sizeof(ECHO_REQUEST) / 2);

	if (sendto(sock, (LPSTR)&echo_req, sizeof(echo_req), 0, (LPSOCKADDR)&server_data, sizeof(server_data)) == SOCKET_ERROR)
	{
		error_to_close_socket("Couldn't perform a ping", sock);
		finalize();

		return EXIT_FAILURE;
	}

	FD_ZERO(&read);
	FD_SET(sock, &read);

	int ret = select(0, &read, NULL, NULL, &t_val);

	if (ret == SOCKET_ERROR)
	{
		error_to_close_socket("Couldn't perform data awaiting", sock);
		finalize();

		return EXIT_FAILURE;
	}
	else if (ret == 0)
	{
		error_to_close_socket("Wating time exceeded", sock);
		finalize();

		return EXIT_FAILURE;
	}
	else
	{
		if (recvfrom(sock, (LPSTR)&echo_rep, sizeof(ECHO_REPLY), 0, NULL, NULL) == SOCKET_ERROR)
		{
			error_to_close_socket("Couldn't receive ICMP", sock);
			finalize();

			return EXIT_FAILURE;
		}

		std::cout << "from " << inet_ntoa(tmp) << " received " << PACK_FRAME_SIZE << " bytes in " << GetTickCount() - echo_rep.echo_request.dw_time
			<< " ms with TTL = " << (int)echo_rep.ip_hdr.TTL << std::endl;
		std::cout << "Type: " << (int)echo_rep.echo_request.icmp_hdr.type << " Code: " << (int)echo_rep.echo_request.icmp_hdr.code << std::endl;
	}

	finalize();

	return EXIT_SUCCESS;
}