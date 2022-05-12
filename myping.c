#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>          // provides access to the POSIX operating system API (include UNIX for Linux including GGC compiler)
#include <string.h>
#include <sys/types.h>       // defines data types used in system source code(unsigned short (ushort_t) type and the dev_t type) 
#include <sys/socket.h>      // main sockets header 
#include <netinet/in.h>      // Internet address family(in_port_t, in_addr_t)
#include <netinet/ip.h>      // Internet address Protocol (IPv4, IPv6)
#include <netinet/ip_icmp.h> // Internet address Protocol for ICMP protocol
#include <arpa/inet.h>       // definitions for internet operations
#include <errno.h>           // defines macros for reporting and retrieving error conditions
#include <sys/time.h>        // time types (timeval, itimerval )
#include <time.h>            // variable types for manipulating date and time (size_t,clock_t)

#define ICMP_HDRLEN 8

// Checksum function - doesn't change
unsigned short calculate_checksum(unsigned short * paddress, int len) {

	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}
	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits
	return answer;
}

int main () {
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is a Ping ^_^ \n";
    int datalen = strlen(data) + 1;

    //****************************************
    //              ICMP HEADER
    //****************************************
    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum  *** Remove IP4_HDRLEN ***
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

    
    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr("129.134.31.12"); // Change for DNS address of Facebook

     // Create raw socket for IP-RAW (make IP-header by yourself) - IPPROTO_RAW --> IPPROTO_ICMP
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    struct timespec start, end;
    // Get current time (always increasing) of CLOCK and store it in start - use for RRT
    clock_gettime(CLOCK_MONOTONIC, &start); 

    //Send the ICMP_HDRLEN and the data (in bytes) of the packet to peer to the destination address socket,
    //return the number of sent or -1 if error
    if (sendto (sock, packet, ICMP_HDRLEN+datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1) {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    // Read the ICMP_HDRLEN + data into packet through sock, if the dest address is null, 
    // fill it with the sender's address and store it's size in it, return the number of bytes read or -1 if error
    if (recvfrom (sock, &packet, ICMP_HDRLEN+datalen , 0, NULL, (socklen_t*)sizeof (struct sockaddr)) < 0)  {
        fprintf (stderr, "recvfrom() failed with error: %d", errno);
        return -1; 
    }
        else {
        clock_gettime(CLOCK_MONOTONIC, &end);
        uint64_t nano_starting_time = start.tv_nsec;
        uint64_t nano_ending_time = end.tv_nsec;
        double micro_seconds = (nano_ending_time - nano_starting_time) / 1000;     // convert nano --> micro
        double milli_seconds = (nano_ending_time - nano_starting_time) / 1000000;  // convert nano --> milli
        
        inet_pton(AF_INET, "129.134.31.12", &(dest_in.sin_addr));
        inet_ntop(AF_INET, &(dest_in.sin_addr), data, INET_ADDRSTRLEN);

        printf("%s\n", data); 
        printf(" >> Reply ping from %s  with RTT: %1.3f millis.  / %1.3f micros.\n ", data, milli_seconds, micro_seconds);

    }
    close(sock);
    return 0;
    
}

