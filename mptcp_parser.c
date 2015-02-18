/* main source file for the program
 *
 * author: Jahanzeb Maqbool
 * email : jahanzeb.maqbool@seecs.edu.pk
 *
 * see THIRPARTYLICENCES file for all the relevant license information.
 *
*/


/* How to compile/run ?
 *
 * compile: g++ -Wall -o mptcp_parser -D__STDC_FORMAT_MACROS mptcp_parser.c -lpcap
 * run: ./mptcp_parser input.pcap
*/


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <vector>
#include <iostream>

/* The header file for this .c file 
 * includes all the data structures and utility methods.
*/
#include "mymptcp.h"

/* just for debugging purpose... 
 * prints (debug only) will be displayed if turned on.
 * this has nothing to do with program's final output (if succesful).
*/
#define _DEBUG 0

/* global counters 
 * used for keeping the track of packet, connection and subflow
 * related information
 */
static long total_payload = 0;
//int tcp_conns = 0;
static int tcp_pcount = 0;
static int total_pcount = 0;
static int mptcp_conn_count = 0;
static int total_subflow_count = 0;

/* list to keep track of the number of connections */
std::vector<mptcp_conn_ds> conn_list;

/*
 * used to initialize the connection payload counters in connection data structure
 * e.g., per connection payload count or subflow payload count
 */
void initialize_conn_list () {
	
	size_t i;
	for ( i = 0; i < conn_list.size(); i++ ) {
		
		conn_list.at(i).c_payload = 0;
		int j;
		for (j = 0; j < conn_list.at(i).get_subflow_count(); j++) {
			conn_list.at(i).subflow_list.at(j).s_payload = 0;
		}
	}
}


/*
 * MPTCP: Printing functions
 * Utility functions: some  from tcpdump source code.
 *
*/
static int extract_mpjoin(const u_char *opt, u_int len, u_char flags)
{
    struct mp_join *mpj = (struct mp_join *) opt;

    if (!(len == 12 && flags & TH_SYN) &&
        !(len == 16 && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) &&
        !(len == 24 && flags & TH_ACK))
            return 0;

    if (len != 24) {
        if (mpj->sub_b & MP_JOIN_B)
            printf(" backup");
		if (_DEBUG)
			printf(" id %u", mpj->addr_id);
    }

    switch (len) {
        /* SYN packet: extract the token and nonce and add to conn_list */
		case 12: 
			
		
			conn_list.at(mptcp_conn_count-1).s_flow.mpj_syn.token 
				= EXTRACT_32BITS(mpj->u.syn.token);	

			conn_list.at(mptcp_conn_count-1).s_flow.mpj_syn.nonce 
				= EXTRACT_32BITS(mpj->u.syn.nonce);	
			
                //printf(" token 0x%x" " nonce 0x%x",
                //        conn_list.at(mptcp_conn_count-1).s_flow.mpj_syn.token,
                //        conn_list.at(mptcp_conn_count-1).s_flow.mpj_syn.nonce);
                break;
		/* SYN/ACK packet: extract the mac and nonce and add to conn_list */	
        case 16: 
		
			conn_list.at(mptcp_conn_count-1).s_flow.mpj_synack.mac 
				= EXTRACT_64BITS(mpj->u.synack.mac);	
			conn_list.at(mptcp_conn_count-1).s_flow.mpj_synack.nonce 
				= EXTRACT_32BITS(mpj->u.synack.nonce);	
				
               // printf(" hmac 0x%" PRIx64 " nonce 0x%x",
               //         conn_list.at(mptcp_conn_count-1).s_flow.mpj_synack.mac,
               //         conn_list.at(mptcp_conn_count-1).s_flow.mpj_synack.nonce);
                break;
        
		/* ACK packet: extract the hmac and add to conn_list */
		case 24: 
           size_t i;
           if (_DEBUG)
			printf(" hmac 0x");    
			for (i = 0; i < sizeof(mpj->u.ack.mac); i++) {
				conn_list.at(mptcp_conn_count-1).s_flow.mpj_ack.mac [i] = mpj->u.ack.mac[i];	
				if (_DEBUG)
					printf("%02x", conn_list.at(mptcp_conn_count-1).s_flow.mpj_ack.mac [i]);
		
			}				
		
		/* this means a subflow has been established
		 * set subflow payload to zero;
		 * conn_ds[mptcp_conn_count-1].s_flow.s_payload = 0;
		*/		
		
		// increment the packet count for this subflow
		//conn_list.at(mptcp_conn_count-1).s_flow.s_pcount = 3; //ack is the 3rd packet
		conn_list.at(mptcp_conn_count-1).add_subflow ();
		total_subflow_count ++;
	
       default:
          break;
    }
	   
	if (_DEBUG)
	printf ("\n\n");
	
       return 1;
}

// PRIx64 works with g++ only if you include -D__STDC_FORMAT_MACROS in your compile like;
// $ g++ -o objectfile -D__STDC_FORMAT_MACROS source.c
void extract_mpcapable (const u_char *mptcp, u_int offset, u_char flags) {

	struct mp_capable *mpc = (struct mp_capable *) mptcp;
	
	/* create a new instance of mptcp_conn_ds, 
	 * initialize the payload counter, fill it and push to conn_list  
	 */
	
	mptcp_conn_ds conn_ds;
	conn_ds.c_payload = 0;
	conn_ds.s_flow.s_pcount = 0;
	
	
	
	// fill the conn_ds for the final result output
	conn_ds.sender_key = EXTRACT_64BITS(mpc->sender_key);
	conn_ds.receiver_key = EXTRACT_64BITS(mpc->receiver_key);
	
	if(_DEBUG)
	{	
	   printf("   [MPTCP_CONN #: %d]\n", mptcp_conn_count);
	   
	   printf("   SENDER_KEY %#" PRIx64
            " \n   RECEIVER_KEY %#" PRIx64
            "\n",
			conn_ds.sender_key,
			conn_ds.receiver_key
			
			);
		printf ("\n\n");
	}
	// finally, add to the list
	conn_list.push_back (conn_ds);
	
	
}

void process_mptcp_opt (const u_char *mptcp, u_int8_t length, u_char flags, long payload_bytes) {
		
	struct mptcp_option *mptcp_opt;
	u_int subtype;
	
	mptcp_opt = (struct mptcp_option *) mptcp;
	length = mptcp_opt->len;
	subtype = ((mptcp_opt->sub_etc) >> 4) & 0xF;
	
	switch (subtype) {
		case MP_CAPABLE:
			/*
			* 1) if MP_CAPABLE && length == 12 // SYN or SYN+ACK packet
			* 2) if MP_CAPABLE && length == 20 // 3rd ACK packet
			* - 3rd ack packet contains both sender and receiver's key,
			* so its better to capture the statistics at that point.
			*/			
			if (length == 20) {
				++mptcp_conn_count;
				extract_mpcapable (mptcp, length, flags);
				
			}
			break;
		case MP_JOIN:
			if(_DEBUG)
				printf ("MP_JOIN option, length:%d\n", length);
			/*
			 * 1) if MP_JOIN && length == 12 => SYN packet; contains
			 *    receiver's 32bit token and sender nonce (32bit)
			 * 2) if MP_JOIN && length == 16 => SYN/ACK packet; contains
			 *    sender's truncated HMAC (64-bit) and sender's nonce (32-bit).
			 * 3) if MP_JOIN && length == 23 => 3rd ACK packet. subfow established.
			 *    this contains 160-bit sender's HMAC.
			 */
			 
			//if (length == 12)	
				//parse_mymptcp_mpjoin (mptcp, length, flags);
			extract_mpjoin (mptcp, length, flags);
			
			break;	
		case DSS:
			//if(_DEBUG)
				//printf ("DSS option\n");	
				// this is the payload
				//payload_bytes
				
				/*
				 * if DSS and no subflow has been added (only connection is established)
				 * then add the payload to the connection payload.
				 * otherwise add payload to the corresponding subflow of this connection.
				*/
				
			/* 	if (payload_bytes > 0) {
					if (conn_ds[mptcp_conn_count-1].get_subflow_count() > 0) {
						//printf ("conn index %d \n",mptcp_conn_count-1);
						conn_ds[mptcp_conn_count-1].subflow_list
							.at(conn_ds[mptcp_conn_count-1].get_subflow_count() - 1)
							.s_payload 
							+= payload_bytes;
						
						// also add subflow bytes to corresponding connection bytes
					//	conn_ds[mptcp_conn_count-1].c_payload += payload_bytes;
						
					}
					//else {
						conn_ds[mptcp_conn_count-1].c_payload += payload_bytes;					
					//}
				} */
			break;
		case ADD_ADDR: 	
			break;
		case REMOVE_ADDR: 
			if(_DEBUG)
				printf ("REMOVE_ADDR option\n");
			break;
		case MP_PRIO: 
			if(_DEBUG)
				printf ("MP_PRIO option\n");
			break;
		case MP_FAIL: 
			if(_DEBUG)
				printf ("MP_FAIL option\n");
			break;
		case MP_FASTCLOSE:
			if(_DEBUG)
				printf ("MP_FASTCLOSE option\n"); 
			break;
		default:
			if(_DEBUG)
				printf ("Invalid mptcp subtype\n"); 
			
	}

	//adding the payload bytes to the stats data structure (connections and per-con subflow)
	if (payload_bytes > 0) {
		if (conn_list.at(mptcp_conn_count-1).get_subflow_count() > 0) {
				conn_list.at(mptcp_conn_count-1).subflow_list
				.at(conn_list.at(mptcp_conn_count-1).get_subflow_count() - 1)
				.s_payload 
				+= payload_bytes;
					
			// also add subflow bytes to corresponding connection bytes
			//	conn_ds[mptcp_conn_count-1].c_payload += payload_bytes;
		}
		conn_list.at(mptcp_conn_count-1).c_payload += payload_bytes;					
	}
	
	/* No. of packets in each subflow are counted after the subflow has been established (after handshake)
	 * This means, handshake packets are not counted...
	 */
	 
	if(conn_list.size() > 0) {
		if (conn_list.at(mptcp_conn_count-1).get_subflow_count() > 0) {
				conn_list.at(mptcp_conn_count-1).subflow_list
				.at(conn_list.at(mptcp_conn_count-1).get_subflow_count() - 1)
				.s_pcount++; 
		}
	}
	
}


/* process each individual packet */
void process_packet (struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct header_ethernet *ethernet;  /* The ethernet header [1] */
	const struct header_ip *ip;              /* The IP header */
	const struct header_tcp *tcp;            /* The TCP header */
	//const struct tcphdr *tcp; 
	//const char *payload;                   /* Packet payload */
	//struct mptcp_option *mpt_opt;			 /* MPTCP option struct */
	
	// tcp option offset pointer
	const u_char *tcp_opt;
	register u_int tcp_opt_offset;
	int size_ip;
	int size_tcp;
	long size_payload;
	
	
	// option size; as total size of tcp header (without option) = 20bytes
	// so size_tcp in our packet minus 20 should be option size.
	register u_int size_toption;
	
	total_pcount++;
	
	/* define ethernet header */
	ethernet = (struct header_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct header_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		if(_DEBUG)
		printf("   [Packet: %d] Skipping* Invalid IP header length: %u bytes\n", total_pcount, size_ip);
		return;
	}

	/* only interested in TCP packets */
	if (!ip->ip_p == IPPROTO_TCP) 
		return;
		
	/*
  	 *  OK, this packet is TCP.
     */
	tcp_pcount++;
	if(_DEBUG) {
		printf("\n\nPacket number %d:\n", tcp_pcount);
		printf("   From: %s\n", inet_ntoa(ip->ip_src));
		printf("   To: %s\n", inet_ntoa(ip->ip_dst));
	}
	
	/* define/compute tcp header offset */
	tcp = (struct header_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	register u_char flags = tcp->th_flags;
	/* 
	* calculating the option size in packet. Also set the pointer
	* to the start of option field to extract the data.
	*/
	size_toption = size_tcp - sizeof (*tcp);
	tcp_opt_offset = SIZE_ETHERNET + size_ip + size_tcp - size_toption;	
	tcp_opt = (const u_char *)(packet + tcp_opt_offset);
	
	
	/* define/compute tcp payload (segment) offset */
	//payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	//payload = (const char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);	
	
	if (size_payload > 0) {
		if(_DEBUG)
			printf("\n   Payload (%ld bytes):\n", size_payload);
		
		total_payload += size_payload;
		//print_payload(payload, size_payload);
	}
	
	register u_int opt;
	register u_int i;

	//i = tcp_opt_offset;
	//while (i < (tcp_opt_offset+size_toption)) {
	//register u_int len;
	for (i = tcp_opt_offset; i < tcp_opt_offset+size_toption; i++) {
		opt = *tcp_opt++;
		if (opt == TCPOPT_MPTCP) 
		{	
			if(_DEBUG)
				printf("(MPTCP:%d), (MPTCP_OPT:%d) , offset : %d, tcp_off: %d\n",opt, *(tcp_opt-1), i, tcp_opt_offset);
			
			process_mptcp_opt(tcp_opt-1, opt, flags, size_payload);
			break;
		}	
		
	//	i++;
	}
	
	
	
	if(_DEBUG) {
		printf("   option offset: %d\n", tcp_opt_offset);	
		printf("   Option Size: %d\n", size_toption);	
		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	}
	
 
	if(_DEBUG) {
		unsigned char tcp_flags = (unsigned char) tcp->th_flags;
		printf("   Flags (%u): ", tcp_flags);
	}

return;
}



/* Detailed printing for connection and all subflow related data. */

void print_details () {
	
	long con_payload = 0;
	size_t c;
	for (c = 0; c < conn_list.size(); c++ ) {
	
		// get the connection from the list....
		mptcp_conn_ds conn = conn_list.at(c);
		
		printf("   [MPTCP_CONN #: %zu]\n", c+1);
		printf("   Payload bytes (bytes in flight): %ld\n",conn.c_payload); 
		printf("   Sender Key: %#" PRIx64
			 "\n   Receiver Key: %#" PRIx64
			 "\n",
			 conn.sender_key,
			 conn.receiver_key
		);
		printf("   Subflow count: %d\n\n",conn.get_subflow_count());
		
		printf("   Printing Subflow Level Data...\n\n");

		int flow;
		for( flow = 0; flow < conn.get_subflow_count(); flow++) {
			
			printf("      Subflow #: %d\n", flow+1);
			printf("      SYN packet data...\n");
			printf("         Token: 0x%x\n         Nonce: 0x%x\n",
					conn.subflow_list.at(flow).mpj_syn.token,
					conn.subflow_list.at(flow).mpj_syn.nonce);
					
			printf("      SYN/ACK packet data...\n");
			printf("         Hmac (64-bit trunc): 0x%" PRIx64 "\n         Nonce: 0x%x",
                        conn.subflow_list.at(flow).mpj_synack.mac,
                        conn.subflow_list.at(flow).mpj_synack.nonce);		
			printf("\n");		
					
			printf("      ACK packet data...\n");
			size_t i;
			printf("         Hmac (160-bit): 0x");
			for (i = 0; i < sizeof(conn.subflow_list.at(flow).mpj_ack.mac); i++) {
				printf("%02x", conn.s_flow.mpj_ack.mac [i]);
			}
			printf("\n\n");		

			printf("      Number of Packets in this subflow: %d\n", conn.subflow_list.at(flow).s_pcount); 
			printf("      subflow payload bytes (bytes in flight): %ld\n", conn.subflow_list.at(flow).s_payload); 
			
			printf("\n\n");		

		}
		con_payload += 	conn.c_payload;	
		
		printf("   +------------------------------------------------------------+\n");
	
	}
	printf("   Total MPTCP Payload (for all mptcp connections): %ld bytes\n\n", con_payload);	

}


/* main method */

int main (int argc, char **argv) 
{
	pcap_t *handle;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	
	
	/* Skip over the program name. */
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 1 )
		{
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
		}

	handle = pcap_open_offline(argv[0], errbuf);
	if (handle == NULL)
		{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
		}
	
	// set the counters to zero.
	initialize_conn_list ();
	
	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
	while ((packet = pcap_next(handle, &header)) != NULL)
	//int i;
	//for (i = 0; i < 5; i++) 
	{
	//	packet = pcap_next(handle, &header);
		if (packet == NULL) exit (1);
			process_packet (&header, packet);
	}
	
	
	printf ("\n\n Printing stats summary...\n\n");		
	printf("   Total Packets (%d)\n", total_pcount);
	printf("   Total TCP Packets (%d)\n", tcp_pcount);
	printf("   Total TCP Payload (%ld bytes)\n", (total_payload));
	printf("   Total # MPTCP connections (%d)\n", mptcp_conn_count);
	printf("   Total # Subflows (%d)\n", total_subflow_count);
	
	size_t i;
	for (i = 0; i < conn_list.size(); i++) { //temporarily 4 connections, make it generic
		printf("   Connection (%zu) has %d subflow(s) \n", i+1, conn_list.at(i).get_subflow_count());
	}
	
	printf("\n");
	/* finally print all the details from conn_list */
	
	printf (" \n\nPrinting all connection data summary...\n\n");	
	print_details ();
	




	/* clean up */
	pcap_close(handle);

	// terminate
	return 0;
}












