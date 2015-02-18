/* header file containg all the necessary datastructures 
 * and some utility methods.
 *
 * author: Jahanzeb Maqbool
 * email : jahanzeb.maqbool@seecs.edu.pk
 *
 * see THIRPARTYLICENCES file for all the relevant license information.
 *
*/


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define max( a, b ) ( ((a) > (b)) ? (a) : (b) )
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )

//* MPTCP options identifier */
#define TCPOPT_MPTCP	 0x1E
/*
 * MPTCP header code - From tcpdump-mptcp
 */
#define MP_CAPABLE       0x0
#define MP_JOIN          0x1
#define DSS              0x2
#define ADD_ADDR         0x3
#define REMOVE_ADDR      0x4
#define MP_PRIO          0x5
#define MP_FAIL          0x6
#define MP_FASTCLOSE     0x7


/* data structure to keep per connection subflow data */
struct mptcp_conn_ds {
    u_int64_t	sender_key;
	u_int64_t	receiver_key;
		
	struct mptcp_subflow{					
		struct {
			u_int32_t	token;
			u_int32_t	nonce;			
		} mpj_syn;
		
		struct {
			u_int32_t	nonce;
			u_int64_t	mac;
		} mpj_synack;
		
		struct {
			u_int8_t	mac[20];
		} mpj_ack;
		
		//total number of subflows in this connection			
		u_int8_t        subflow_count; 
		
		// subflow paylaod bytes
		long s_payload;
		
		// subflow packet count
		int s_pcount;
		
	}s_flow;
	
	std::vector<mptcp_subflow> subflow_list;
	// connection payload bytes
	long c_payload;
	
	void add_subflow () {
		subflow_list.push_back (s_flow);
	
	}
	int get_subflow_count () {
		return subflow_list.size();
	}
};



/* REF: tcpdum ->"extract.h" - COPYRIGHT LICENSE (see THIRPARTY_LICENCES) */
static inline u_int16_t
EXTRACT_16BITS(const void *p)
{
	return ((u_int16_t)ntohs(*(const u_int16_t *)(p)));
}

static inline u_int32_t
EXTRACT_32BITS(const void *p)
{
	return ((u_int32_t)ntohl(*(const u_int32_t *)(p)));
}
static inline u_int64_t
EXTRACT_64BITS(const void *p)
{
	return ((u_int64_t)(((u_int64_t)ntohl(*((const u_int32_t *)(p) + 0))) << 32 | \
		((u_int64_t)ntohl(*((const u_int32_t *)(p) + 1))) << 0));

}

/* Ethernet header */
struct header_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct header_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

    /* TCP header */
struct header_tcp {
        u_short th_sport;   /* source port */
        u_short th_dport;   /* destination port */
        u_int32_t th_seq;       /* sequence number */
        u_int32_t th_ack;       /* acknowledgement number */

        u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;     /* window */
        u_short th_sum;     /* checksum */
        u_short th_urp;     /* urgent pointer */
};


struct mptcp_option {
        u_int8_t        kind;
        u_int8_t        len;
        u_int8_t        sub_etc;        /* subtype upper 4 bits, other stuff lower 4 bits */
};
struct mp_capable {
        u_int8_t        kind;
        u_int8_t        len;
        u_int8_t        sub_ver;
        u_int8_t        flags;
        u_int8_t        sender_key[8];
        u_int8_t        receiver_key[8];	
};

struct mp_join {
        u_int8_t  kind;
        u_int8_t  len;
        u_int8_t  sub_b;
        u_int8_t  addr_id;
        union {
                struct {
                        u_int8_t  token[4];
                        u_int8_t  nonce[4];
                } syn;
                struct {
                        u_int8_t  mac[8];
                        u_int8_t  nonce[4];
                } synack;
                struct {
                        u_int8_t  mac[20];
                } ack;
        } u;
};
#define MP_JOIN_B                       0x01

