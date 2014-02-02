//Sniffer functions

#ifdef WIN32

#include <winsock2.h>         // For socket(), connect(), send(), and recv()
#include <ws2tcpip.h>     // beinhaltet spezifische Information f�r Winsock2 wzB. IP_HDRINCL

#else

#include <string.h>
#include <stdlib.h> 
#include <sys/types.h>       // For data types
#include <sys/socket.h>      // For socket(), connect(), send(), and recv()
#include <netdb.h>           // For gethostbyname()
#include <arpa/inet.h>       // For inet_addr()
#include <unistd.h>          // For close()
#include <netinet/in.h>      // For sockaddr_in
#include <sys/ioctl.h>		//for SIOCGIFINDEX, ioctl()
#include <net/if.h>		//for IFNAMSIZ, IFF_PROMISC
#include <net/if_arp.h>		//for ARPHRD_ARCNET, ARPHRD_ETHER
#include <signal.h>		//for SIGINT
#include <linux/if_ether.h>	//for ETH_P_ALL
#include <linux/if_packet.h>	// For sockaddr_ll
#include <stdlib.h>	       // For malloc(), free(), exit(), atoi()
#include <pthread.h>         // For POSIX threads

#endif

//Sockets programming based on http://www.delikon.de/

#define MAX_HOSTNAME_LAN 255
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
//#define MAX_ADDR_LEN 16
//length of each row shown in hex
#define length_hex 30

#define HOSTNAME_LEN 1024
#define PAKSIZE 65536
#define MAX_COMMAND_SIZE 65536

//number of concurrent simultaneous connections allowed
#define TRANSACTION_PACKET_SIZE 256

/* G L O B A L S */
#ifdef WIN32
SOCKET sock;
SOCKADDR_IN saSource, saDest;
typedef int socklen_t;
typedef char raw_type;       // Type used for raw data on this platform
#else
#define INVALID_SOCKET 0
#define SOCKET_ERROR -1
int sock;
sockaddr_in saSource, saDest;
typedef void raw_type;       // Type used for raw data on this platform
#endif


int lentcp=0, lenudp;
//the pointer , which shows us the payload begin
unsigned char *datatcp=NULL;
//the pointer , which shows us the payload begin
unsigned char *dataudp=NULL;
struct udphdr *pUdpheader;

struct ipheader *pIpheader;
struct tcpheader *pTcpheader;
char szSourceIP[16], szDestIP[16];
int aux;
int pos;

//Session data
struct split_packet *first_split_packet=NULL;
struct split_packet *current_split_packet=NULL;

/*
struct sockaddr_ll
{
  unsigned short  sll_family;
  unsigned short  sll_protocol;
  int             sll_ifindex;
  unsigned short  sll_hatype;
  unsigned char   sll_pkttype;
  unsigned char   sll_halen;
  unsigned char   sll_addr[8];
};
*/

typedef struct RecvBufSplit_packet
{
  char * RecvBufSplit;
  struct RecvBufSplit_packet * next;
}
BUF_SPLIT;

typedef struct split_packet
{
  unsigned char ip[16];
  unsigned int port;
  int dummy_char_count;
  char * RecvBufSplit;
  //	struct RecvBufSplit_packet * RecvBufSplit_pkt;
  struct split_packet * previous;
  struct split_packet * next;
}
SPLT_PKT;

typedef struct transaction_packet
{
  unsigned char client_ip[16];
  unsigned short int client_port;
  unsigned char server_ip[16];
  unsigned short int server_port;
  int client_XID;
  int server_XID;
  char end_transaction;
}
TRANS_PKT;

typedef struct session
{
  unsigned char username[31];
  unsigned char terminal[31];
  unsigned char program[31];
  unsigned char sid[4];
  unsigned char serial[6];
  unsigned char dbname[31];
  unsigned char starttime[41];
  unsigned char client_ip[16];
  unsigned short int client_port;
  unsigned char server_ip[16];
  unsigned short int server_port;
}
SESS;



typedef struct tcpheader
{
  unsigned short int sport;		/* source port */

  unsigned short int dport;   /* destination port */

  unsigned int th_seq;        /* sequence number */

  unsigned int th_ack;        /* acknowledgement number */

unsigned char th_x2:4;      /* data offset, rsvd */

#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
unsigned char th_off:4;
#define	TH_FIN	0x01	//Final. The connection should be closed, the peer is supposed to answer with one last segment with the FIN flag set as well.
#define	TH_SYN	0x02	//Synchronization. A segment with the SYN flag set indicates that client wants to initiate a new connection to the destination port.
#define	TH_RST	0x04	//Reset. Tells the peer that the connection has been terminated.
#define	TH_PUSH	0x08	//Push. The systems IP stack will not buffer the segment and forward it to the application immediately (mostly used with telnet).
#define	TH_ACK	0x10	//Acknowledgement. Used to acknowledge data and in the second and third stage of a TCP connection initiation (see IV.).
#define	TH_URG	0x20	//Urgent. Segment will be routed faster, used for termination of a connection or to stop processes (using telnet protocol).
#define TH_ECNECHO	0x40	/* ECN Echo */
#define TH_CWR		0x80	/* ECN Cwnd Reduced */

  unsigned char Flags;
  unsigned short int th_win;	/* window */

  unsigned short int th_sum;  /* checksum */

  unsigned short int th_urp;  /* urgent pointer */

}
TCP_HDR;


#define	TCPOPT_EOL		0
#define	TCPOPT_NOP		1
#define	TCPOPT_MAXSEG		2
#define    TCPOLEN_MAXSEG		4
#define	TCPOPT_WSCALE		3	/* window scale factor (rfc1323) */
#define	TCPOPT_SACKOK		4	/* selective ack ok (rfc2018) */
#define	TCPOPT_SACK		5	/* selective ack (rfc2018) */
#define	TCPOPT_ECHO		6	/* echo (rfc1072) */
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#define TCPOPT_TIMESTAMP	8	/* timestamp (rfc1323) */
#define    TCPOLEN_TIMESTAMP		10
#define    TCPOLEN_TSTAMP_APPA		(TCPOLEN_TIMESTAMP+2) /* appendix A */
#define TCPOPT_CC		11	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW		12	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO		13	/* T/TCP CC options (rfc1644) */
#define TCPOPT_SIGNATURE	19	/* Keyed MD5 (rfc2385) */
#define    TCPOLEN_SIGNATURE		18

#define TCP_SIGLEN 16			/* length of an option 19 digest */

#define TCPOPT_TSTAMP_HDR	\
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)


struct ipheader
{
unsigned char ip_hl:4, ip_v:4; /* this means that each member is 4 bits */
  unsigned char ip_tos;					/* type of service */

  unsigned short int ip_len;    /* total length */

  unsigned short int ip_id;     /* identification */

  unsigned short int ip_off;    /* fragment offset field */

#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
  unsigned char ip_ttl;					/* time to live */

  unsigned char ip_p;         /* protocol */

  unsigned short int ip_sum;  	/* checksum */

  unsigned int ip_src;				/* source address */

  unsigned int ip_dst;				/* dest address */

}
; /* total ip header length: 20 bytes (=160 bits) */


// Psuedo Header

typedef struct ps_hdr
{
  unsigned int   source_address;   // Source Address		 =>	  4 Bytes
  unsigned int   dest_address;     // Destination Address	 =>	  4 Bytes
  unsigned char  placeholder;	     // Place Holder		 =>	  1 Bytes
  unsigned char  protocol;	     // Protocol		 =>	  1 Bytes
  unsigned short tcp_length;	     // TCP Length		 =>    +  2 Bytes
  //				       = 12 Bytes
  struct tcpheader tcp;

}
PS_HDR;

typedef struct udphdr
{
  unsigned short sport;      	/* source port */

  unsigned short dport;       /* destination port */

  unsigned short len;         /* udp length */

  unsigned short cksum;       /* udp checksum */

}
UDP_HDR;

struct session sess_data;


#ifndef WIN32
void sigint_sniffer(int signum);
#endif
int session_values_Oracle(unsigned char *datatcp,int lentcp,SESS *sess_data, char client_ip[],unsigned short int client_port,char server_ip[], unsigned short int server_port, char * timestamp);
void print_header(char *timestamp);
void my_printf(FILE *stream,char *pointer);
void process_pak(void);
void option_sniffer(void);
int process_packet(struct transaction_packet *trans_packet,char *RecvBufSplit,char * timestamp);//Processes the packet looking for the start of sessions, end of sessions and SQL commands. Returns the command type
void init_net(void);
void read_packets(void);
int is_oracle_packet(char *RecvBuf,  struct transaction_packet *trans_packet);// Listens the socket and returns an Oracle packet
unsigned short checksum(unsigned short *buffer, int size);
int kill_session(void);
int Send_RST(unsigned int server_IP, unsigned short int server_port, unsigned int client_IP, unsigned short int client_port, unsigned int tcp_sequence_number);

struct split_packet * AddItem(struct split_packet * split_paket_pointer,unsigned char *ip,unsigned int port,int dummy_char_count);
struct split_packet * RemoveItem(struct split_packet * split_paket_pointer);
struct split_packet * FindItem(struct split_packet * split_paket_pointer,unsigned char ip[16],unsigned int port);

//packet_type types
#define NO_PACKET_TYPE -1
#define COMMAND_TYPE 0
#define END_SESSION_TYPE 1
#define START_SESSION_TYPE 2


int Thin_Client=0;

char before_recv_timestamp[32];
char after_recv_timestamp[32];
char delta_recv_timestamp[32];
char delta_process_timestamp[32];

void option_sniffer()
{
  char debug_file_name[256]="";
  char auditory_file_name[256]="";
  char session_file_name[256]="";
  char delay_debug_file_name[256]="";
  char file_name_remove[256]="";
  char file_extension[32]="";
  int count_file_name;
  int count_file_name_back;

  count_file_name=count_file_radical("auditory", ".txt");
  count_file_name_back=count_file_radical("session", ".txt");
  if(count_file_name<count_file_name_back)
  {
    count_file_name=count_file_name_back;
  }
  count_file_name_back=count_file_radical("delay_debug", ".txt");
  if(count_file_name<count_file_name_back)
  {
    count_file_name=count_file_name_back;
  }

  if (SAVE_DEBUG=='y')
  {
    count_file_name_back=count_file_radical("debug", ".txt");
    if(count_file_name<count_file_name_back)
    {
      count_file_name=count_file_name_back;
    }
    count_file_name++;

    //verify if the file already exists
    //in that case change the name of the file adding an increasing radical
    strcpy(debug_file_name,"debug");
    strcpy(file_extension,".txt");
    file_radical(debug_file_name, file_extension,count_file_name);

    // Open for write (will fail if file "debug.txt" does not exist)
    if( (debug_file  = fopen( debug_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",debug_file_name);
    else
      printf( "The file '%s' was opened\n",debug_file_name);
  }
   else
   count_file_name++;

  // Open for write (will fail if file "auditory.txt" does not exist)
  strcpy(auditory_file_name,"auditory");
  strcpy(file_extension,".txt");
  file_radical(auditory_file_name, file_extension,count_file_name);
  if( (audit_file  = fopen( auditory_file_name, "w+" )) == NULL )
    printf( "The file '%s' was not opened\n",auditory_file_name);
  else
    printf( "The file '%s' was opened\n",auditory_file_name);

  // Open for write (will fail if file "session.txt" does not exist)
  strcpy(session_file_name,"session");
  strcpy(file_extension,".txt");
  file_radical(session_file_name, file_extension,count_file_name);
  if( (session_file  = fopen( session_file_name, "w+" )) == NULL )
    printf( "The file '%s' was not opened\n",session_file_name);
  else
    printf( "The file '%s' was opened\n",session_file_name);

  // Open for write (will fail if file "delay_debug.txt" does not exist)
  strcpy(delay_debug_file_name,"delay_debug");
  strcpy(file_extension,".txt");
  file_radical(delay_debug_file_name, file_extension,count_file_name);
  if( (delay_debug_file  = fopen( delay_debug_file_name, "w+" )) == NULL )
    printf( "The file '%s' was not opened\n",delay_debug_file_name);
  else
    printf( "The file '%s' was opened\n",delay_debug_file_name);

  fflush(stdout);
  read_packets();

  if (SAVE_DEBUG=='y')
  {
    fflush(debug_file);
  }
  fflush(audit_file);
  fflush(session_file);

  if (SAVE_DEBUG=='y')
  {
    /* Close debug_file */
    if( fclose( debug_file ) )
    {
      printf("The file '%s' was not closed\n",debug_file_name);
    }
    else
    {
      printf("The file '%s' was closed\n",debug_file_name);
    }
  }
  /* Close audit_file */
  if( fclose( audit_file ) )
  {
    printf("The file '%s' was not closed\n",auditory_file_name);
  }
  else
  {
    printf("The file '%s' was closed\n",auditory_file_name);
  }
  /* Close session_file */
  if( fclose( session_file ) )
  {
    printf("The file '%s' was not closed\n",session_file_name);
  }
  else
  {
    printf("The file '%s' was closed\n",session_file_name);
  }

  /* Close delay_debug_file */
  if( fclose( delay_debug_file ) )
  {
    printf("The file '%s' was not closed\n",delay_debug_file_name);
  }
  else
  {
    printf("The file '%s' was closed\n",delay_debug_file_name);
  }
}

void read_packets()
{
  struct transaction_packet *trans_packet;
  int new_packet;
  char RecvBuf[PAKSIZE] = {0};
  char RecvBufSplit[PAKSIZE] = {0};
  int packet_type;
  int i;
  char timestamp[32];
  int pCount=0;

  trans_packet = (struct transaction_packet *) calloc (TRANSACTION_PACKET_SIZE,sizeof(struct transaction_packet));

  sess_data.username[0]=(unsigned char)0;
  sess_data.terminal[0]=(unsigned char)0;
  sess_data.program[0]=(unsigned char)0;
  sess_data.sid[0]=(unsigned char)0;
  sess_data.serial[0]=(unsigned char)0;
  sess_data.client_ip[0]=(unsigned char)0;
  sess_data.client_port=0;
  sess_data.server_ip[0]=(unsigned char)0;
  sess_data.server_port=0;
  sess_data.dbname[0]=(unsigned char)0;
  sess_data.starttime[0]=(unsigned char)0;

  get_timestamp(before_recv_timestamp);
  get_timestamp(after_recv_timestamp);
  fprintf(delay_debug_file,"delta_process_timestamp delta_recv_timestamp\n\n");

  // open raw socket, set promiscuous mode
  init_net();
#ifndef WIN32
  signal(SIGINT, sigint_sniffer);
#endif

  while(1)
  {
    new_packet=is_oracle_packet(RecvBuf,trans_packet); // Listens the socket and returns an Oracle packet
    if (new_packet==1)
    {
      pCount++;
      packet_type=process_packet(trans_packet,RecvBufSplit,timestamp);//Processes the packet looking for the start of sessions, end of sessions and SQL commands. Returns the command type
      //      if (packet_type!=NO_PACKET_TYPE)
      {
        if (SAVE_DEBUG=='y')
        {
          //In debug file write the TPC header info
          fprintf(debug_file,"*******************************************\n");
          fprintf(debug_file,"-TCP-");
          fprintf(debug_file,"\nStart address->%s\n",szSourceIP);
          fprintf(debug_file,"Start port->%i\n",ntohs(pTcpheader->sport));
          fprintf(debug_file,"Destination address->%s\n",szDestIP);
          fprintf(debug_file,"Destination port->%i\n",ntohs(pTcpheader->dport));
          fprintf(debug_file,"th_ack->%u\n",htonl(pTcpheader->th_ack));
          fprintf(debug_file,"Sequence number->%u\n",htonl(pTcpheader->th_seq));
          fprintf(debug_file,"Flags(TH_CWR|TH_ECNECHO|TH_URG|TH_ACK|TH_PSH|TH_RST|TH_SYN|TH_FIN)->%X\n",pTcpheader->Flags);
          fprintf(debug_file,"datatcp address->%x\n",(unsigned int)datatcp);
          fprintf(debug_file,"size of ipheader->%i\n",sizeof(struct ipheader));
          fprintf(debug_file,"size of tcpheader->%i\n",sizeof(struct tcpheader));
          fprintf(debug_file,"size of the hole packet->%i\n",ntohs(pIpheader->ip_len));
          fprintf(debug_file,"Timstamp->%s\n",timestamp);

          //In debug file write the TPC packet
          fprintf(debug_file,"\nchar Packet%i []=",pCount);
          fprintf(debug_file,"\n\"");
          //Writes the TPC packet in multiples of length_hex (length_hex is defined in DBSniffer.h)
          for (i=0;i<lentcp;i++)
          {

            fprintf(debug_file," %.2x",*(datatcp+i));
            if ((i+1)%length_hex==0 && i>0)
            {
              fprintf(debug_file,"\"");
              fprintf(debug_file," ");

              for (int i2=i-length_hex+1;i2<i+1;i2++)
              {
                if( *(datatcp+i2)<=127&&*(datatcp+i2)>=20)
                {
                  fprintf(debug_file,"%c",*(datatcp+i2));
                }
                else
                {
                  fprintf(debug_file,".");
                }
              }
              fprintf(debug_file,"\n\"");
            }

          }

          //Writes the last line of the TPC packet if needed
          if (i%length_hex!=0)
          {
            fprintf(debug_file,"\"");

            for (int i2=i-length_hex+i%length_hex;i2<i;i2++)
            {
              fprintf(debug_file,"   ");
            }
            fprintf(debug_file," ");
            for (int i2=i-i%length_hex;i2<i;i2++)
            {
              if( *(datatcp+i2)<=127&&*(datatcp+i2)>=20)
              {
                fprintf(debug_file,"%c",*(datatcp+i2));
              }
              else
                fprintf(debug_file,".");
            }
          }
          fprintf(debug_file,"\n");
        }

        if (packet_type==END_SESSION_TYPE)
        {
          if (SAVE_DEBUG=='y')
          {
            fprintf(debug_file,"%s\n",start_session);
            fprintf(debug_file,"End Session: %s:%i\n",szSourceIP,ntohs(pTcpheader->sport));
            fprintf(debug_file,"Date_Time: %s\n" ,timestamp);
            fprintf(debug_file,"%s\n",end_session);
          }
          fprintf(session_file,"%s\n",start_session);
          fprintf(session_file,"End Session: %s:%i\n",szSourceIP,ntohs(pTcpheader->sport));
          fprintf(session_file,"Date_Time: %s\n" ,timestamp);
          fprintf(session_file,"%s\n",end_session);
        }
        else
        {
          if(packet_type==START_SESSION_TYPE)
          {
            if (SHOW_DISPLAY=='y')
            {
              printf("%s\n",start_session);
              printf("User: %s\n",sess_data.username);
              printf("Terminal: %s\n",sess_data.terminal);
              printf("Program: %s\n",sess_data.program);
              printf("SID: %s\n",sess_data.sid);
              printf("Serial: %s\n",sess_data.serial);
              printf("Client_IP: %s\n",sess_data.client_ip);
              printf("Client_Port: %i\n",ntohs(sess_data.client_port));
              printf("Server_IP: %s\n",sess_data.server_ip);
              printf("Server_Port: %i\n",ntohs(sess_data.server_port));
              printf("DB_Name: %s\n",sess_data.dbname);
              printf("Date_Time: %s\n",sess_data.starttime);
              printf("%s\n",end_session);
            }
            if (SAVE_DEBUG=='y')
            {
              fprintf(debug_file,"%s\n",start_session);
              fprintf(debug_file,"User: %s\n",sess_data.username);
              fprintf(debug_file,"Terminal: %s\n",sess_data.terminal);
              fprintf(debug_file,"Program: %s\n",sess_data.program);
              fprintf(debug_file,"SID: %s\n",sess_data.sid);
              fprintf(debug_file,"Serial: %s\n",sess_data.serial);
              fprintf(debug_file,"Client_IP: %s\n",sess_data.client_ip);
              fprintf(debug_file,"Client_Port: %i\n",ntohs(sess_data.client_port));
              fprintf(debug_file,"Server_IP: %s\n",sess_data.server_ip);
              fprintf(debug_file,"Server_Port: %i\n",ntohs(sess_data.server_port));
              fprintf(debug_file,"DB_Name: %s\n",sess_data.dbname);
              fprintf(debug_file,"Date_Time: %s\n",sess_data.starttime);
              fprintf(debug_file,"%s\n",end_session);
            }
            fprintf(session_file,"%s\n",start_session);
            fprintf(session_file,"User: %s\n",sess_data.username);
            fprintf(session_file,"Terminal: %s\n",sess_data.terminal);
            fprintf(session_file,"Program: %s\n",sess_data.program);
            fprintf(session_file,"SID: %s\n",sess_data.sid);
            fprintf(session_file,"Serial: %s\n",sess_data.serial);
            fprintf(session_file,"Client_IP: %s\n",sess_data.client_ip);
            fprintf(session_file,"Client_Port: %i\n",ntohs(sess_data.client_port));
            fprintf(session_file,"Server_IP: %s\n",sess_data.server_ip);
            fprintf(session_file,"Server_Port: %i\n",ntohs(sess_data.server_port));
            fprintf(session_file,"DB_Name: %s\n",sess_data.dbname);
            fprintf(session_file,"Date_Time: %s\n",sess_data.starttime);
            fprintf(session_file,"%s\n",end_session);
          }
          //packet_type==COMMAND_TYPE
          else
          {
            if(packet_type==COMMAND_TYPE)
            {
              print_header(timestamp);
              if (SHOW_DISPLAY=='y')
              {

                printf("%s",RecvBufSplit);
              }
              if (SAVE_DEBUG=='y')
              {
                fprintf(debug_file,"%s",RecvBufSplit);
              }
              fprintf(audit_file,"%s",RecvBufSplit);
              if (SHOW_DISPLAY=='y')
              {
                printf("\n");
              }
              if (SAVE_DEBUG=='y')
              {
                fprintf(debug_file,"\n");
              }
              fprintf(audit_file,"\n");
            }
          }
        }
        if (SAVE_DEBUG=='y')
        {
          fflush(debug_file);
        }
        fflush(audit_file);
        fflush(session_file);
        fflush(stdout);
      }
    }
  }
}

//Processes the packet looking for the start of sessions, end of sessions and SQL commands. Returns the command type
int process_packet(struct transaction_packet *trans_packet,char *RecvBufSplit, char *timestamp)
{
  int i,j;
  int dummy_char_count;
  int split;
  struct transaction_packet *trans_packet_current;

  get_timestamp(timestamp);
  //If lentcp==0 then it is a tcp control message and may be the end of the connection
  if (lentcp==0)
  {
    //Flags & 0x04 => RST
    //Flags & 0x01 => FIN
    //end of communication socket >= end of Oracle Session
    if (((pTcpheader->Flags & 0x04)==0x04) || ((pTcpheader->Flags & 0x01)==0x01))
    {
      trans_packet_current=trans_packet;
      i=0;
      do
      {
        if ((strcmp((char *)trans_packet_current->client_ip,szSourceIP)==0) && (trans_packet_current->client_port==pTcpheader->sport))
        {
          break;
        }
        i++;
        *trans_packet_current++;
      }
      while (i<TRANSACTION_PACKET_SIZE);
      if (i<TRANSACTION_PACKET_SIZE)
      {
        trans_packet_current->client_ip[0]=0;
        trans_packet_current->client_port='\0';
        trans_packet_current->server_ip[0]=0;
        trans_packet_current->server_port='\0';
        return END_SESSION_TYPE;
      }
    }
  }
  //lentcp!=0
  else
  {
    split=0;
    current_split_packet=FindItem(first_split_packet,(unsigned char *)szSourceIP,pTcpheader->sport);
    //If the current packet is a continuation of another one
    j=0;
    if (current_split_packet!=NULL)
    {
      split=1;
      dummy_char_count=current_split_packet->dummy_char_count;
      if (current_split_packet->RecvBufSplit!=NULL)
      {
        memset(RecvBufSplit, 0, PAKSIZE);
        while ((*(current_split_packet->RecvBufSplit+j)!=0)&& (j<PAKSIZE-1))
        {
          RecvBufSplit[j]=current_split_packet->RecvBufSplit[j];
          j++;
        }
        first_split_packet=RemoveItem(current_split_packet);
      }
      pos=1;
    }
    //It is the start of a fresh packet
    else
    {
      //Search for something important
      pos=-1;
      pos=str_find_unsensitive(datatcp,lentcp,"select");
      aux=str_find_unsensitive(datatcp,lentcp,"insert");
      if (pos==-1)
      {
        pos=aux;
      }
      if (aux<pos && aux!=-1)
      {
        pos=aux;
      }
      aux=str_find_unsensitive(datatcp,lentcp,"delete");
      if (pos==-1)
      {
        pos=aux;
      }
      if (aux<pos && aux!=-1)
      {
        pos=aux;
      }
      aux=str_find_unsensitive(datatcp,lentcp,"update");
      if (pos==-1)
      {
        pos=aux;
      }
      aux=str_find_unsensitive(datatcp,lentcp,"commit");
      if (pos==-1)
      {
        pos=aux;
      }
      if (aux<pos && aux!=-1)
      {
        pos=aux;
      }
      aux=str_find_unsensitive(datatcp,lentcp,"rollback");
      if (pos==-1)
      {
        pos=aux;
      }
      if (aux<pos && aux!=-1)
      {
        pos=aux;
      }
      aux=str_find_unsensitive(datatcp,lentcp,"truncate");
      if (pos==-1)
      {
        pos=aux;
      }
      if (aux<pos && aux!=-1)
      {
        pos=aux;
      }
      aux=str_find_unsensitive(datatcp,lentcp,"declare");
      if (pos==-1)
      {
        pos=aux;
      }
      if (aux<pos && aux!=-1)
      {
        pos=aux;
      }
      aux=str_find_unsensitive(datatcp,lentcp,"begin");
      if (pos==-1)
      {
        pos=aux;
      }
      if (aux<pos && aux!=-1)
      {
        pos=aux;
      }
      dummy_char_count=0;
    }

    //If something important was found
    if (pos!=-1)
    {
      // append the information in the packet to the *RecvBufSplit
      // if split==1 (it is a continuation packet) and there is a 6 in the 5th position then the first 10 chars are to be discarded
      if ((split==1) && (*(datatcp+4)==6))
      {
        pos=pos+10;
      }
      for (i=pos;i<lentcp;i++)
      {
        //The 0x01 in the packet marks the end
        if(*(datatcp+i)!=1)
        {
          //there is a dummy character every 64 characters
          if(Thin_Client==0)
          {
            if (dummy_char_count!=64)
            {
              if (*(datatcp+i)!=0)
              {
                RecvBufSplit[j]=*(datatcp+i);
                j++;
              }
            }
            else
            {
              dummy_char_count=-1;
            }
          }
          else
          {
            if (*(datatcp+i)!=0)
            {
              RecvBufSplit[j]=*(datatcp+i);
              j++;
            }
          }
        }
        else
        {
          break;
        }
        dummy_char_count++;
      }

      if (j>0)
      {
        RecvBufSplit[j]=0;
      }

      //if the information in the packet is to be continued in the following packet
      if( i==lentcp)
      {
        current_split_packet=AddItem(first_split_packet,(unsigned char *)szSourceIP,pTcpheader->sport,dummy_char_count);
        if((current_split_packet -> RecvBufSplit = (char  *) malloc (j+1))==NULL)
        {
          ERROR_MESSAGE("current_split_packet -> RecvBufSplit");
        }

        strcpy((char *)current_split_packet -> RecvBufSplit,(char *)RecvBufSplit);
      }
      //if the information in the packet is complete
      else
      {
        if (j>0)
        {
          return COMMAND_TYPE;
        }
      }//end: If something important was found
    }
    else
    {
      if (session_values_Oracle(datatcp,lentcp,&sess_data,szSourceIP,pTcpheader->sport,szDestIP,pTcpheader->dport,timestamp)==2)
      {

        trans_packet_current=trans_packet;
        i=0;
        do
        {
          if ((strcmp((char *)trans_packet_current->client_ip,szDestIP)==0) && (trans_packet_current->client_port==pTcpheader->dport))
          {
            break;
          }
          i++;
          *trans_packet_current++;
        }
        while (i<TRANSACTION_PACKET_SIZE);
        if (i==TRANSACTION_PACKET_SIZE)
        {
          trans_packet_current=trans_packet;
          i=0;
          do
          {
            if (trans_packet_current->client_ip[0]==0)
            {
              strcpy((char *)trans_packet_current->client_ip,szDestIP);
              trans_packet_current->client_port=pTcpheader->dport;
              strcpy((char *)trans_packet_current->server_ip,szSourceIP);
              trans_packet_current->server_port=pTcpheader->sport;
              trans_packet_current->server_XID=0;
              trans_packet_current->client_XID=0;
              trans_packet_current->end_transaction='n';
              /*
                            if (SHOW_DISPLAY=='y')
                            {
                              printf("XID REGISTO GUARDADO\n");
                            }
                            if (SAVE_DEBUG=='y')
                            {
                              fprintf(debug_file,"XID REGISTO GUARDADO\n");
                            }
                            fprintf(audit_file,"XID REGISTO GUARDADO\n");
              */
              break;
            }
            i++;
            *trans_packet_current++;
          }
          while (i<TRANSACTION_PACKET_SIZE);
        }
        return START_SESSION_TYPE;
      }
      else
      {
        //if the initial of the packet has in position 10 a 8 and in position 11 a 6 then it has the Server XID
        if(*(datatcp+10)==8 && *(datatcp+11)==6 && *(datatcp+39)==0 && lentcp>39)
          //        if(*(datatcp+10)==8 && *(datatcp+11)==6 && *(datatcp+21)==*(datatcp+58) && lentcp>58)
          //        if(*(datatcp+10)==8 && *(datatcp+11)==6  && lentcp>58)
        {
          trans_packet_current=trans_packet;
          i=0;
          do
          {
            if ((strcmp((char *)trans_packet_current->client_ip,szDestIP)==0) && (trans_packet_current->client_port==pTcpheader->dport))
            {
              trans_packet_current->server_XID=*(datatcp+25);
              /*
                            if (SHOW_DISPLAY=='y')
                            {
                              printf("XID Server guardado: %i\n",*(datatcp+25));
                            }
                            if (SAVE_DEBUG=='y')
                            {
                              fprintf(debug_file,"XID Server guardado: %i\n",*(datatcp+25));
                            }
                            fprintf(audit_file,"XID Server guardado: %i\n",*(datatcp+25));
              */
              break;
            }
            i++;
            *trans_packet_current++;
          }
          while (i<TRANSACTION_PACKET_SIZE);
          /*
          #ifdef WIN32
                    print_header(st);
          #else
                    print_header(st,tp);
          #endif
                    if (SHOW_DISPLAY=='y')
                    {
                      printf("XID Server: %i\n",*(datatcp+25));
                    }
                    if (SAVE_DEBUG=='y')
                    {
                      fprintf(debug_file,"XID Server: %i\n",*(datatcp+25));
                    }
                    fprintf(audit_file,"XID Server: %i\n",*(datatcp+25));
          */
        }
        else
        {
          //if the initial of the packet has in position 10 a 0x11 and in position 11 a 0x69 then it has the Client XID
          if(*(datatcp+10)==0x11 && *(datatcp+11)==0x69 && *(datatcp+26)==0x68 && *(datatcp+29)==0 && lentcp>28)
          {
            trans_packet_current=trans_packet;
            i=0;
            do
            {
              if ((strcmp((char *)trans_packet_current->client_ip,szSourceIP)==0) && (trans_packet_current->client_port==pTcpheader->sport))
              {
                trans_packet_current->client_XID=*(datatcp+28);
                if (((trans_packet_current->client_XID!=0) && (trans_packet_current->client_XID==trans_packet_current->server_XID))
                    ||
                    ((trans_packet_current->client_XID!=0) && (trans_packet_current->server_XID==0)))
                {
                  //Commit
                  strcpy((char *)RecvBufSplit,"Commit assumed");
                  /*
                  #ifdef WIN32
                                 print_header(st);
                  #else
                                 print_header(st,tp);
                  #endif
                                 if (SHOW_DISPLAY=='y')
                                 {
                                   printf("Commit assumed\n");
                                 }
                                 if (SAVE_DEBUG=='y')
                                 {
                                   fprintf(debug_file,"Commit assumed\n");
                                 }
                                 fprintf(audit_file,"Commit assumed\n");
                  */
                  return COMMAND_TYPE;
                }
                else
                {
                  if ((trans_packet_current->client_XID!=0) && (trans_packet_current->client_XID!=trans_packet_current->server_XID))
                  {
                    //Rollback
                    strcpy((char *)RecvBufSplit,"Rollback  assumed");
                    /*
                    #ifdef WIN32
                                   print_header(st);
                    #else
                                   print_header(st,tp);
                    #endif
                                   if (SHOW_DISPLAY=='y')
                                   {
                                     printf("Rollback assumed\n");
                                   }
                                   if (SAVE_DEBUG=='y')
                                   {
                                     fprintf(debug_file,"Rollback assumed\n");
                                   }
                                   fprintf(audit_file,"Rollback assumed\n");
                    */
                    return COMMAND_TYPE;

                  }
                }
                /*
                                if (SHOW_DISPLAY=='y')
                                {
                                  printf("XID client guardado: %i\n",*(datatcp+28));
                                }
                                if (SAVE_DEBUG=='y')
                                {
                                  fprintf(debug_file,"XID Client guardado: %i\n",*(datatcp+28));
                                }
                                fprintf(audit_file,"XID Client guardado: %i\n",*(datatcp+28));
                */
                break;
              }
              i++;
              *trans_packet_current++;
            }
            while (i<TRANSACTION_PACKET_SIZE);
            /*
            #ifdef WIN32
                        print_header(st);
            #else
                        print_header(st,tp);
            #endif
                        if (SHOW_DISPLAY=='y')
                        {
                          printf("XID client: %i\n",*(datatcp+28));
                        }
                        if (SAVE_DEBUG=='y')
                        {
                          fprintf(debug_file,"XID client: %i\n",*(datatcp+28));
                        }
                        fprintf(audit_file,"XID client: %i\n",*(datatcp+28));
            */
          }
          else
          {
            //if the initial of the packet has in position 10 a 8 and in position 11 a 0x7a then it has the Oracle release
            if(*(datatcp+10)==8 && *(datatcp+11)==0x7a && *(datatcp+12)==0 && *(datatcp+13)==0x7a)
            {
              for (i=14;i<lentcp;i++)
              {
                //The 0x01 in the packet marks the end
                if(*(datatcp+i)!=1)
                {
                  if (*(datatcp+i)!=0)
                  {
                    database_release_name[i-14]=*(datatcp+i);
                  }
                }
                else
                {
                  break;
                }
              }
              sprintf(RecvBufSplit,"Database Release: %s",database_release_name);
              /*
              #ifdef WIN32
                            print_header(st);
              #else
                            print_header(st,tp);
              #endif
                            if (SHOW_DISPLAY=='y')
                            {
                              printf("Database Release: %s\n",database_release_name);
                            }
                            if (SAVE_DEBUG=='y')
                            {
                              fprintf(debug_file,"Database Release: %s\n",database_release_name);
                            }
                            fprintf(audit_file,"Database Release: %s\n",database_release_name);
              */
              return COMMAND_TYPE;
            }
          }
        }
      }
    }
  }
  return NO_PACKET_TYPE;
}

void print_header(char * timestamp)
{
  if (SHOW_DISPLAY=='y')
  {
    printf("%s\n%s:%i\n",header,szSourceIP,ntohs(pTcpheader->sport));
  }
  if (SAVE_DEBUG=='y')fprintf(debug_file,"%s\n%s:%i\n",header,szSourceIP,ntohs(pTcpheader->sport));
  fprintf(audit_file,"%s\n%s:%i\n",header,szSourceIP,ntohs(pTcpheader->sport));
  if (SHOW_DISPLAY=='y')
  {
    printf("%s:%i\n",szDestIP,ntohs(pTcpheader->dport));
  }
  if (SAVE_DEBUG=='y')fprintf(debug_file,"%s:%i\n",szDestIP,ntohs(pTcpheader->dport));
  fprintf(audit_file,"%s:%i\n",szDestIP,ntohs(pTcpheader->dport));
  if (SHOW_DISPLAY=='y')
  {
    printf("Date_Time: %s\n",timestamp);
  }
  if (SAVE_DEBUG=='y')
  {
    fprintf(debug_file,"Date_Time: %s\n",timestamp);
  }
  fprintf(audit_file,"Date_Time: %s\n",timestamp);
  if (SHOW_DISPLAY=='y')
  {
    printf("%s\n",footer);
  }
  if (SAVE_DEBUG=='y')
  {
    fprintf(debug_file,"%s\n",footer);
  }
  fprintf(audit_file,"%s\n",footer);
}


// open raw socket, set promiscuous mode
void init_net()
{

#ifdef WIN32
  WSADATA w;
  SOCKADDR_IN sa;
  DWORD bytes;
  char hostname[HOSTNAME_LEN];
  struct hostent *h;
  unsigned int opt = 1;

  if (WSAStartup(MAKEWORD(2,0), &w) != 0) //using the version 2.0 of the DLL
  {
    printf("WSAStartup failed\n");
    exit(1);
  }
  if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET)
  {
    printf("unable to open raw socket\n");
    exit(1);
  }

  if ((gethostname(hostname, HOSTNAME_LEN)) == SOCKET_ERROR)
  {
    printf("unable to gethostname\n");
    exit(1);
  }

  if ((h = gethostbyname(hostname)) == NULL)
  {
    printf("unable to gethostbyname\n");
    exit(1);
  }

  sa.sin_family = AF_INET;
  sa.sin_port = htons(6000);
  memcpy(&sa.sin_addr.S_un.S_addr, h->h_addr_list[0], h->h_length);

  if ((bind(sock, (SOCKADDR *)&sa, sizeof(sa))) == SOCKET_ERROR)
  {
    printf("unable to bind() socket\n");
    exit(1);
  }
  if ((WSAIoctl(sock, SIO_RCVALL, &opt, sizeof(opt), NULL, 0, &bytes, NULL, NULL)) == SOCKET_ERROR)
  {
    printf("failed to set promiscuous mode\n");
    exit(1);
  }
#else
  /*
  if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == SOCKET_ERROR)	{
  ERROR_MESSAGE("unable to open raw socket");
  exit(1);
  }
  */

  struct ifreq ifr;
  int ifindex;
  struct sockaddr_ll sll;

  //  if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == SOCKET_ERROR) //This was the earlier version where all the protocols where received
  if ((sock = socket(PF_PACKET, SOCK_RAW, IPPROTO_TCP)) == SOCKET_ERROR)
  {
    ERROR_MESSAGE("unable to open raw socket");
    exit(1);
  }

  // get interface index number
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, linux_interface, IFNAMSIZ);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
  {
    ERROR_MESSAGE("SIOCGIFINDEX");
    exit(1);
  }
  ifindex = ifr.ifr_ifindex;

  /*
  //I don't know what the following lines do!!!
  struct sockaddr myaddr;
  int addrlen;

  // get hardware address
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, linux_interface, IFNAMSIZ);
  if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
  {
  ERROR_MESSAGE("SIOCGIFINDEX");
  exit(1);
  }
  myaddr = ifr.ifr_hwaddr;

  switch (myaddr.sa_family)
  {
  case ARPHRD_ARCNET:
  addrlen = 1;
  break;
  case ARPHRD_ETHER:
  addrlen = 6;
  break;
  default:
  addrlen = sizeof(myaddr.sa_data);
  }
  */

  //start: using an older system method to place the network adapter in promiscuous mode
  //Unfortunately, with this method, multiple promiscuous listeners can
  //interfere with each other and a buggy program can leave promiscuous mode on even after it exits.
  //from: Richard.Stevens-Unix.Network.Programming-Vol.1-3Rd Ed-Sockets Networking, Chap. 29.4

  //change the state of the interface
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, linux_interface, IFNAMSIZ);
  ioctl(sock,SIOCGIFFLAGS,&ifr);
  ifr.ifr_flags|=IFF_PROMISC;
  ioctl(sock,SIOCSIFFLAGS,&ifr);
  //The problem is that if another programm changes the interface to the initial status the promiscuous mode is changed to all the other programmes

  //end: using an older system method to place the network adapter in promiscuous mode


  /*
  //start: using a new system method to place the network adapter in promiscuous mode
  struct packet_mreq pr;

  memset(&pr, 0, sizeof(pr));
  pr.mr_ifindex = ifindex;
  pr.mr_type = PACKET_MR_PROMISC;


  //It works with both PACKET_ADD_MEMBERSHIP and PACKET_MR_PROMISC
  if( setsockopt(sock,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&pr, sizeof(struct packet_mreq)) < 0 )
  {
  ERROR_MESSAGE( "failed to set promiscuous mode" );
  }
  //end: using a new system method to place the network adapter in promiscuous mode
  */

  //
  // bind(2) uses only sll_protocol and sll_ifindex. see packet(7)
  //

  memset(&sll, 0xff, sizeof(sll));
  sll.sll_family = AF_PACKET;	// allways AF_PACKET
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifindex;
  if (bind(sock, (struct sockaddr *)&sll, sizeof sll) == -1)
  {
    ERROR_MESSAGE("unable to bind() socket");
  }

#endif
}

#ifndef WIN32
void sigint_sniffer(int signum)
{
  struct ifreq ifr;

  if (sock == -1)
    return;

  printf("\nLeaving promiscuous mode\n");
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, linux_interface, IFNAMSIZ);
  ioctl(sock, SIOCGIFFLAGS,&ifr);
  ifr.ifr_flags &= ~IFF_PROMISC;
  ioctl(sock, SIOCSIFFLAGS,&ifr);

  close(sock);
  exit(0);
}
#endif

int session_values_Oracle(unsigned char *datatcp,int lentcp,SESS *sess_data, char client_ip[],unsigned short int client_port,char server_ip[], unsigned short int server_port,char *timestamp)
{
  int aux;
  int pos;
  int result=0;

  //if the initial of the packet is a 0x04 then it has the session info we need
  if(sess_data->dbname[0]==(unsigned char)0)
    //  if(*(datatcp+10)==1 && *(datatcp+11)==0x2c && *(datatcp+aux)!='\0')
  {
    pos=str_find(datatcp,lentcp,"SERVICE_NAME=");
    if (pos!=-1)
    {
      //	  Thin_Client=0;
      pos=pos+13;
      aux=pos;
      do
      {
        sess_data->dbname[aux-pos]=*(datatcp+aux);
        aux++;
        if (*(datatcp+aux)==0x29 || (aux==lentcp))
        {
          sess_data->dbname[aux-pos]=0;
          aux=-1;
        }
      }
      while (aux>0);
    }
    else
    {
      pos=str_find(datatcp,lentcp,"SID=");
      if (pos!=-1)
      {
        Thin_Client=1;
        pos=pos+4;
        aux=pos;
        do
        {
          sess_data->dbname[aux-pos]=*(datatcp+aux);
          aux++;
          if (*(datatcp+aux)==0x29 || (aux==lentcp))
          {
            sess_data->dbname[aux-pos]=0;
            aux=-1;
          }
        }
        while (aux>0);
      }
    }
  }

  //if the initial of the packet is a 0x04 then it has the session info we need
	  //altera��o HUC
  if((*(datatcp+10)==3 && *(datatcp+11)==0x76) || (*(datatcp+22)==3 && *(datatcp+23)==0x76))
//  if(*(datatcp+10)==3 && *(datatcp+11)==0x76)
    //if(*(datatcp)==4)
  {
    pos=str_find(datatcp,lentcp,"AUTH_TERMINAL");
    pos=pos-7;
    aux=pos;
    do
    {
      aux--;
    }
    while (*(datatcp+aux)>=20 && (aux>0));
    aux++;
    pos=aux;
    do
    {
      sess_data->username[aux-pos]=*(datatcp+aux);
      aux++;
      if (*(datatcp+aux)<20 || (aux==lentcp))
      {
        sess_data->username[aux-pos]=0;
        aux=-1;
      }
    }
    while (aux>0);
    //printf("%s\n",sess_data->terminal);
  }
  //if the initial of the packet is a 0x04 then it has the session info we need
	  //altera��o HUC
  if((*(datatcp+10)==3 && *(datatcp+11)==0x73 && (*(datatcp+12)==3 || *(datatcp+12)==0)) || (*(datatcp+22)==3 && *(datatcp+23)==0x73 && (*(datatcp+24)==3 || *(datatcp+24)==0)))
//  if(*(datatcp+10)==3 && *(datatcp+11)==0x73 && (*(datatcp+12)==3 || *(datatcp+12)==0))
    //if(*(datatcp)==4)
  {
	  //altera��o HUC
    result=2;
      sprintf((char *)sess_data->starttime,"%s",timestamp);
//    result=1;
    sess_data->client_port=client_port;
    sess_data->server_port=server_port;
    //printf("%i\n",ntohs(sess_data->port));
    strncpy((char *)sess_data->client_ip,(const char *)client_ip,16);
    //printf("%s\n",sess_data->ip);
    strncpy((char *)sess_data->server_ip,(const char *)server_ip,16);

    /*
    aux=42;
    do{
    sess_data->username[aux-42]=*(datatcp+aux);
    aux++;
    if (*(datatcp+aux)<20 || (aux==lentcp))
    {
    sess_data->username[aux-42]=0;
    aux=-1;
    }
    }
    while (aux>0);
    //printf("%s\n",sess_data->username);
    */

    /*
       pos=str_find(datatcp,lentcp,"AUTH_SESSKEY");
       pos=pos-7;
       aux=pos;
       do
       {
         aux--;
       }
       while (*(datatcp+aux)>=20 && (aux>0));
       aux++;
       pos=aux;
       do
       {
         sess_data->username[aux-pos]=*(datatcp+aux);
         aux++;
         if (*(datatcp+aux)<20 || (aux==lentcp))
         {
           sess_data->username[aux-pos]=0;
           aux=-1;
         }
       }
       while (aux>0);
       //printf("%s\n",sess_data->terminal);
    */

    pos=str_find(datatcp,lentcp,"AUTH_TERMINAL");
    pos=pos+14+4;
    aux=pos;
    do
    {
      sess_data->terminal[aux-pos]=*(datatcp+aux);
      aux++;
      if (*(datatcp+aux)<20 || (aux==lentcp))
      {
        sess_data->terminal[aux-pos]=0;
        aux=-1;
      }
    }
    while (aux>0);
    //printf("%s\n",sess_data->terminal);

    sess_data->program[0]=0;
    pos=str_find(datatcp,lentcp,"AUTH_PROGRAM_NM");
    if (pos!=-1)
    {
      pos=pos+16+4;
      aux=pos;
      do
      {
        sess_data->program[aux-pos]=*(datatcp+aux);
        aux++;
        if (*(datatcp+aux)<20 || (aux==lentcp))
        {
          sess_data->program[aux-pos]=0;
          aux=-1;
        }
      }
      while (aux>0);
      //printf("%s\n",sess_data->program);
    }
  }

  //if the initial of the packet is a 0x03 then it has the session info we need
  if(((*(datatcp+18)==0x41 && *(datatcp+19)==0x55 &&*(datatcp+20)==0x54 && *(datatcp+21)==0x48 && *(datatcp+22)==0x5f && *(datatcp+23)==0x56))  || ((*(datatcp+16)==0x41 && *(datatcp+17)==0x55 &&*(datatcp+18)==0x54 && *(datatcp+19)==0x48 && *(datatcp+20)==0x5f && *(datatcp+21)==0x56)))
  {
    result=2;
    pos=str_find(datatcp,lentcp,"AUTH_SESSION_ID");
    pos=pos+16+4;
    aux=pos;
    do
    {
      sess_data->sid[aux-pos]=*(datatcp+aux);
      aux++;
      if (*(datatcp+aux)<20 || (aux==lentcp))
      {
        sess_data->sid[aux-pos]=0;
        aux=-1;
      }
    }
    while (aux>0);
    //printf("%s\n",sess_data->sid);

    pos=str_find(datatcp,lentcp,"AUTH_SERIAL_NUM");
    pos=pos+16+4;
    aux=pos;
    do
    {
      sess_data->serial[aux-pos]=*(datatcp+aux);
      aux++;
      if (*(datatcp+aux)<20 || (aux==lentcp))
      {
        sess_data->serial[aux-pos]=0;
        aux=-1;
      }
    }
    while (aux>0);
    //printf("%s\n",sess_data->serial);
    /*
        pos=str_find(datatcp,lentcp,"AUTH_SC_DBUNIQUE_NAME",21);
        if (pos!=-1)
        {
          pos=pos+21+4;
          aux=pos;
          do
          {
            sess_data->dbname[aux-pos]=*(datatcp+aux);
            aux++;
            if (*(datatcp+aux)<20 || (aux==lentcp))
            {
              sess_data->dbname[aux-pos]=0;
              aux=-1;
            }
          }
          while (aux>0);
          //printf("%s\n",sess_data->dbname);
        }
    */
    /*
        pos=str_find(datatcp,lentcp,"AUTH_SC_INSTANCE_START_TIME",27);
        if (pos!=-1)
        {
          pos=pos+27+4;
          aux=pos;
          do
          {
            sess_data->starttime[aux-pos]=*(datatcp+aux);
            aux++;
            if (*(datatcp+aux)<20 || (aux==lentcp))
            {
              sess_data->starttime[aux-pos]=0;
              aux=-1;
            }
          }
          while (aux>0);
          //printf("%s\n",sess_data->starttime);
        }
        else
    */
    {
      sprintf((char *)sess_data->starttime,"%s",timestamp);
    }

  }
  return(result);
}

void my_printf(FILE *stream,char *pointer)
{
  printf(pointer);
  fprintf(stream,pointer);
}

struct split_packet * AddItem(struct split_packet * split_paket_pointer,unsigned char *ip,unsigned int port,int dummy_char_count)
{
  struct split_packet * previous_record;

  if (split_paket_pointer != NULL)
  {
    while (split_paket_pointer -> next != NULL)	    split_paket_pointer = split_paket_pointer -> next;
    previous_record=split_paket_pointer -> previous;
    if((split_paket_pointer -> next = (struct split_packet  *) malloc (sizeof (struct split_packet)))==NULL)
    {
      ERROR_MESSAGE("split_paket_pointer -> next");
    }
    split_paket_pointer = split_paket_pointer -> next;
    split_paket_pointer -> next = NULL;
    split_paket_pointer -> previous = previous_record;
    split_paket_pointer ->RecvBufSplit=NULL;
    strcpy((char *)split_paket_pointer -> ip,(char *)ip);
    split_paket_pointer -> port = port;
    split_paket_pointer -> dummy_char_count= dummy_char_count;
  }
  else
  {
    if((split_paket_pointer = (struct split_packet  *) malloc (sizeof (struct split_packet)))==NULL)
    {
      ERROR_MESSAGE("split_paket_pointer");
    }
    split_paket_pointer -> next = NULL;
    split_paket_pointer -> previous = NULL;
    split_paket_pointer ->RecvBufSplit=NULL;
    strcpy((char *)split_paket_pointer -> ip,(char *)ip);
    split_paket_pointer -> port = port;
    split_paket_pointer -> dummy_char_count= dummy_char_count;
  }
  return split_paket_pointer;
  if (first_split_packet==NULL)
  {
    first_split_packet=current_split_packet;
  }
}
struct split_packet * RemoveItem(struct split_packet * split_paket_pointer)
{
  struct split_packet * previous_record;
  struct split_packet * next_record;

  previous_record=split_paket_pointer->previous;
  next_record=split_paket_pointer->next;

  if (previous_record !=NULL)
  {
    previous_record->next=next_record;
  }
  if (next_record !=NULL)
  {
    next_record->previous=previous_record;
  }
  if (split_paket_pointer->RecvBufSplit!=NULL)
  {
    free(split_paket_pointer->RecvBufSplit);
  }
  free(split_paket_pointer);

  if (previous_record != NULL)
  {
    while (previous_record -> previous != NULL)
    {
      previous_record = previous_record-> previous;
    }
  }
  else
  {
    previous_record=next_record;
  }
  return(previous_record);
}


struct split_packet * FindItem(struct split_packet * split_paket_pointer,unsigned char * ip,unsigned int port)
{
  if (split_paket_pointer != NULL)
  {
    while ((split_paket_pointer -> next != NULL) && ((strcmp((char *)split_paket_pointer ->ip,(char *)ip)!=0) || (split_paket_pointer ->port!=port)))
    {
      split_paket_pointer = split_paket_pointer -> next;
    }
    if ((strcmp((char *)split_paket_pointer ->ip,(char *)ip)==0) && (split_paket_pointer ->port==port))
    {
      return(split_paket_pointer);
    }
  }
  return(NULL);
}


// Listens the socket and returns an Oracle packet
int is_oracle_packet(char *RecvBuf,struct transaction_packet *trans_packet)
{
#ifdef WIN32
  DWORD bytes;
#else
  int bytes;
#endif
  int i;
  char char_port[6]={0};
  char char_oracle_port[6]={0};
  unsigned short int int_port;
  struct transaction_packet *trans_packet_current;

#ifdef WIN32
#define RECVBUF_OFFSET 0
#else
#define RECVBUF_OFFSET 14
#endif
  pIpheader = (struct ipheader *)(RecvBuf + RECVBUF_OFFSET);
  pTcpheader = (struct tcpheader *)(RecvBuf+RECVBUF_OFFSET+ sizeof(struct ipheader ));
  pUdpheader = (struct udphdr *) (RecvBuf+ RECVBUF_OFFSET+ sizeof(struct ipheader ));

  memset(RecvBuf, 0, PAKSIZE);

  get_timestamp(before_recv_timestamp);
  time_diff(delta_process_timestamp,before_recv_timestamp,after_recv_timestamp);
  //The recvfrom and recvmsg calls are used  to  receive  messages  from  a socket
  //and  may be used to receive data on a socket whether or not it is connection-oriented.
  //The recv call is normally used only on a connected socket and is identical to recvfrom with a NULL from parameter.
  //both of them are good options, but we do not need the source address of received data because it is a connected socket

  /*
    struct sockaddr_ll from;
    socklen_t fromlen = sizeof(from);
    if ((bytes = recvfrom(sock, RecvBuf, PAKSIZE, 0,(struct sockaddr*)&from, &fromlen)) == SOCKET_ERROR)
  */

  if ((bytes = recv(sock, RecvBuf, PAKSIZE, 0)) == SOCKET_ERROR)
  {
    printf("socket error on recv\n");
    exit(1);
  }
  else
  {
    //Using only IP packets
    if((pIpheader->ip_p)==IPPROTO_TCP)
    {
      get_timestamp(after_recv_timestamp);
      time_diff(delta_recv_timestamp,after_recv_timestamp,before_recv_timestamp);
      fprintf(delay_debug_file,"%s %s\n",delta_process_timestamp,delta_recv_timestamp);
      fflush(delay_debug_file);
      sprintf(char_oracle_port,"%i",DB_listener_port);

      saSource.sin_addr.s_addr = pIpheader->ip_src;
      strncpy(szSourceIP, inet_ntoa(saSource.sin_addr), 16);

      //Check Dest IP
      saDest.sin_addr.s_addr = pIpheader->ip_dst;
      strncpy(szDestIP, inet_ntoa(saDest.sin_addr), 16);

      lentcp =(ntohs(pIpheader->ip_len)-(sizeof(struct ipheader)+sizeof(struct tcpheader)));
      lenudp =(ntohs(pIpheader->ip_len)-(sizeof(struct ipheader)+sizeof(struct udphdr)));
      datatcp=(unsigned char *) RecvBuf+RECVBUF_OFFSET+sizeof(struct ipheader)+sizeof(struct tcpheader);

      //If the source IP or the destination IP is from the client_ip defined in the config.cfg file or it is *
      if((strcmp((char *)client_ip,szDestIP)==0) || (strcmp((char *)client_ip,szSourceIP)==0) || (client_ip[0]=='*'))
      {
        //With Windows Oracle Server the Oracle port is changed at startup of a connection
        //The server sends a packet containing the new port to be used by the client
        if(((strcmp((char *)DB_listener_ip,szSourceIP)==0) || DB_listener_ip[0]=='*') && (DB_listener_port==ntohs(pTcpheader->sport)))
        {
          //It is a packet from the server
          pos=str_find_unsensitive(datatcp,lentcp,"(port=");
          if (pos!=-1)
          {
            i=pos+5;
            while (*(datatcp+i)!=')')
            {
              char_port[i-pos-5]=*(datatcp+i);
              i++;
              if(i-pos-5>6)
              {
                printf("ERROR CHAR_PORT LENGTH!!!\n");
              }
            }
            if(strcmp(char_port,char_oracle_port)!=0)
            {
              printf("ERROR CHAR_PORT!!!\n");
            }
            //              strcpy(char_port,"1521");
            int_port=atoi(char_port);

            //Start: Find the first empty row in trans_packet and inserts the new session
            trans_packet_current=trans_packet;
            //Find the first empty row in trans_packet
            i=0;
            do
            {
              if ((strcmp((char *)trans_packet_current->server_ip,szDestIP)==0) && (trans_packet_current->server_port==htons(int_port)))
              {
                break;
              }
              i++;
              *trans_packet_current++;
            }
            while (i<TRANSACTION_PACKET_SIZE);
            //
            if (i==TRANSACTION_PACKET_SIZE)
            {
              //Inserts the new session
              trans_packet_current=trans_packet;
              i=0;
              do
              {
                if (trans_packet_current->client_ip[0]==0)
                {
                  strcpy((char *)trans_packet_current->client_ip,szDestIP);
                  trans_packet_current->client_port='\0';
                  strcpy((char *)trans_packet_current->server_ip,szSourceIP);
                  trans_packet_current->server_port=htons(int_port);
                  trans_packet_current->server_XID=0;
                  trans_packet_current->client_XID=0;
                  trans_packet_current->end_transaction='n';
                  break;
                }
                i++;
                *trans_packet_current++;
              }
              while (i<TRANSACTION_PACKET_SIZE);
            }
            //End: Find the first empty row in trans_packet and inserts the new session
          }
          //
        }
        else
          //It is not a packet from the server let's see if it is one of the sessions that are already started
        {
			trans_packet_current=trans_packet;
          i=0;
          //start: a litle speed optimization
          //if the result of the next if is true then then the packet can be processed

			//altera��o HUC
          if ((ntohs(pTcpheader->sport)==DB_listener_port || ntohs(pTcpheader->dport)==DB_listener_port || ((strcmp(szSourceIP,"172.20.2.44")==0 || strcmp(szDestIP,"172.20.2.44")==0)))
//          if ((ntohs(pTcpheader->sport)==oracle_port || ntohs(pTcpheader->dport)==oracle_port))
              &&
              ((strcmp(szSourceIP,(char *)DB_listener_ip)==0 || strcmp(szDestIP,(char *)DB_listener_ip)==0)|| DB_listener_ip[0]=='*' ))
          {
            //do nothing
          }
          else
          {
            //end: a litle speed optimization
            do
            {
              if(trans_packet_current->client_port=='\0')
              {
                if (
                  (((strcmp((char *)trans_packet_current->server_ip,szSourceIP)==0) && (trans_packet_current->server_port==pTcpheader->sport)))
                  ||
                  (((strcmp((char *)trans_packet_current->server_ip,szDestIP)==0) && (trans_packet_current->server_port==pTcpheader->dport)))
                )
                {
                  trans_packet_current->client_port=pTcpheader->sport;
                  break;
                }
              }
              else
              {
                if (
                  (((strcmp((char *)trans_packet_current->client_ip,szDestIP)==0) && (trans_packet_current->client_port==pTcpheader->dport))
                   &&
                   ((strcmp((char *)trans_packet_current->server_ip,szSourceIP)==0) && (trans_packet_current->server_port==pTcpheader->sport)))
                  ||
                  (((strcmp((char *)trans_packet_current->client_ip,szSourceIP)==0) && (trans_packet_current->client_port==pTcpheader->sport))
                   &&
                   ((strcmp((char *)trans_packet_current->server_ip,szDestIP)==0) && (trans_packet_current->server_port==pTcpheader->dport)))
                )
                {
                  break;
                }
              }
              i++;
              *trans_packet_current++;
            }
            while (i<TRANSACTION_PACKET_SIZE);
          }
        }
        //If the packet is from the oracle_port defined in the config.cfg file
        //or is belonging to an open session
        //then the packet can be processed
        if (
          ((ntohs(pTcpheader->sport)==DB_listener_port || ntohs(pTcpheader->dport)==DB_listener_port)
           &&
           ((strcmp(szSourceIP,(char *)DB_listener_ip)==0 || strcmp(szDestIP,(char *)DB_listener_ip)==0)|| DB_listener_ip[0]=='*' ))
          ||
          (i<TRANSACTION_PACKET_SIZE)
        )
          //        if ((ntohs(pTcpheader->sport)==oracle_port || ntohs(pTcpheader->dport)==oracle_port) &&             ((strcmp(szSourceIP,(char *)oracle_ip)==0 || strcmp(szDestIP,(char *)oracle_ip)==0)|| oracle_ip[0]=='*' ))
        {
          //          process_packet(trans_packet);
          return 1;
        }
      }
    }
    /*
        else
        {
          printf("it is not a TCP packet\n");
        }
    */
  }
  return 0;
}

/*************************************
*  Kill_session was based on
*  http://unsecure.altervista.org
*  created by Komrade
*************************************/

//see also: http://mixter.void.ru/rawip.html
//see: http://packetstormsecurity.nl/groups/mixter/
//and: http://beej.us/guide/bgnet/
//and: http://www.totse.com/en/hack/introduction_to_hacking/packetattacksv170247.html

//With Windows XP SP2 it is no longer possible to craft TCP packets over RAW socket
//see: http://seclists.org/lists/nmap-hackers/2005/Apr-Jun/0001.html
//see: http://support.microsoft.com/kb/897656
//see: http://www.microsoft.com/technet/prodtechnol/winxppro/maintain/sp2netwk.mspx
//see: http://support.microsoft.com/kb/893066/


// kill_session by Z� 17/09/2006

/* A common checksum function */
unsigned short checksum(unsigned short *buffer, int size)
{
  unsigned long cksum=0;
  while(size > 1)
  {
    cksum += *buffer++;
    size -= sizeof(unsigned short);
  }
  if(size)
    cksum += *(unsigned char*)buffer;
  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);
  return (unsigned short)(~cksum);
}

int kill_session(void)
{
  unsigned short int sport;	/* source port */
  unsigned short int dport;	/* destination port */
  unsigned int ip_src;		/* source address */
  unsigned int ip_dst;		/* dest address */
  unsigned int th_seq;        /* sequence number */
  unsigned int th_ack;        /* sequence number */

  int result;


  sport=pTcpheader->sport;
  ip_src=pIpheader->ip_src;
  dport=pTcpheader->dport;
  ip_dst=pIpheader->ip_dst;
  th_seq=pTcpheader->th_seq;
  th_ack=pTcpheader->th_ack;

  //for(int count=0;count<5;count++)
  {
    //kill the socket by sending a TCP RESET to the database server
    result=Send_RST(ip_dst, dport, ip_src, sport, th_seq);
    //kill the socket by sending a TCP RESET to the database client
    result=Send_RST(ip_src, sport, ip_dst, dport, th_ack);
  }
  return(result);
}

int Send_RST(unsigned int server_IP, unsigned short int server_port, unsigned int client_IP, unsigned short int client_port, unsigned int tcp_sequence_number)
{
  int sd;
  char packet[4096];
  struct sockaddr_in sin;
  unsigned short pseudo[32];
  unsigned char *ptr;
  struct ipheader *ip = (struct ipheader *) packet;
  struct tcpheader *tcp = (struct tcpheader *) (packet + sizeof(struct ipheader));

  int one = 1;
  const int *val = &one;
  unsigned int new_th_ack;

  new_th_ack=htonl(pTcpheader->th_seq)+(ntohs(pIpheader->ip_len)-(sizeof(struct ipheader)+sizeof(struct tcpheader)));
  //printf("new_th_ack %u\n",new_th_ack);
#ifdef WIN32
  WSADATA wsa;
  BOOL flag = TRUE;
#endif

#ifdef WIN32
  if(WSAStartup(MAKEWORD(2,1),&wsa))
  {
    fprintf(stderr, "\nError! WSAStartup failed!\n");
    return(1);
  }

  if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET)
  {
    fprintf(stderr, "\nError! Unable to open socket\n");
    WSACleanup();
    return(1);
  }
#else

  sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sd< 0)
  {
    perror("Kill session socket() error");
    return(1);
  }

#endif
  sin.sin_family = AF_INET;
  sin.sin_port = htons(135); //this will be changed with a random port
  sin.sin_addr.s_addr = server_IP; //this is the ip to where the packet will be sent

#ifdef WIN32
  if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&flag, sizeof(flag)) < 0)
  {
    fprintf(stderr, "\nError! Unable to set IP_HDRINCL option\n");
    closesocket(sd);
    WSACleanup();
    return(1);
  }
#else
  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
  {
    perror("Kill session setsockopt() error");
    return(1);
  }
#endif
  //build an TCP/IP packet, calculate the checksum for both the IP and TCP
  //and finally sends out the packet
  memset(packet, 0, 4096);
  ptr = NULL;
  sin.sin_port = htons((unsigned short)rand());

  ip->ip_hl = 5;		//IP Header Length (number of 32 -bit words forming the header, usually five)
  ip->ip_v = 4;		//Version (always set to the value 4, which is the current version of IP)
  ip->ip_tos = 0;		//Type of Service (ToS), now known as Differentiated Services Code Point (DSCP) (usually set to 0, but may indicate particular Quality of Service needs from the network, the DSCP defines the way routers should queue packets while they are waiting to be forwarded).
  ip->ip_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));	//Size of Datagram (in bytes, this is the combined length of the header and the data)
  ip->ip_id = htons((unsigned short)rand());	//Identification ( 16-bit number which together with the source address uniquely identifies this packet - used during reassembly of fragmented  datagrams).  the value doesn't matter here
  ip->ip_off = 0;		//Fragmentation Offset (a byte count from the start of the original sent packet, set by any router which performs IP router fragmentation)
  ip->ip_ttl = 128;	//Time To Live (Number of hops /links which the packet may be routed over, decremented by most routers  - used to prevent accidental routing loops)
  ip->ip_p = 6;		//Protocol (Service Access Point (SAP) which indicates the type of transport packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).
  ip->ip_src = client_IP;	//Source Address (the IP address  of the original sender of the packet). Here is usually the client ip
  ip->ip_dst = server_IP;	//Destination Address (the IP address of the final destination of the packet). Here is usually the server ip
  ip->ip_sum = 0;		//Header Checksum (A 1's complement checksum inserted by the sender and updated whenever the packet header is modified by a router - Used to detect processing errors introduced into the packet inside a router  or bridge where the packet is not protected by a link layer cyclic redundancy check. Packets with an invalid checksum are discarded by all nodes in an IP network)
  ip->ip_sum = checksum((unsigned short *) packet, 20);

  tcp->th_ack = htonl(0);				//Acknowledgment Number: 32 bits (If the ACK control bit is set this field contains the value of the next sequence number the sender of the segment is expecting to receive.  Once a connection is established this is always sent.)
  //tcp->th_ack =htonl(new_th_ack);
  //ack value of the last client packet or 0
  tcp->th_seq = tcp_sequence_number;	//Sequence Number: 32 bits (The sequence number of the first data octet in this segment (except when SYN is present). If SYN is present the sequence number is the initial sequence number (ISN) and the first data octet is ISN+1).
  //here the value is between seq value of the last client packet and seq value of the last client packet + 17500
  tcp->sport = client_port;	//client port
  tcp->dport = server_port;	//server port
  tcp->Flags = TH_RST;		//Flags (a sequence of three flags (one of the 4 bits is unused) used to control whether routers  are allowed to fragment  a packet (i.e. the Don't Fragment, DF, flag), and to indicate the parts of a packet to the receiver)
  tcp->th_win=0;	//Window: 16 bits (The number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept).
  tcp->th_off=5;	// Data Offset: 4 bits (The number of 32 bit words in the TCP Header.  This indicates where the data begins.  The TCP header (even one including options) is an integral number of 32 bits long).
  //the minimum size of the tcp header is 5
  tcp->th_urp=0;	//Urgent Pointer: 16 bits (This field communicates the current value of the urgent pointer as a positive offset from the sequence number in this segment.  The urgent pointer points to the sequence number of the octet following the urgent data.  This field is only be interpreted in segments with the URG control bit set).

  ptr = (unsigned char *)pseudo;
  // These passages were NOT coded by me. They're from Sahir Hidayatullah. These statements are based on hard coded offsets of the various fields from the start of the datagram
  memset(pseudo,0,32); // Zero out the pseudo-header
  memcpy(ptr,packet+20,20); // Copy in the tcp header
  memcpy((ptr+20),packet+12,4); // Source IP
  memcpy((ptr+24),packet+16,4); // Dest IP
  memcpy((ptr+29),packet+9,1); // 8bit zero + Protocol
  memset((ptr+31),20,1);

  tcp->th_sum=0;		//Checksum: 16 bits
  tcp->th_sum = checksum(pseudo, 32);

  /* Sends out the datagram. 40 bytes is the sum of IP and TCP header length */
  if(sendto(sd,packet,40,0,(struct sockaddr *) &sin, sizeof(sin)) < 0)
  {
#ifdef WIN32
    printf ("Error while sending the packet: %d\n", WSAGetLastError());
    closesocket(sd);
    WSACleanup();
#else
    printf ("Error while sending the packet\n");
    close(sd);
#endif
    return(1);
  }

  else
  {
    struct in_addr  addr;

    addr.s_addr = server_IP;
    printf ("TCP RESET packet sent to %s:%i",inet_ntoa(addr),ntohs(server_port));
    addr.s_addr = client_IP;
    printf (" from %s:%i\n",inet_ntoa(addr),ntohs(client_port));
  }

#ifdef WIN32
  closesocket(sd);
  WSACleanup();
#else
  close(sd);
#endif
  return(0);
}
