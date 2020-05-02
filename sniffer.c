/**
    @file   sniffer.c
    @author Daniel Pátek (xpatek08)
    @brief  VUT FIT 2020 / IPK Project 2 variant ZETA
*/

// access to library functions (etc. pcap_lookupdev())
#include <pcap.h> 

// standart C stuff
#include <stdio.h>      // printf()
#include <string.h>     // strcpy(), strcat()
#include <stdlib.h>     // EXIT_SUCCES, EXIT_FAILURE macros
#include <unistd.h>     // getopt()
#include <ctype.h>      // isprint()
#include <stdbool.h>    // type boolean
#include <sys/time.h>   // time miliseconds
#include <time.h>       // time()

// used for exiting the program (with ctrl+c etc.) with proper clear
#include <signal.h>

// Definitions for certain ether types
#define IPv4_TYPE 2048
#define IPv6_TYPE 34525

// Network Data Structures
#include <arpa/inet.h>          // inet_ntop()
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// Global variable
// length of the first header (ethernet..)
// cant get it to the packet_parse function -> has to be global
int header_length;

// general variable - descriptor
// global due to signal function
pcap_t* pcap_descriptor;


/**
    @brief clear the pcap_descriptor and print stats
    @param pcap_descriptor pcap descriptor
*/

void clear() {
    // stats of packets
    struct pcap_stat stats;

    // print the stats (if some exist)
    if (pcap_stats(pcap_descriptor, &stats) >= 0) {
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n", stats.ps_drop);
    }

    // close the pcap descriptor
    pcap_close(pcap_descriptor);
    exit(EXIT_SUCCESS);
}


/**
    @brief Establishes pcap_descriptor with filtering and returnes it.
    @param device interface (string)
    @param filter_expression filter expression (string)
    @param pcap_descriptor pointer to empty pcap descriptor
*/
pcap_t* open_pcap_socket(char* device, const char* filter_expression) {
    // error buffer for pcap_functions
    char errbuf[PCAP_ERRBUF_SIZE];

    // variables for the lookupnet function (we wont use source_ip)
    uint32_t  source_ip, netmask;

    // struct for filtering
    struct bpf_program  bpf;

    // If no device is selected, get the first one. This should not get executed.
    if (!*device) {
        if (!(device = pcap_lookupdev(errbuf))) {
            printf("pcap_lookupdev(): %s\n", errbuf);
            return NULL;
        }
    }

    /*
        Opening the device for live capture.
        we need device pointer to do that
        argument no. 2 max size of packet is set to the BUFSIZ, which is general buffer size provided by netinet
        argument no. 3 enables promiscular mode
        argument no. 4 disables any timeout
        we get pcap_descriptor 
    */
    if ((pcap_descriptor = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // get network device source IP address and netmask
    // we need to get netmask in order to perform filtering in next step
    if (pcap_lookupnet(device, &source_ip, &netmask, errbuf) < 0) {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // convert the filter expression into a packet filter code
    // we will get the bpf struct, used for filtering, based on our filter expression
    if (pcap_compile(pcap_descriptor, &bpf, (char *) filter_expression, 0, netmask)) {
        printf("pcap_compile(): %s\n", pcap_geterr(pcap_descriptor));
        return NULL;
    }

    // assign the packet filter to the given libpcap socket
    if (pcap_setfilter(pcap_descriptor, &bpf) < 0) {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pcap_descriptor));
        return NULL;
    }

return pcap_descriptor;
}


/**
    @fn Capturing loop.
    @brief have to find out link layer type (in order to find out header offset)
    @param pcap_descriptor pcap descriptor
    @param packet_number number of packets to handle (0 means no limit)
    @param func Function pointer for pcap_loop
*/
void start_capture(pcap_t* pcap_descriptor, int packet_number, pcap_handler func) {
    // dlt enum (link-layer header type)
    int link_type; 

    // determine the datalink layer type (ethernet / slip)
    if ((link_type = pcap_datalink(pcap_descriptor)) < 0) {
        printf("pcap_datalink(): %s\n", pcap_geterr(pcap_descriptor));
        return;
    }

    // Set the datalink layer header size.
    switch (link_type) {
        case DLT_NULL:
            header_length = 4;
            break;

        case DLT_EN10MB:
            header_length = 14;
            break;

        case DLT_SLIP:
        case DLT_PPP:
            header_length = 24;
            break;

        case DLT_LINUX_SLL:
            header_length = 16;
            break;

        default:
            printf("Unsupported datalink (%d)\n", link_type);
            return;
    }

    // start capturing packet_number
    if (pcap_loop(pcap_descriptor, packet_number, func, 0) < 0) {
        printf("pcap_loop() failed: %s\n", pcap_geterr(pcap_descriptor));
    }
}


/**
    @fn printData
    @brief Function for printing the packet content.
    @param packet pointer to the start character of the packet
    @param size packet total size
    @param headSize packet head size
*/
void printData(unsigned char *packet, int size, int headSize) {
    // boolean indicates if the head has been printed or is printing right now
    bool headPrinted = false;
    // two counters for double-for cycle
    int i = 0, j = 0;

    // line counter
    int line_counter = 1; 

    // after header offset
    int afterHeaderOffset = headSize % 16;

    // first line counter
    printf("0x0000:");

    // for cycle every element of the packet (packet size)
    for (i = 0; i < size; i++) {
        // if it finished the hexa line or head is printing
        if (headPrinted ? ((i - afterHeaderOffset) % 16 == 0 && i != headSize) :
        (i != 0 && i % 16 == 0)) {
            // continue to print characters (print dot if char is not printable)
            printf(" ");
            for (j = i - 16; j < i; j++) {
                if (isprint(packet[j])) {
                    printf("%c", (unsigned char) packet[j]);
                }
                else {
                    printf(".");
                }
                // print the space between bytes
                if (j == i - 9) {
                    printf(" ");
                }
            }
            printf("\n");

            //now we have to print the number of bytes printed
            if (line_counter < 10) printf("0x00%d:", line_counter++ * 10);
            else if (line_counter < 100) printf("0x0%d:", line_counter++ * 10);
            else printf("0x%d:", line_counter++ * 10);
        }
        
        // two spaces after the 0x0000 etc.
        if ((headPrinted ? i - afterHeaderOffset : i) % 16 == 0) {
            printf("  ");
        }
        
        // space between each 8 bytes in hexa
        if ((((headPrinted ? i - afterHeaderOffset : i) - 8) % 16) == 0) {
            printf(" ");
        }

        // this prints the hexa representation
        printf("%02X ", (unsigned char) packet[i]);

        // process the last line of head or last line of packet
        if ((i == size - 1) || (headSize - 1 == i)) {
            // print the missing spaces to fill the line
            for (j = 0; j < 15 - ((headPrinted ? i - afterHeaderOffset : i) % 16); j++) {
                printf("   ");
                // print space between 8 bytes
                if (j == 7) printf(" ");
            }

            // change boolean if nessessary
            if (headSize != size) headPrinted = !headPrinted;

            // spaces between hex and data
            printf(" ");

            // now print the rest of the data
            for (j = (!headPrinted ? (headSize == size) ? (i - (i % 16)) : (i - ((i - afterHeaderOffset) % 16)) : headSize - afterHeaderOffset);
                j <= (!headPrinted ? i : headSize - 1); j++) {
                // if the character is not printable -> print dot
                if (isprint(packet[j])) {
                    printf("%c", (unsigned char) packet[j]);
                }
                else {
                    printf(".");
                }

                // print the space between bytes
                if (headPrinted) {
                    if (j == headSize - (headSize % 16) + 7) printf(" ");
                }
                else {
                    if (headSize == size) {
                        if (j == i - (i % 16) + 7) printf (" ");
                    }
                    else {
                        if (j == i - ((i - afterHeaderOffset) % 16) + 7) printf(" ");
                    }
                }
            }

            // if ending the head, print next line counter
            // otherwise just newline
            if (headPrinted && headSize != size) {
                printf("\n\n");
                if (line_counter < 10) printf("0x00%d:", line_counter++ * 10);
                else if (line_counter < 100) printf("0x0%d:", line_counter++ * 10);
                else printf("0x%d:", line_counter++ * 10);
            } else {
                printf("\n");
            }
        }
    }
}

/**
    @brief packet parser function (called by pcap)
    @param user description (we wont use that)
    @param packethdr structure containing info about packet
    @param packetptr pointer to the first char of packet
*/
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr) { 
    // bool flags for ip version
    bool ipv6_flag = false;
    bool ipv4_flag = false;

    // total header offset in case of ipv6
    int ip6_header_next_offset = 0;

    // printing the current time in miliseconds
    time_t timer;
    struct tm * tm_info;

    //get the time
    char buffer[26];
    timer = time(NULL);
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%H:%M:%S", tm_info);

    //get miliseconds
    struct timeval time;
    gettimeofday(&time, NULL);

    // print the packet info
    // next piece of code is from cn.wei.hp@gmail.com
    // next piece of code from this link: https://code.google.com/p/pcapsctpspliter/issues/detail?id=6
	int packet_type = ((int) (packetptr[12]) << 8) | (int) packetptr[13];
	// END code segment that I borrowed from cn.wei.hp@gmail.com

	// Set flags based on ether type.
	switch(packet_type) {
			case IPv4_TYPE:
                ipv4_flag = true;
                break;

			case IPv6_TYPE:
                ipv6_flag = true;
                break;

            default:
                return;
		}

    //create array for source and destination ip adresses
    char source_ip[256];
    char destination_ip[256];

    // skip the datalink layer header
    u_char * tempPtr = packetptr + header_length;

    struct ip* iphdr;
    struct ip6_hdr* ip6hdr;

    if (ipv4_flag) {
    // find ip adresses in ip header
    iphdr = (struct ip *) tempPtr;

    //copy ip adresses
    strcpy(source_ip, inet_ntoa(iphdr->ip_src));
    strcpy(destination_ip, inet_ntoa(iphdr->ip_dst));

    // advance to the transport layer header
    tempPtr += 4 * iphdr->ip_hl;
    }
    int nextHeader = -1;

    if (ipv6_flag) {
        ip6hdr = (struct ip6_hdr *) tempPtr;
        //copy ip adresses
        inet_ntop(AF_INET6, &(ip6hdr->ip6_src), source_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6hdr->ip6_dst), destination_ip, INET6_ADDRSTRLEN);

        nextHeader = ip6hdr->ip6_nxt;
        tempPtr += 40;
        ip6_header_next_offset += 40;

        switch (nextHeader) {
        case IPPROTO_ROUTING:;
            struct ip6_rthdr * header =  (struct ip6_rthdr *) tempPtr;
            tempPtr += sizeof(struct ip6_rthdr);
            ip6_header_next_offset += sizeof(struct ip6_rthdr);
            nextHeader = header->ip6r_nxt;
            break;
        
        case IPPROTO_HOPOPTS:;
            struct ip6_hbh * header1 =  (struct ip6_hbh *) tempPtr;
            tempPtr += sizeof(struct ip6_hbh);
            ip6_header_next_offset += sizeof(struct ip6_hbh);
            nextHeader = header1->ip6h_nxt;
            break;

        case IPPROTO_FRAGMENT:;
            struct ip6_frag * header2 =  (struct ip6_frag *) tempPtr;
            tempPtr += sizeof(struct ip6_frag);
            ip6_header_next_offset += sizeof(struct ip6_frag);
            nextHeader = header2->ip6f_nxt;
            break;

        case IPPROTO_DSTOPTS:;
            struct ip6_dest * header3 =  (struct ip6_dest *) tempPtr;
            tempPtr += sizeof(struct ip6_dest);
            ip6_header_next_offset += sizeof(struct ip6_dest);
            nextHeader = header3->ip6d_nxt;
            break;
        
        default:
            break;
        }

    }

    // parse head and data in two options
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    switch (ipv6_flag ? nextHeader : iphdr->ip_p) {    
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *) tempPtr;
		    // print time and miliseconds
            printf("%s", buffer);
		    //print miliseconds
            printf(".%06ld ", (long int) time.tv_usec);
            printf("TCP %s : %d > %s : %d\n\n", source_ip, ntohs(tcphdr->source), destination_ip, ntohs(tcphdr->dest));
            if (ipv4_flag) printData(packetptr, packethdr->caplen, header_length + 4 * iphdr->ip_hl + 4 * tcphdr->doff);
            if (ipv6_flag) printData(packetptr, packethdr->caplen, header_length + ip6_header_next_offset + 4 * tcphdr->doff);
		// packet space between
    		printf("\n\n");
            break;
    
        case IPPROTO_UDP:
            udphdr = (struct udphdr *) tempPtr;
		// print time and miliseconds
    		printf("%s", buffer);
		//print miliseconds
    		printf(".%06ld ", (long int) time.tv_usec);
            printf("UDP %s : %d > %s : %d\n\n", source_ip, ntohs(udphdr->source), destination_ip, ntohs(udphdr->dest));
            if (ipv4_flag) printData(packetptr, packethdr->caplen, header_length + 4 * iphdr->ip_hl + 8);
            if (ipv6_flag) printData(packetptr, packethdr->caplen, header_length + ip6_header_next_offset + 8);
		// packet space between
    		printf("\n\n");
            break;
    }
}

// Print all interfaces
void printInterfaces() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    pcap_if_t *temp;
    int i = 1;
    if (pcap_findalldevs(&interfaces, error_buffer) < 0) {
        printf("Error in pcap_findalldevs(): %s", error_buffer);
        exit(EXIT_FAILURE);
    }

    printf("Avaiable interfaces on this device: \n");
    for (temp = interfaces; temp; temp = temp->next) {
        printf("%d:\t%s\n", i++, temp->name);
    }
}

// Print help text
void printHelp(char * argv) {
    printf("usage: %s [-h] [-i ] [-n ] [-p ] [-u] [-t]\n", argv);
    printf("\t-h            open this help\n");
    printf("\t-i [string]   specify an interface\n");
    printf("\t-n [integer]  set packet limit (unlimited if not set)\n");
    printf("\t-p [integer]  set packet port to filter\n");
    printf("\t-u            filter only UDP packets\n");
    printf("\t-t            filter only TCP packets\n");
}


int main(int argc, char **argv) {
    // interface name
    char interface[256] = "";

    // filter string to be built
    char filter_expression[256] = "";

    // number of packtes to scan
    int packet_number = 0, c;

    // port filter
    char port_number[10] = "port ";

    // boolean for tcp and udp connections
    bool TCPonly = false;
    bool UDPonly = false;

    // bool to check whether the interface was added
    bool interfaceAdded = false;

    // process long args
    int argctmp = argc;
    while (argctmp--) {
        if (strcmp(argv[argctmp], "--tcp")) {
            TCPonly = true;
            argv[argctmp] = "";
        }
        if (strcmp(argv[argctmp], "--udp")) {
            UDPonly = true;
            argv[argctmp] = "";
        }
    }

    // Get the command line options, if any
    while ((c = getopt (argc, argv, "hi:n:utp:")) != -1) {
        switch (c) {
        case 'h':
            printHelp(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'i':
            interfaceAdded = true;
            strcpy(interface, optarg);
            break;
        case 'n':
            packet_number = atoi(optarg);
            break;
        case 'u':
            UDPonly = true;
            break;
        case 't':
            TCPonly = true;
            break;
        case 'p':
            strcat(port_number, optarg);
            break;
        }
    }

    // check conflicting types of args
    if (TCPonly && UDPonly) {
        printf("Args are in conflict.\n");
        printHelp(argv[0]);
        exit(EXIT_FAILURE);
    }

    //check if the interface was added
    if (!interfaceAdded) {
        printf("Interface is not specified.\n");
        printInterfaces();
        exit(EXIT_FAILURE);
    }

    // if any, set packet capture filter expression
    if (TCPonly) strcat(filter_expression, "tcp ");
    if (UDPonly) strcat(filter_expression, "udp ");
    if (strcmp(port_number, "port ") != 0) strcat(filter_expression, port_number);

    // open libpcap
    if ((pcap_descriptor = open_pcap_socket(interface, filter_expression))) {
        //connect the signals to the ending function
        signal(SIGINT, clear);
        signal(SIGQUIT, clear);
        signal(SIGTERM, clear);
        
        // run the sniffing
        start_capture(pcap_descriptor, packet_number, (pcap_handler) parse_packet);

        clear();
    }
    exit(EXIT_SUCCESS);
}
