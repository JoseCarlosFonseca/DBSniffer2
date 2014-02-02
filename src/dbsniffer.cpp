//TODO usar o getopt() para fazer o parsing dos argumentos
//
//In Linux must be executed with root user because of the need to use the Raw IP Sockets
//In linux use ifconfig with user root to see ethernet configuration
//

#define TARGET_DB_MySQL 1
#define TARGET_DB_Oracle 0

#include "util.h"
#include "sniffer.h"
#include "crc.h"
#include "parser.h"
#include "learner.h"
#include "detector.h"
#include "getoptWin32.h"


//Argument defines
#define MAX_PARAMETER_NAME 256
#define MAX_PARAMETER_VALUE 256

#ifndef DBSNIFFER_H
#define DBSNIFFER_H

#define DBSNIFFER_VERSION "2011/04/12"

int init_opt(int, char **);
void show_usage(char *progname);

#endif //DBSNIFFER_H

int main(int argc, char **argv) {

    int init_opt_return;

    printf("%s Version %s %s\n", argv[0], __DATE__, __TIME__);
#ifdef WIN32
    printf("for Windows\n");
    printf("You must be administrator to run this program!\n\n");
#endif

#ifdef __linux__
    printf("for Linux\n");
    if (getuid() != 0) {
        printf("You must be root to run this program!\n");
        //    exit (0);
    }
#endif

#ifdef NDEBUG
    //    printf ("The program was compiled with the release option!\n");
#else
    printf("The program was compiled with the debug option!\n");
    //printf("FILE: %s LINE: %i FUNCTION: %s\n",__FILE__,__LINE__,__FUNCTION__);
#endif
#ifdef __linux__
    //to test the use of the assert
    //if the program is running with user root
    //assert(getuid () != 0);
#endif

    /*
    char *file_line;
    char RecvBufSplit[PAKSIZE] = {0};
    if((file_line=(char *)malloc((MAX_FILE_LINE_LENGTH)*sizeof(char)))==NULL)
      ERROR_MESSAGE("file_line");
    sprintf(RecvBufSplit,"insert into address (addr_id, addr_street1, addr_street2, addr_city, addr_state, addr_zip, addr_co_id) values (203,'|Al{xhE!Q]/zGmFC,nWxr[GJD*QzqR','Kjk}PJ|mZ=VZkLzSCB^EMg_','=AZUh?+]Kd=^@![{K(|ZkPNy*~}~','yapeQVMB$y[X+IwFlzb',';EE*Nn/',56)");
    printf("%s\n",RecvBufSplit);
    file_line=line_parser(RecvBufSplit);
    printf("%s\n",RecvBufSplit);
     */
    init_opt_return = init_opt(argc, argv);
    printf("Using: %s\n", config_file_name);
    fflush(stdout); //used to print the messages in the Java interface application more often

    if (init_opt_return != 0) {
        exit(-1);
    }

    if (strcmp(remove_files, "") != 0) {
        remove_files_created_by_mode(remove_files);
        return (0);
    }

    if (strcmp(mode, "sniffer") == 0) {
        option_sniffer();
    } else
        if (strcmp(mode, "justparser") == 0) {
        printf("\nJust Parsing...\n\n");
        option_parser();
    } else
        if (strcmp(mode, "justlearner") == 0) {
        printf("\nJust Learning...\n\n");
        option_learner(0); //the parameter is learn_also_read_only and if it is 1 then there will be also learned the read only transaction
    }
    if (strcmp(mode, "learner") == 0) {
        printf("\nParsing...\n\n");
        option_parser();
        fflush(stdout); //used to print the messages in the Java interface application more often
        printf("\nLearning...\n\n");
        option_learner(0); //the parameter is learn_also_read_only and if it is 1 then there will be also learned the read only transaction
    } else
        if (strcmp(mode, "detector") == 0) {
        option_detector();
    }
    return (0);
}

/* parse args, init format strings */
int init_opt(int argc, char **argv) {
    int result;
    char parameter_name[MAX_PARAMETER_NAME];
    char parameter_value[MAX_PARAMETER_VALUE];
    int error;
    int count;
    int size;
    char mode_final[MAX_PARAMETER_VALUE];

    int ch; /* storage var for getopt info */
    char *valid_options;


    mode_final[0] = 0;
    //if there is no arguments
    if (argc < 2) {
        show_usage(argv[0]);
        exit(1);
    }

    // The getopt() function returns the next option character specified on the command line.
    // A colon (:) is returned if getopt() detects a missing argument and the first character of optstring was a colon (:).
    // A question mark (?) is returned if getopt() encounters an option character not in optstring or detects a missing argument and the first character of optstring was not a colon (:).
    // Otherwise getopt() returns -1 when all command line options are parsed.

    valid_options = "?c:m:r:p:d:k:";
    strcpy(config_file_name, "config.cfg");
    strcpy(detector_option, "transaction");
    strcpy(kill_option, "nothing");
    /* loop through each command line var and process it */
    while ((ch = getopt(argc, argv, valid_options)) != -1) {
        printf("Processing cmd line switch: %c\n", ch);
        switch (ch) {
            case 'c': //config file
                strcpy(config_file_name, optarg);
                printf("config file: %s\n", config_file_name);
                break;
            case 'm':
                strcpy((char *) mode_final, optarg);
                printf("mode: %s\n", mode_final);
                break;
            case 'r': //remove files
                strcpy(remove_files, optarg);
                printf("remove files: %s\n", remove_files);
                break;
            case 'p': //append files
                strcpy(append_files, optarg);
                printf("parsing option: %s\n", append_files);
                break;
            case 'v':
                hidden = true;
                break;
            case 'd': //detector options
                strcpy(detector_option, optarg);
                printf("detector option: %s\n", detector_option);
                break;
            case 'k': //kill detector options
                strcpy(kill_option, optarg);
                printf("kill option: %s\n", kill_option);
                break;
            case '?': /* show help and exit with 1 */
                show_usage(argv[0]);
#ifndef WIN32
                if (optopt)
                    exit(1);
#endif
                exit(0);
            default:
                show_usage(argv[0]);
                exit(1);
                break;
        }
    }

    if (optind < argc) {
        show_usage(argv[0]);
        exit(1);
    } else {

        if ((pcap_lookupdev(errbuf)) == NULL) {
            strcpy((char *) linux_interface, "eth0");
        } else {
            /* Get the name of the first device suitable for capture */
            strcpy((char *) linux_interface, (char *) parameter_value);
        };
        /* If user supplied interface name, use it. */

        //remove " from the beginning and the end of the string containing the config file name
        //size of file_line
        size = 0;
        while (*(config_file_name + size) != 0) {
            size++;
        }

        if (*(config_file_name) == '"') {
            *(config_file_name) = ' ';
            *(config_file_name + size - 1) = '\0';
            count = 0;
            do {
                *(config_file_name + count) = *(config_file_name + count + 1);
                count++;
            } while (count < size);
            //Now the config file name has no " in the beginning nor in the end

            printf("The file is:'%s'\n", config_file_name);
            //    exit (0);

        }

        printf("The file is:'%s'\n", config_file_name);
        // Open for write (will fail if file "debug.txt" does not exist)
        if ((config_file = fopen(config_file_name, "r")) == NULL) {
            printf("The file '%s' was not opened\n", config_file_name);
            result = -1;
        } else {
            if (hidden == false) {
                printf("The config file '%s' was opened\n", config_file_name);
            }
            /* Set pointer to beginning of file: */
            fseek(config_file, 0L, SEEK_SET);

            while (!feof(config_file)) {
                parameter_name[0] = 0;
                parameter_value[0] = 0;
                fscanf(config_file, "%s", parameter_name);
                if (parameter_name[0] != 0) {
                    fscanf(config_file, "%s", parameter_value);
                    if (parameter_value[0] == 0) {
                        printf("Parameter value error! Parameter '%s' does not have a value!", parameter_name);
                        error = 1;
                    } else {
                        error = 0;
                        if (strcmp((char *) parameter_name, "Mode:") == 0) {
                            if (argc > 3) {
                                if (argv[2][0] == '-' && argv[2][1] == 'm') {
                                    strcpy((char *) parameter_value, (char *) argv[3]);
                                }
                            }
                            strcpy((char *) mode, (char *) parameter_value);
                        } else if (strcmp((char *) parameter_name, "Server_Port:") == 0) {
                            string2int((char *) parameter_value, (int &) DB_listener_port);
                        } else if (strcmp((char *) parameter_name, "Server_IP:") == 0) {
                            strcpy((char *) DB_listener_ip, (char *) parameter_value);
                        } else if (strcmp((char *) parameter_name, "Client_IP:") == 0) {
                            strcpy((char *) client_ip, (char *) parameter_value);
                        } else if (strcmp((char *) parameter_name, "Display:") == 0) {
                            SHOW_DISPLAY = parameter_value[0];
                        } else if (strcmp((char *) parameter_name, "Debug:") == 0) {
                            SAVE_DEBUG = parameter_value[0];
                        } else if (strcmp((char *) parameter_name, "Interface:") == 0) {
                            strcpy((char *) linux_interface, (char *) parameter_value);
                        } else if (strcmp((char *) parameter_name, "Header:") == 0) {
                            strcpy((char *) header, (char *) parameter_value);
                        } else if (strcmp((char *) parameter_name, "Footer:") == 0) {
                            strcpy((char *) footer, (char *) parameter_value);
                        } else if (strcmp((char *) parameter_name, "Start_session:") == 0) {
                            strcpy((char *) start_session, (char *) parameter_value);
                        } else if (strcmp((char *) parameter_name, "End_session:") == 0) {
                            strcpy((char *) end_session, (char *) parameter_value);
                        } else {
                            printf("Parameter name error! Parameter '%s' does not exist!", parameter_name);
                            error = 1;
                        }
                    }
                    if (error == 0) {
                        printf("%s %s\n", parameter_name, parameter_value);
                    }
                }
            }

            printf("\n");
        }

    }
    if (mode_final[0] != 0) {
        strcpy(mode, mode_final);
    }
    return (0);
}

/*
 * Function: show_usage(char *)
 *
 * Purpose:  Display the program options and exit
 *
 * Arguments: progname => name of the program (argv[0])
 */
void show_usage(char *progname) {
    printf("USAGE: %s [-options]\n", progname);
    printf("Options:\n");
    printf(" -c <config>  - Uses the Config File <config>\n");
    printf("                the default Config File is condifg.cfg\n");
    printf(" -m <mode>    - Change the operation mode of Config File to <mode>:\n");
    printf("                    sniffer      - sniffs the database packets\n");
    printf("                    learner      - learns the profiles\n");
    printf("                    detector     - starts the malicious commands detection\n");
    printf("                    justparser   - just parses the profiles\n");
    printf("                    justlearner  - just learns the profiles\n");
    printf(" -p <parsing> - How the files files created by the sniffer will be parsed and learned:\n");
    printf("                    all          - parsing and learning all files (default)\n");
    printf("                    last         - parsing and learning just last file\n");
    printf("                    merge        - merge the files before parsing\n");
    printf(" -r <mode>    - Removes the files previously created by <mode> (has precedence over the -m switch):\n");
    printf("                    all          - all files created\n");
    printf("                    sniffer      - just files created by sniffer\n");
    printf("                    learner      - just files created by learner\n");
    printf("                    detector     - just files created by detector\n");
    printf("                    justparser   - just files created by justparser\n");
    printf("                    justlearner  - just files created by justlearner\n");
    printf(" -d <mode>    - How the detector is operated:\n");
    printf("                    transaction  - detects malicious transactions (default)\n");
    printf("                    command      - only detects malicious commands\n");
    printf(" -k <mode>    - What actions the detector takes when an intrusion is detected:\n");
    printf("                    nothing      - does nothing (default)\n");
    printf("                    kill         - kills the session\n");
    printf(" -?           - Show this information screen\n");
}
