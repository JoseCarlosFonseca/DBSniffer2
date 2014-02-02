//parser functions

void first_word(unsigned char *main_string, char * f_word);
void file_command_parser(char * file_line, FILE * aud_file2);
char * line_parser(char * file_line);
char * line_parser_old(char * file_line);
char * command_parser(char * file_line);
char * block_parser(char * file_line, char * block, char keep);
int find_next_block(char * file_line, char * block);
int str_find_unsensitive2_in_block(unsigned char *main_string, char *search_string);
void option_parser(void);
void option_parser_files(char *auditory_file_name, char *session_file_name, char *aud_file_name);

#define MAX_FILE_NAME 256

#define MAX_PARAMETER_NAME 256
#define MAX_PARAMETER_VALUE 256

typedef struct session_info {
	char client_IP_port[32];
	char server_IP_port[32];
	char client_port[16];
	char server_port[16];
	char user[16];
}
SESSION_INFO;

void option_parser() {
	char *file_line = NULL;

	FILE *audit_file_append;
	FILE *session_file_append;
	char auditory_file_name_append[MAX_FILE_NAME] = "";
	char session_file_name_append[MAX_FILE_NAME] = "";
	char aud_file_name_append[MAX_FILE_NAME] = "";
	int nitems;

	char auditory_file_name[MAX_FILE_NAME] = "";
	char session_file_name[MAX_FILE_NAME] = "";
	char aud_file_name[MAX_FILE_NAME] = "";
	char file_name_remove[MAX_FILE_NAME] = "";
	char file_extension[32] = "";
	int count_file_name;
	int count_file_name_back;
	int count;

	if ((file_line = (char *) malloc((PAKSIZE + 1) * sizeof (char))) == NULL)
		ERROR_MESSAGE("file_line");

	count_file_name = count_file_radical("auditory", ".txt");
	count_file_name_back = count_file_radical("session", ".txt");
	if (count_file_name < count_file_name_back) {
		count_file_name = count_file_name_back;
	}
	//  count_file_name++;
	if (strcmp(append_files, "merge") == 0) {
		count_file_name++;
		// Open for read (will fail if file "auditory.txt" does not exist)
		strcpy(auditory_file_name_append, "auditory");
		strcpy(file_extension, ".txt");
		file_radical(auditory_file_name_append, file_extension, count_file_name);
		if ((audit_file_append = fopen(auditory_file_name_append, "a+")) == NULL)
			printf("The file '%s' was not opened\n", auditory_file_name_append);
		else
			printf("The file '%s' was opened\n", auditory_file_name_append);

		for (count = 0; count < count_file_name; count++) {
			// Open for read (will fail if file "auditory.txt" does not exist)
			strcpy(auditory_file_name, "auditory");
			strcpy(file_extension, ".txt");
			file_radical(auditory_file_name, file_extension, count);
			if ((audit_file = fopen(auditory_file_name, "rb")) == NULL)
				printf("The file '%s' was not opened\n", auditory_file_name);
			else
				printf("The file '%s' was opened\n", auditory_file_name);

			// Set pointer to beginning of file:
			fseek(audit_file, 0L, SEEK_SET);
			while (!feof(audit_file)) {
				nitems = fread(file_line, 1, PAKSIZE, audit_file);
				fwrite(file_line, 1, nitems, audit_file_append);
			}
			/* Close audit_file */
			if (fclose(audit_file))
				printf("The file '%s' was not closed", auditory_file_name);
			else
				printf("The file '%s' was closed\n", auditory_file_name);
		}
		/* Close audit_file */
		if (fclose(audit_file_append))
			printf("The file '%s' was not closed", auditory_file_name_append);
		else
			printf("The file '%s' was closed\n", auditory_file_name_append);

		// Open for read (will fail if file "session.txt" does not exist)
		strcpy(session_file_name_append, "session");
		strcpy(file_extension, ".txt");
		file_radical(session_file_name_append, file_extension, count_file_name);
		if ((session_file_append = fopen(session_file_name_append, "a+")) == NULL)
			printf("The file '%s' was not opened\n", session_file_name_append);
		else
			printf("The file '%s' was opened\n", session_file_name_append);

		for (count = 0; count < count_file_name; count++) {
			// Open for read (will fail if file "session.txt" does not exist)
			strcpy(session_file_name, "session");
			strcpy(file_extension, ".txt");
			file_radical(session_file_name, file_extension, count);
			if ((session_file = fopen(session_file_name, "rb")) == NULL)
				printf("The file '%s' was not opened\n", session_file_name);
			else
				printf("The file '%s' was opened\n", session_file_name);

			// Set pointer to beginning of file:
			fseek(session_file, 0L, SEEK_SET);
			while (!feof(session_file)) {
				nitems = fread(file_line, 1, PAKSIZE, session_file);
				fwrite(file_line, 1, nitems, session_file_append);
			}
			/* Close session_file */
			if (fclose(session_file))
				printf("The file '%s' was not closed", session_file_name);
			else
				printf("The file '%s' was closed\n", session_file_name);

		}
		/* Close session_file */
		if (fclose(session_file_append))
			printf("The file '%s' was not closed", session_file_name_append);
		else
			printf("The file '%s' was closed\n", session_file_name_append);

		//    count_file_name++;
	}

	if (strcmp(append_files, "all") == 0) {
		for (count = 0; count <= count_file_name; count++) {
			// Open for read (will fail if file "auditory.txt" does not exist)
			strcpy(auditory_file_name, "auditory");
			strcpy(file_extension, ".txt");
			file_radical(auditory_file_name, file_extension, count);
			if ((audit_file = fopen(auditory_file_name, "rb")) == NULL)
				printf("The file '%s' was not opened\n", auditory_file_name);
			else
				printf("The file '%s' was opened\n", auditory_file_name);

			// Open for read (will fail if file "session.txt" does not exist)
			strcpy(session_file_name, "session");
			strcpy(file_extension, ".txt");
			file_radical(session_file_name, file_extension, count);
			if ((session_file = fopen(session_file_name, "rb")) == NULL)
				printf("The file '%s' was not opened\n", session_file_name);
			else
				printf("The file '%s' was opened\n", session_file_name);

			// Open for write (will fail if file "session.txt" does not exist)
			strcpy(aud_file_name, "aud");
			strcpy(file_extension, ".txt");
			file_radical(aud_file_name, file_extension, count);
			if ((aud_file = fopen(aud_file_name, "w+")) == NULL)
				printf("The file '%s' was not opened\n", aud_file_name);
			else
				printf("The file '%s' was opened\n", aud_file_name);
			option_parser_files(auditory_file_name, session_file_name, aud_file_name);
		}
	}
	if ((strcmp(append_files, "last") == 0) || (strcmp(append_files, "merge") == 0)) {
		count = count_file_name;
		// Open for read (will fail if file "auditory.txt" does not exist)
		strcpy(auditory_file_name, "auditory");
		strcpy(file_extension, ".txt");
		file_radical(auditory_file_name, file_extension, count);
		if ((audit_file = fopen(auditory_file_name, "rb")) == NULL)
			printf("The file '%s' was not opened\n", auditory_file_name);
		else
			printf("The file '%s' was opened\n", auditory_file_name);

		// Open for read (will fail if file "session.txt" does not exist)
		strcpy(session_file_name, "session");
		strcpy(file_extension, ".txt");
		file_radical(session_file_name, file_extension, count);
		if ((session_file = fopen(session_file_name, "rb")) == NULL)
			printf("The file '%s' was not opened\n", session_file_name);
		else
			printf("The file '%s' was opened\n", session_file_name);

		// Open for write (will fail if file "session.txt" does not exist)
		strcpy(aud_file_name, "aud");
		strcpy(file_extension, ".txt");
		file_radical(aud_file_name, file_extension, count);
		if ((aud_file = fopen(aud_file_name, "w+")) == NULL)
			printf("The file '%s' was not opened\n", aud_file_name);
		else
			printf("The file '%s' was opened\n", aud_file_name);
		option_parser_files(auditory_file_name, session_file_name, aud_file_name);
	}
}

void option_parser_files(char *auditory_file_name, char *session_file_name, char *aud_file_name) {
	char *file_line = NULL;
	char *file_line2 = NULL;
	char parameter_name[MAX_PARAMETER_NAME];
	char parameter_name_new[MAX_PARAMETER_NAME];
	char parameter_value[MAX_PARAMETER_VALUE];
	int error;
	int skip_next;
	int new_session;

	char session_user[16];
	//  char session_terminal[16];
	char session_program[256];
	char session_SID[16];
	char session_Serial[16];
	char session_client_IP[16];
	char session_client_port[16];
	char session_client_IP_port[32];
	char session_server_IP[16];
	char session_server_port[16];
	char session_server_IP_port[32];
	char session_DB_name[32];
	char session_date[16];
	char session_time[16];
	char session_timestamp[32];

	char command_date[16];
	char command_time[16];
	char command_timestamp[32];

	long lSize, lSize_count, count;
	struct session_info *my_session_info = NULL;
	char * aud_file_count;
	FILE *aud_file2;
	int nitems;
	char aud_file_name2[256] = "";


	if ((file_line = (char *) malloc((PAKSIZE) * sizeof (char))) == NULL)
		ERROR_MESSAGE("file_line");
	if ((file_line2 = (char *) malloc((PAKSIZE) * sizeof (char))) == NULL)
		ERROR_MESSAGE("file_line2");

	if ((aud_file_count = (char *) malloc((32) * sizeof (char))) == NULL)
		ERROR_MESSAGE("aud_file_count");

	// obtain number of SQL commands
	lSize = 0;
	while (fscanf(session_file, "%s", parameter_name) != EOF) {
		if (strcmp((char *) parameter_name, start_session) == 0) lSize++;
	}

	if ((my_session_info = (struct session_info *) malloc(sizeof (struct session_info) *(lSize + 1))) == NULL) {
		ERROR_MESSAGE("my_session_info");
		exit(1);
	}
	lSize_count = 0;
	// Initialize the CRC table
	gen_crc_table();

	// Set pointer to beginning of file:
	fseek(session_file, 0L, SEEK_SET);

	new_session = 0;
	skip_next = 0;
	parameter_name_new[0] = 0;
	while (!feof(session_file)) {
		parameter_name[0] = 0;
		parameter_value[0] = 0;
		if (skip_next != 0) {
			strcpy(parameter_name, parameter_name_new);
		}

		if ((strcmp((char *) parameter_name, start_session) != 0) && (skip_next == 0)) {
			fscanf(session_file, "%s", parameter_name);
		}
		if (parameter_name[0] != 0) {

			if (strcmp((char *) parameter_name, start_session) == 0) {
				new_session = 0;
				fscanf(session_file, "%s", parameter_name);
			} else {
				if (strcmp((char *) parameter_name, end_session) == 0) {
					new_session = 1;
				}
			}
			if (new_session == 0) {
				fscanf(session_file, "%s", parameter_value);
				if (parameter_value[0] == 0) {
					printf("Parameter value error! Parameter '%s' does not have a value!", parameter_name);
					error = 1;
				} else {
					error = 0;
					skip_next = 0;
					if (strcmp((char *) parameter_name, "User:") == 0) {
						if (strcmp((char *) parameter_value, "Terminal:") == 0) {
							strcpy((char *) parameter_name_new, (char *) parameter_value);
							parameter_value[0] = 0;
							skip_next = 1;
						}
						strcpy((char *) session_user, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Terminal:") == 0) {
						if (strcmp((char *) parameter_value, "Program:") == 0) {
							strcpy((char *) parameter_name_new, (char *) parameter_value);
							parameter_value[0] = 0;
							skip_next = 1;
						}
						strcpy((char *) session_program, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Program:") == 0) {
						if (strcmp((char *) parameter_value, "SID:") == 0) {
							strcpy((char *) parameter_name_new, (char *) parameter_value);
							parameter_value[0] = 0;
							skip_next = 1;
						}
						strcpy((char *) session_program, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "SID:") == 0) {
						if (strcmp((char *) parameter_value, "Serial:") == 0) {
							strcpy((char *) parameter_name_new, (char *) parameter_value);
							parameter_value[0] = 0;
							skip_next = 1;
						}
						strcpy((char *) session_SID, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Serial:") == 0) {
						if (strcmp((char *) parameter_value, "Client_IP:") == 0) {
							strcpy((char *) parameter_name_new, (char *) parameter_value);
							parameter_value[0] = 0;
							skip_next = 1;
						}
						strcpy((char *) session_Serial, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Client_IP:") == 0) {
						strcpy((char *) session_client_IP, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Client_Port:") == 0) {
						strcpy((char *) session_client_port, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Server_IP:") == 0) {
						strcpy((char *) session_server_IP, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Server_Port:") == 0) {
						strcpy((char *) session_server_port, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "DB_Name:") == 0) {
						if (strcmp((char *) parameter_value, "Date_Time:") == 0) {
							strcpy((char *) parameter_name_new, (char *) parameter_value);
							parameter_value[0] = 0;
							skip_next = 1;
						}
						strcpy((char *) session_DB_name, (char *) parameter_value);
					} else if (strcmp((char *) parameter_name, "Date_Time:") == 0) {
						strcpy((char *) session_date, (char *) parameter_value);
						fscanf(session_file, "%s", parameter_value);
						strcpy((char *) session_time, (char *) parameter_value);
						sprintf((char *) session_timestamp, "%s %s", session_date, session_time);
						strcpy((char *) parameter_value, (char *) session_timestamp);
					} else if (strcmp((char *) parameter_name, "End") == 0) {
						fscanf(session_file, "%s", parameter_value);
						fscanf(session_file, "%s", parameter_value);
						fscanf(session_file, "%s", parameter_value);
						fscanf(session_file, "%s", parameter_value);
						fscanf(session_file, "%s", parameter_value);
						error = 1;
					} else {
						printf("Parameter name error! Parameter '%s' does not exist!", parameter_name);
						error = 1;
					}
				}
				if (error == 0) {
					//          printf("%s %s\n",parameter_name,parameter_value);
				}
			} else
				//new_session=1 => it just finished to process the header of a new session
			{
				sprintf((char *) session_client_IP_port, "%s:%s", session_client_IP, session_client_port);
				sprintf((char *) session_server_IP_port, "%s:%s", session_server_IP, session_server_port);
				strcpy(my_session_info[lSize_count].client_IP_port, session_client_IP_port);
				strcpy(my_session_info[lSize_count].server_IP_port, session_server_IP_port);
				strcpy(my_session_info[lSize_count].client_port, session_client_port);
				strcpy(my_session_info[lSize_count].server_port, session_server_port);
				strcpy(my_session_info[lSize_count].user, session_user);
				lSize_count++;
			}
		}
	}

	printf("Predicted number of sessions: %ld\n", lSize);
	printf("Actual number of correct sessions detected: %ld\n", lSize_count);
	/*
	for(count=0;count<lSize_count;count++)
	{
	//printf("%s <-> %s\n",my_session_info[count].client_IP_port,my_session_info[count].server_IP_port);
	strcpy(session_client_IP_port,my_session_info[count].client_IP_port);
	strcpy(session_server_IP_port,my_session_info[count].server_IP_port);
	printf("%s <-> %s\n",session_client_IP_port,session_server_IP_port);
	}
	exit(0);
	*/


	//        printf("%s\n",end_session);
	//fprintf(aud_file,"%s\n",start_session);
	// Set pointer to beginning of file:
	fseek(audit_file, 0L, SEEK_SET);
	fscanf(audit_file, "%s", file_line);
	while (!feof(audit_file)) {
		if (strcmp((char *) file_line, header) != 0) {
			if (fscanf(audit_file, "%s", file_line) == EOF) {
				//              ERROR_MESSAGE("EOF reached!");
				break;
			}
		}
		if (file_line[0] != 0) {
			if (strcmp((char *) file_line, header) == 0) {
				if (fscanf(audit_file, "%s", file_line) == EOF) {
					//                 ERROR_MESSAGE("EOF reached!");
					break;
				}
				fscanf(audit_file, "%s", file_line2);
				count = 0;
				strcpy(session_client_IP_port, my_session_info[count].client_IP_port);
				strcpy(session_server_IP_port, my_session_info[count].server_IP_port);
				strcpy(session_client_port, my_session_info[count].client_port);
				strcpy(session_server_port, my_session_info[count].server_port);
				strcpy(session_user, my_session_info[count].user);
				//         printf("A %s <-> %s\n",session_client_IP_port,session_server_IP_port);
				//         printf("B %s <-> %s\n",file_line,file_line2);
				while ((strcmp((char *) file_line2, session_client_IP_port) != 0) || (strcmp((char *) file_line, session_server_IP_port) != 0)) {
					count++;
					if (count >= lSize_count) break;
					// printf("%s <-> %s\n",session_client_IP_port,session_server_IP_port);

					//printf("count: %ld\n",count);
					strcpy(session_client_IP_port, my_session_info[count].client_IP_port);
					strcpy(session_server_IP_port, my_session_info[count].server_IP_port);
					strcpy(session_client_port, my_session_info[count].client_port);
					strcpy(session_server_port, my_session_info[count].server_port);
					strcpy(session_user, my_session_info[count].user);
				}
				//			  printf("file_line %s\n",file_line);
				//         printf("count: %ld\n",count);
				//         printf("lSize_count: %ld\n",lSize_count);
				if (count < lSize_count) {
					//           aud_file_count=int2string(count-1,10);
					//           printf("count-1: %ld aud_file_count: %s\n",count-1,aud_file_count);

					//it is the correct command in the auditory.txt file
					fscanf(audit_file, "%s", parameter_value);
					fscanf(audit_file, "%s", parameter_value);
					strcpy((char *) command_date, (char *) parameter_value);
					fscanf(audit_file, "%s", parameter_value);
					strcpy((char *) command_time, (char *) parameter_value);
					sprintf((char *) command_timestamp, "%s %s", command_date, command_time);
					fscanf(audit_file, "%s", file_line); //footer

					// Open for write (will fail if file "session.txt" does not exist)
					aud_file_count = int2string(count, 10);
					strcpy(aud_file_name2, aud_file_count);
					strcat(aud_file_name2, ".txt");
					if ((aud_file2 = fopen(aud_file_name2, "a")) == NULL)
						printf("The file '%s' was not opened\n", aud_file_name2);
					else {
						//            printf( "The file '%s' was opened\n",aud_file_name2);
						fprintf(aud_file2, "%s%s;%s;", session_client_port, session_server_port, session_user);
						file_command_parser(file_line, aud_file2);
						fprintf(aud_file2, ";%s\n", command_timestamp);
						/* Close audit_file */
						if (fclose(aud_file2)) {
							printf("The file '%s' was not closed", aud_file_name2);
						}
						/*          else
						{
						printf("The file '%s' was closed\n",aud_file_name);
						}*/
					}
				}
			}
		}
	}

	//  fflush(stdout);

	//  fflush(audit_file);


	for (count = 0; count < lSize_count; count++) {
		// Open for read (will fail if file "auditory.txt" does not exist)
		aud_file_count = int2string(count, 10);
		strcpy(aud_file_name2, aud_file_count);
		strcat(aud_file_name2, ".txt");
		if ((aud_file2 = fopen(aud_file_name2, "r")) != NULL) {
			//       printf( "The file '%s' was opened\n",aud_file_name);

			// Set pointer to beginning of file:
			fseek(aud_file2, 0L, SEEK_SET);
			while (!feof(aud_file2)) {
				nitems = fread(file_line, 1, PAKSIZE, aud_file2);
				fwrite(file_line, 1, nitems, aud_file);
			}
			// Close audit_file
			if (fclose(aud_file2))
				printf("The file '%s' was not closed", aud_file_name2);
			/*      else
			printf("The file '%s' was closed\n",aud_file_name);*/
			if (remove(aud_file_name2) == -1)
				printf("Error deleting file: %s\n", aud_file_name2);
			/*      else
			printf( "File %s successfully deleted\n",aud_file_name);*/
		}
	}





	/*
	//test parser
	strcpy(file_line,"SELECT CHAR_VALUE FROM SYSTEM.PRODUCT_PRIVS");
	printf("%s\n",line_parser(file_line));
	strcpy(file_line,"SELECT CHAR_VALUE FROM SYSTEM.PRODUCT_PRIVS WHERE   (UPPER('SQL*Plus') LIKE UPPER(PRODUCT)) AND   ((UPPER(USER) LIKE USERID) OR (USERID = 'PUBLIC')) AND   (UPPER(ATTRIBUTE) = 'ROLES')");
	printf("%s\n",line_parser(file_line));
	strcpy(file_line,"        SELECT CHAR_VALUE FROM SYSTEM.PRODUCT_PRIVS WHERE  x=(select * from cat  WHERE   (UPPER('SQL*Plus') LIKE UPPER(PRODUCT)) AND   ((UPPER(USER) LIKE USERID) OR (USERID = 'PUBLIC')) AND   (UPPER(ATTRIBUTE) = 'ROLES'))  ");
	printf("%s\n",line_parser(file_line));
	strcpy(file_line,"SELECT CHAR_VALUE FROM SYSTEM.PRODUCT_PRIVS WHERE  x=123.45+(select * 'teste de plicas' from cat)-123.45 ");
	printf("%s\n",line_parser(file_line));
	*/


	assert(file_line != NULL);
	if (file_line != NULL)
		free(file_line);
	file_line = NULL;

	/* Close audit_file */
	if (fclose(audit_file)) {
		printf("The file '%s' was not closed", auditory_file_name);
	} else {
		printf("The file '%s' was closed\n", auditory_file_name);
	}
	/* Close session_file */
	if (fclose(session_file)) {
		printf("The file '%s' was not closed", session_file_name);
	} else {
		printf("The file '%s' was closed\n", session_file_name);
	}
	/* Close aud_file */
	if (fclose(aud_file)) {
		printf("The file '%s' was not closed", aud_file_name);
	} else {
		printf("The file '%s' was closed\n", aud_file_name);
	}


	/*
	int ch;

	printf("\npress any key to end.");
	ch=getchar();
	*/
}

void file_command_parser(char * file_line, FILE * aud_file2) {
	int size;
	char command[MAX_COMMAND_SIZE] = {0};
	char f_word[32];
	int session_CRC32;

	fscanf(audit_file, "%s", file_line);
	while (!feof(audit_file) && (strcmp((char *) file_line, header) != 0)) {
		if (command[0] != '\0') {
			sprintf(command, "%s %s", command, file_line);
		} else {
			sprintf(command, "%s", file_line);
		}
		fscanf(audit_file, "%s", file_line);

	}
	file_line = line_parser(command);

	first_word((unsigned char *) file_line, f_word);
	fprintf(aud_file2, "%s;", f_word);
	fprintf(aud_file2, "%s;", file_line);
	size = 0;
	while (*(file_line + size) != 0) {
		size++;
	}
	session_CRC32 = update_crc(0xFFFFFFFF, (unsigned char *) file_line, size);
	//  fprintf(aud_file,"%08X",update_crc(-1, (unsigned char *)file_line, size));
	//in stead of sending a -1 we send a 0xFFFFFFFF that is the same. It is just for avoiding a warning
	fprintf(aud_file2, "%u", session_CRC32);
}

char * line_parser(char * file_line) {
	int size;
	int count;
	int pos;

	//size of file_line
	size = 0;
	while (*(file_line + size) != 0) {
		size++;
	}

	//remove text between '' and CR LF ; and numbers
	count = 0;

	do {
		//remove CR LF and ;
		if ((*(file_line + count) == 13) || (*(file_line + count) == 10) || (*(file_line + count) == ';')) {
			*(file_line + count) = ' ';
		}
		count++;
	} while (count < size);

	count = 0;
	do {
		{
			//remove text between ''
			if (*(file_line + count) == '\'') {
				count++;
				if (count == size) {
					break;
				}
				while (*(file_line + count) != '\'' && count < size) {
					*(file_line + count) = ' ';
					count++;
					if (count == size) {
						break;
					}
				}
				if (count == size) {
					break;
				}
			} else {
				//remove numbers
				if (((*(file_line + count) >= '0') && (*(file_line + count) <= '9') && !((*(file_line + count - 1) >= 'a' && *(file_line + count - 1) <= 'z') || (*(file_line + count - 1) >= 'A' && *(file_line + count - 1) <= 'Z')))
					|| ((*(file_line + count) == '-' || *(file_line + count) == '+' || *(file_line + count) == '*' || *(file_line + count) == '/' || *(file_line + count) == '.' || *(file_line + count) == ',') && (*(file_line + count + 1) >= '0') && (*(file_line + count + 1) <= '9'))) {
						while ((((*(file_line + count) >= '0') && (*(file_line + count) <= '9'))
							|| ((*(file_line + count) == '-' || *(file_line + count) == '.'))) && (count < size)) {
								*(file_line + count) = ' ';
								count++;
								if (count == size) {
									break;
								}
							}

					}
			}
		}
		count++;
	} while (count < size);


	//size of file_line
	size = 0;
	while (*(file_line + size) != 0) {
		size++;
	}
	//remove extra spaces and TABs and output lowercase
	pos = 0;
	count = 0;
	do {
		if (*(file_line + count) == '\t') *(file_line + count) = ' ';
		if (*(file_line + count) == ' ') {
			//if it is not the initial space
			if (count > 0) {
				*(file_line + pos) = *(file_line + count);
				pos++;
			}
			while ((*(file_line + count) == ' ' || *(file_line + count) == '\t') && count < size) {
				count++;
			}
		}
		/*
		//for uppercase
		if ((*(file_line+count)>='a') && (*(file_line+count)<='z'))
		{
		*(file_line+pos)=*(file_line+count)-32;
		}
		*/
		//for lowercase
		if ((*(file_line + count) >= 'A') && (*(file_line + count) <= 'Z')) {
			*(file_line + pos) = *(file_line + count) + 32;
		} else {
			*(file_line + pos) = *(file_line + count);
		}
		pos++;
		count++;
	} while (count < size);

	if ((*(file_line + pos - 2) == ' ') && (*(file_line + pos - 1) == '\0')) {
		*(file_line + pos - 2) = '\0';
	}

	for (count = pos; count < size; count++) {
		*(file_line + pos) = '\0';
	}

	return (file_line);
	//  return command_parser(file_line);
}

char * line_parser_old(char * file_line) {
	int size;
	int count;
	int pos;

	//size of file_line
	size = 0;
	while (*(file_line + size) != 0) {
		size++;
	}

	//remove text between '' and CR LF ; and numbers
	count = 0;

	do {
		//remove CR LF and ;
		if ((*(file_line + count) == 13) || (*(file_line + count) == 10) || (*(file_line + count) == ';')) {
			*(file_line + count) = ' ';
		}
		count++;
	} while (count < size);

	count = 0;
	do {
		{
			//remove text between ''
			if (*(file_line + count) == '\'') {
				//a linha seguinte estava a dar uns erros
				*(file_line + count) = ' ';
				count++;
				if (count == size) {
					break;
				}
				while (*(file_line + count) != '\'' && count < size) {
					*(file_line + count) = ' ';
					count++;
					if (count == size) {
						break;
					}
				}
				//a linha seguinte estava a dar uns erros
				*(file_line + count) = ' ';

				//        count++;
				if (count == size) {
					break;
				}
			} else {
				//remove numbers
				if (((*(file_line + count) >= '0') && (*(file_line + count) <= '9') && !((*(file_line + count - 1) >= 'a' && *(file_line + count - 1) <= 'z') || (*(file_line + count - 1) >= 'A' && *(file_line + count - 1) <= 'Z')))
					|| ((*(file_line + count) == '-' || *(file_line + count) == '+' || *(file_line + count) == '*' || *(file_line + count) == '/' || *(file_line + count) == '.' || *(file_line + count) == ',') && (*(file_line + count + 1) >= '0') && (*(file_line + count + 1) <= '9'))) {
						while ((((*(file_line + count) >= '0') && (*(file_line + count) <= '9'))
							|| ((*(file_line + count) == '-' || *(file_line + count) == '.' || *(file_line + count) == ','))) && (count < size)) {
								*(file_line + count) = ' ';
								count++;
								if (count == size) {
									break;
								}
							}

					}
			}
		}
		count++;
	} while (count < size);


	//size of file_line
	size = 0;
	while (*(file_line + size) != 0) {
		size++;
	}
	//remove extra spaces and output lowercase
	pos = 0;
	count = 0;
	do {
		if (*(file_line + count) == ' ') {
			//if it is not the initial space
			if (count > 0) {
				*(file_line + pos) = *(file_line + count);
				pos++;
			}
			while (*(file_line + count) == ' ' && count < size) {
				count++;
			}
		}
		/*
		//for uppercase
		if ((*(file_line+count)>='a') && (*(file_line+count)<='z'))
		{
		*(file_line+pos)=*(file_line+count)-32;
		}
		*/
		//for lowercase
		if ((*(file_line + count) >= 'A') && (*(file_line + count) <= 'Z')) {
			*(file_line + pos) = *(file_line + count) + 32;
		} else {
			*(file_line + pos) = *(file_line + count);
		}
		pos++;
		count++;
	} while (count < size);
	if (*(file_line + pos - 2) == ' ') {
		*(file_line + pos - 2) = '\0';
	}
	for (count = pos; count < size; count++) {
		*(file_line + pos) = '\0';
	}

	return (file_line);
	//  return command_parser(file_line);
}

char * command_parser(char * file_line) {
	char *line;
	char *file_line_new;
	int search_pointer;
	int search_pointer2;
	int search_pointer3;
	int size;
	int file_line_size;
	int count;
	unsigned int count_brackets;
	int initial_bracket;
	int final_bracket;

	if ((file_line_new = (char *) malloc(1024)) == NULL) {
		ERROR_MESSAGE("parser.h: file_line_new");
		exit(1);
	}


	file_line_size = 0;
	while (*(file_line + file_line_size) != 0) {
		file_line_size++;
	}

	//  printf("str_find_unsensitive2_in_block: %s\n <-> %i\n",file_line,str_find_unsensitive2_in_block((unsigned char *)file_line,"where"));
	//  return(block_parser(file_line,"where", 'n'));


	search_pointer = str_find_unsensitive2_in_block((unsigned char *) file_line, "where");
	if (search_pointer != -1) {
		search_pointer2 = find_next_block(file_line, "where");
		search_pointer3 = str_find_unsensitive2((unsigned char *) (file_line + search_pointer), "select");
		if (search_pointer3 != -1) {
			search_pointer3 += search_pointer;
			printf("Ola %i %i %i\n", search_pointer, search_pointer2, search_pointer3);
			if (search_pointer3 < search_pointer2) {
				//search the previous '('
				count = search_pointer3;
				do {
					if (*(file_line + count) == '(') {
						break;
					}
					count--;
				} while (count > search_pointer);
				initial_bracket = count;

				//search the corresponding ')'
				do {
					count_brackets = 0;

					if (*(file_line + count) == '(') {
						count_brackets++;
					}

					if (*(file_line + count) == ')') {
						count_brackets--;
						if (count_brackets == 0) {
							break;
						}
					}
					count++;
				} while (count < search_pointer2);
				final_bracket = count;

				printf("%i %i %i\n", initial_bracket, final_bracket, file_line_size);


				//copy the select clause to line
				if ((line = (char *) malloc(final_bracket - initial_bracket + 1)) == NULL) {
					ERROR_MESSAGE("learner.h: line");
					exit(1);
				}
				for (count = initial_bracket; count < final_bracket + 1; count++) {
					*(line + count - initial_bracket) = *(file_line + initial_bracket + count);
				}
				*(line + count) = '\0';
				//parse the select clause
				printf("line1: %s\n", line);
				line = command_parser(line);

				printf("line2: %s\n", line);
				//we can erase from 'where' to the next_block
				for (count = search_pointer + sizeof ("where") - 1; count < search_pointer2; count++) {
					*(file_line + count) = 'X';
				}

				size = 0;
				while (*(line + size) != 0) {
					size++;
				}

				//copy the line to the file_line
				for (count = 0; count < size; count++) {
					*(file_line + initial_bracket + count) = *(line + count);
				}
				free(line);
			} else {
				//we can erase from 'where' to the next block
				for (count = search_pointer + sizeof ("where") - 1; count < search_pointer2 - 1; count++) {
					*(file_line + count) = ' ';
				}
			}
		}
	}
	return (file_line);


	/*
	char file_line_new_end_pointer=0;
	int line_pointer=0;

	// **************************************************************************************************
	//from
	// **************************************************************************************************
	search_pointer=str_find_unsensitive2((unsigned char *)(file_line),"from");
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"where");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"group by");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"union");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"intersect");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"minus");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"order by");
	}
	}
	}
	}
	}
	if (search_pointer2==-1)
	{
	search_pointer2=file_line_size;
	}
	if(line=(char *)malloc(search_pointer2-search_pointer+1))==NULL)
	{
	ERROR_MESSAGE("learner.h: line");
	exit (1);
	}
	for (count=0;count<search_pointer2-search_pointer;count++)
	{
	*(line+count)=*(file_line+search_pointer+count);
	}
	*(line+count)='\0';

	line=block_parser(line,"from",'n');

	size_block_name=sizeof("from");

	//copy file_line before the end of the word 'from' to file_line_new
	for (count=0;count<search_pointer+size_block_name;count++)
	{
	*(file_line_new+count)=*(file_line+count);
	}
	*(file_line_new+count)=' ';

	//concat file_line_new with line
	count=0;
	while (*(line+count)!=0)
	{
	*(file_line_new+search_pointer+size_block_name+1+count)=*(line+count);
	count++;
	}
	file_line_new_end_pointer=search_pointer+size_block_name+1+count;
	free(line);

	// **************************************************************************************************
	//where
	// **************************************************************************************************
	search_pointer=str_find_unsensitive2((unsigned char *)(file_line),"where");
	if (search_pointer!=-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"group by");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"union");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"intersect");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"minus");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"order by");
	}
	}
	}
	}
	if (search_pointer2==-1)
	{
	search_pointer2=file_line_size;
	}
	if(line=(char *)malloc(search_pointer2-search_pointer+1))==NULL)
	{
	ERROR_MESSAGE("learner.h: line");
	exit (1);
	}
	for (count=0;count<search_pointer2-search_pointer;count++)
	{
	*(line+count)=*(file_line+search_pointer+count);
	}
	*(line+count)='\0';

	line=block_parser(line,"where",'y');

	size_block_name=sizeof("where");

	//copy file_line before the end of the word 'where' to file_line_new
	for (count=0;count<search_pointer+size_block_name;count++)
	{
	*(file_line_new+file_line_new_end_pointer+count)=*(file_line+count);
	}
	*(file_line_new+file_line_new_end_pointer+count)=' ';

	//concat file_line_new with line
	count=0;
	while (*(line+count)!=0)
	{
	*(file_line_new+file_line_new_end_pointer+search_pointer+size_block_name+1+count)=*(line+count);
	count++;
	}
	file_line_new_end_pointer=file_line_new_end_pointer+search_pointer+size_block_name+1+count;
	free(line);
	}

	// **************************************************************************************************
	//group by
	// **************************************************************************************************
	search_pointer=str_find_unsensitive2((unsigned char *)(file_line),"group by");
	if (search_pointer!=-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"union");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"intersect");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"minus");
	if (search_pointer2==-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"order by");
	}
	}
	}
	if (search_pointer2==-1)
	{
	search_pointer2=file_line_size;
	}
	for (count=0;count<search_pointer2-search_pointer;count++)
	{
	*(file_line_new+file_line_new_end_pointer+count)=*(file_line+search_pointer+count);
	}
	*(line+count)='\0';
	}


	// **************************************************************************************************
	//UNION, INTERCECT, MINUS
	// **************************************************************************************************
	search_pointer=str_find_unsensitive2((unsigned char *)(file_line),"union");
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"intersect");
	if ((search_pointer2<search_pointer) && (search_pointer2>0))
	{
	search_pointer=search_pointer2;
	}
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"minus");
	if ((search_pointer2<search_pointer) && (search_pointer2>0))
	{
	search_pointer=search_pointer2;
	}
	if (search_pointer!=-1)
	{
	search_pointer2=str_find_unsensitive2((unsigned char *)(file_line+search_pointer),"order by");
	if (search_pointer2==-1)
	{
	search_pointer2=file_line_size;
	}
	if(line=(char *)malloc(search_pointer2-search_pointer+1))==NULL)
	{
	ERROR_MESSAGE("learner.h: line");
	exit (1);
	}
	for (count=0;count<search_pointer2-search_pointer;count++)
	{
	*(line+count)=*(file_line+search_pointer+count);
	}
	*(line+count)='\0';

	line=block_parser(line,"where",'y');

	size_block_name=sizeof("where");

	//copy file_line before the end of the word 'where' to file_line_new
	for (count=0;count<search_pointer+size_block_name;count++)
	{
	*(file_line_new+file_line_new_end_pointer+count)=*(file_line+count);
	}
	*(file_line_new+file_line_new_end_pointer+count)=' ';

	//concat file_line_new with line
	count=0;
	while (*(line+count)!=0)
	{
	*(file_line_new+file_line_new_end_pointer+search_pointer+size_block_name+1+count)=*(line+count);
	count++;
	}
	file_line_new_end_pointer=file_line_new_end_pointer+search_pointer+size_block_name+1+count;
	free(line);
	}

	return file_line_new;
	*/
}

char * block_parser(char * file_line, char * block, char keep) {
	char *line;
	int count;
	int line_pointer = 0;
	int search_pointer_where;
	int search_pointer;
	int file_line_size;
	int aux;

	file_line_size = 0;
	while (*(file_line + file_line_size) != 0) {
		file_line_size++;
	}

	search_pointer_where = str_find_unsensitive2((unsigned char *) (file_line + line_pointer), block);
	//if there are no more WHERE statements
	if (search_pointer_where == -1) {
		return file_line;
	}//if there are WHERE statements
	else {
		search_pointer = str_find_unsensitive2((unsigned char *) (file_line + search_pointer_where + 5), "select");
		//if there are no more SELECT statements
		if (search_pointer == -1) {
			for (count = search_pointer_where + 5; count < file_line_size - 1; count++) {
				*(file_line + count) = '\0';
			}
			return file_line;
		}//if there are more SELECT statements
		else {
			//a select has allways a '(' before therefore we need to search for the corresponding ')'
			aux = 1;
			for (count = search_pointer + search_pointer_where + 5; count < file_line_size; count++) {
				if (*(file_line + count) == '(') {
					aux++;
				} else {
					if (*(file_line + count) == ')') {
						aux--;
						if (aux == 0) {
							break;
						}
					}
				}
			}
			aux = count;
			if ((line = (char *) malloc(aux - search_pointer - search_pointer_where - 5 + 1)) == NULL) {
				ERROR_MESSAGE("learner.h: line");
				exit(1);
			}
			for (count = 0; count < aux - search_pointer - search_pointer_where - 5; count++) {
				*(line + count) = *(file_line + search_pointer_where + search_pointer + 5 + count);
			}
			*(line + count) = '\0';
			//recursivelly call command_parser
			line = command_parser(line);

			*(file_line + search_pointer_where + 5) = ' ';
			//clean the rest of file_line
			for (count = search_pointer_where + 5 + 1; count < file_line_size - 1; count++) {
				*(file_line + count) = '\0';
			}

			//concat file_line with line
			count = 0;
			while (*(line + count) != 0) {
				*(file_line + search_pointer_where + 5 + 1 + count) = *(line + count);
				count++;
			}
			free(line);

			return file_line;
		}
	}
}

int find_next_block(char * file_line, char * block) {
	char *file_line_new;
	int search_pointer = 0;
	int file_line_size;

	if ((file_line_new = (char *) malloc(1024)) == NULL) {
		ERROR_MESSAGE("learner.h: file_line_new");
		exit(1);
	}

	file_line_size = 0;
	while (*(file_line + file_line_size) != 0) {
		file_line_size++;
	}


	if (strcmp(block, "order by") == 0) {
		return (file_line_size);
	}
	if ((strcmp(block, "minus") == 0) || (strcmp(block, "intersect") == 0) || (strcmp(block, "union") == 0)) {
		search_pointer = str_find_unsensitive2_in_block((unsigned char *) (file_line + search_pointer), "order by");
		if (search_pointer == -1) {
			return (file_line_size);
		} else {
			return (search_pointer);
		}
	}

	if ((strcmp(block, "group by") == 0)) {
		search_pointer = str_find_unsensitive2_in_block((unsigned char *) (file_line + search_pointer), "union");
		if (search_pointer == -1) {
			search_pointer = str_find_unsensitive2_in_block((unsigned char *) (file_line + search_pointer), "intersect");
			if (search_pointer == -1) {
				search_pointer = str_find_unsensitive2_in_block((unsigned char *) (file_line + search_pointer), "minus");
			}
		}
		if (search_pointer == -1) {
			return (find_next_block(file_line, "union"));
		} else {
			return (search_pointer);
		}
	}

	if ((strcmp(block, "where") == 0)) {
		search_pointer = str_find_unsensitive2_in_block((unsigned char *) (file_line + search_pointer), "group by");
		if (search_pointer == -1) {
			return (find_next_block(file_line, "group by"));
		} else {
			return (search_pointer);
		}
	}

	if ((strcmp(block, "from") == 0)) {
		search_pointer = str_find_unsensitive2_in_block((unsigned char *) (file_line + search_pointer), "where");
		if (search_pointer == -1) {
			return (find_next_block(file_line, "where"));
		} else {
			return (search_pointer);
		}
	}

	return -1;
}

void first_word(unsigned char *main_string, char * f_word) {
	int count;

	count = 0;
	while ((*(main_string + count) != 0) && ((*(main_string + count) >= 'a' && *(main_string + count) <= 'z') || (*(main_string + count) >= 'A' && *(main_string + count) <= 'Z'))) {
		f_word[count] = *(main_string + count);
		count++;
	}
	f_word[count] = '\0';
}

int str_find_unsensitive2_in_block(unsigned char *main_string, char *search_string) {
	unsigned int i;
	unsigned int j;
	unsigned int count_brackets;
	unsigned int match;
	unsigned int main_length;
	unsigned int search_length;

	main_length = 0;
	while (*(main_string + main_length) != 0) {
		main_length++;
	}

	search_length = 0;
	while (*(search_string + search_length) != 0) {
		search_length++;
	}

	if (main_length > 1 && search_length > 1 && main_length > search_length) {
		i = 0;
		j = 0;
		do {
			if (*(main_string + i) == '(') {
				count_brackets = 1;
				do {
					if (*(main_string + i) == '(') {
						count_brackets++;
					}
					if (*(main_string + i) == ')') {
						count_brackets--;
						if (count_brackets == 0) {
							break;
						}
					}
					i++;
				} while (i + search_length < main_length);
				if (i + search_length >= main_length) {
					match = 0;
					break;
				}
				i++;
			}
			match = 0;
			for (j = 0; j < search_length - 1; j++) {
				if ((*(main_string + j + i) == *(search_string + j))
					|| ((*(main_string + j + i) == *(search_string + j) + 32) && *(search_string + j) >= 65 && *(search_string + j) <= 90)
					|| (*(main_string + j + i) + 32 == *(search_string + j) && *(main_string + j + i) >= 65 && *(main_string + j + i) <= 90)) {
						match = 1;
					} else {
						match = 0;
						break;
					}
			}
			i++;
		} while ((match == 0) && (i + search_length < main_length));
		if (match != 0)
			return (--i);
		else
			return (-1);
	} else
		return (-1);
}

