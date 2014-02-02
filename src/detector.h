//detector functions

//transaction_type defines
#define GOOD_TRANSACTION 0
#define MALICIOUS_TRANSACTION 1
#define ANTICIPATED_TRANSACTION 2
#define DELAYED_TRANSACTION 3

void option_detector(void);
int read_next_command(char * parameter_value,int * next_command,int start);
int read_command_int(char * parameter_value,int & command_int,int start);
int read_command_char(char * parameter_value,char * command_char,int start);
void sigint_detector(int signum);

#define MAX_NUM_SESSION_PROFILES_DETECTED 64

struct session_profile
{
	int session_ID;
	profile *profiles[MAX_NUM_SESSION_PROFILES_DETECTED];//definition in learner.h
	int row_ID[MAX_NUM_SESSION_PROFILES_DETECTED];
	char timestamp[32];
	int LastProfileName;
	int session_Transaction_ID;
};

void option_detector()
{
	unsigned int transactions_temp_index=0;
	struct transaction *transactions=NULL;
	//  struct profile profiles[MAX_NUM_TRANSACTIONS]={0};
	struct profile *profiles=NULL;
	//  struct user users[MAX_NUM_USERS_TRANSACTIONS]={0};
	struct user *users=NULL;
	//  struct session_profile session_profiles[MAX_NUM_USERS_TRANSACTIONS]={0};
	struct session_profile *session_profiles=NULL;
	struct session_profile session_profiles_aux={0};
	//  struct computed_profile_sequence computed_profile_sequences[MAX_NUM_PROFILE_SEQUENCES]={0};
	struct computed_profile_sequence *computed_profile_sequences=NULL;


	int i;
	int j;
	//  char file_line[MAX_FILE_LINE_LENGTH];
	char *file_line;
	char *file_line_pointer=NULL;
	//  char parameter_value[MAX_COMMAND_LENGTH];
	char *parameter_value=NULL;
	int count;
	int i_next_command;
	int session_profiles_aux_index;

	int FlagNewTransaction=0;

	char record_aux[4096];

	int session_ID;
	int session_old_ID;
	char session_user[16];
	int command_code=-1;
	char session_command_type[16];
	int session_CRC32;
	char session_timestamp[32];
	int session_Transaction_ID=0;
	int session_old_Transaction_ID;
	int MyTransactionName=0;
	int LastTransactionName=0;

	char session_old_timestamp[32]="";
	char delta_timestamp[32]={0};

	int transaction_type;
	int transaction_old_type=-99;
	int size;
	int next_command_row_ID;
	int max_profile_sequences;

	int  *commands_crc32=NULL;				//crc32 of the command text
	int max_commands_crc32;

	int test;

	if((profiles=(struct profile *)malloc((MAX_NUM_TRANSACTIONS)*sizeof(struct profile)))==NULL)
		ERROR_MESSAGE("profiles");
	if((users=(struct user *)malloc((MAX_NUM_USERS_TRANSACTIONS)*sizeof(struct user)))==NULL)
		ERROR_MESSAGE("users");
	if((session_profiles=(struct session_profile *)malloc((MAX_NUM_USERS_TRANSACTIONS)*sizeof(struct session_profile)))==NULL)
		ERROR_MESSAGE("session_profiles");
	if((computed_profile_sequences=(struct computed_profile_sequence *)malloc((MAX_NUM_PROFILE_SEQUENCES)*sizeof(struct computed_profile_sequence)))==NULL)
		ERROR_MESSAGE("computed_profile_sequences");
	if((commands_crc32=(int *)malloc((MAX_NUM_COMMANDS)*sizeof(int)))==NULL)
		ERROR_MESSAGE("commands");

	if((file_line=(char *)malloc((MAX_FILE_LINE_LENGTH)*sizeof(char)))==NULL)
		ERROR_MESSAGE("file_line");
	if((parameter_value=(char *)malloc((MAX_COMMAND_LENGTH)*sizeof(char)))==NULL)
		ERROR_MESSAGE("parameter_value");

	for(count=0;count<MAX_NUM_TRANSACTIONS;count++)
	{
		profiles[count].name=-1;
		profiles[count].count=0;
		profiles[count].num_commands=0;
		profiles[count].tc=NULL;
	}
	for(count=0;count<MAX_NUM_USERS_TRANSACTIONS;count++)
	{
		users[count].profile_name=-1;
		users[count].profile_user[0]='\0';
	}
	for(count=0;count<MAX_NUM_USERS_TRANSACTIONS;count++)
	{
		session_profiles[count].session_ID=-1;
		session_profiles[count].timestamp[0]='\0';
		session_profiles[count].LastProfileName=-1;
		session_profiles[count].session_Transaction_ID=9999;

		for(i=0;i<MAX_NUM_SESSION_PROFILES_DETECTED;i++)
		{
			session_profiles[count].profiles[i]=NULL;
			session_profiles[count].row_ID[i]=-1;
		}
	}
	for(count=0;count<MAX_NUM_PROFILE_SEQUENCES;count++)
	{
		computed_profile_sequences[count].from_transaction_name=-1;
		computed_profile_sequences[count].to_transaction_name=-1;
		computed_profile_sequences[count].percentage=-1;
	}
	file_line[0]='\0';
	parameter_value[0]='\0';

	// Open for read (will fail if file "session.txt" does not exist)
	if( (profile_file  = fopen( "profile.txt", "r" )) == NULL )
		ERROR_MESSAGE( "The file 'profile.txt' was not opened" );
	else
		printf( "The file 'profile.txt' was opened\n" );

	// Open for read (will fail if file "prof_seq2.txt" does not exist)
	if( (profile_seq_file  = fopen( "prof_seq2.txt", "r" )) == NULL )
		ERROR_MESSAGE( "The file 'prof_seq2.txt' was not opened" );
	else
		printf( "The file 'prof_seq2.txt' was opened\n" );

	// Open for write (will fail if file "detect_debug.txt" does not exist)
	if( (detect_debug_file= fopen( "detector_debug.txt", "w+" )) == NULL )
		ERROR_MESSAGE( "The file 'detector_debug.txt' was not opened" );
	else
		printf( "The file 'detector_debug.txt' was opened\n" );

	// Open for write (will fail if file "delay_debug.txt" does not exist)
	if( (delay_debug_file  = fopen( "detector_delay_debug.txt", "w+" )) == NULL )
		ERROR_MESSAGE( "The file 'detector_delay_debug.txt' was not opened" );
	else
		printf( "The file 'detector_delay_debug.txt' was opened\n" );

	// Open for read (will fail if file "command.txt" does not exist)
	if( (command_file  = fopen( "command.txt", "r" )) == NULL )
		printf( "The file 'command.txt' was not opened\n");
	else
		printf( "The file 'command.txt' was opened\n");

	fflush(stdout);

	// Initialize the CRC table
	gen_crc_table();


	// Set pointer to beginning of file:
	fseek(profile_seq_file, 0L, SEEK_SET );

	i=0;
	while (!feof(profile_seq_file))
	{
		//    fscanf(profile_seq_file,"%s",record_aux);
		read_record(profile_seq_file,record_aux);
		computed_profile_sequences[i].from_transaction_name=atoi(record_aux);
		//    fscanf(profile_seq_file,"%s",record_aux);
		read_record(profile_seq_file,record_aux);
		computed_profile_sequences[i].to_transaction_name=atoi(record_aux);
		//    fscanf(profile_seq_file,"%s",record_aux);
		read_record(profile_seq_file,record_aux);
		computed_profile_sequences[i].percentage=atoi(record_aux);
		i++;
		assert(i<=MAX_NUM_PROFILE_SEQUENCES);
	}
	max_profile_sequences=--i;
	// Set pointer to beginning of file:
	fseek(profile_file, 0L, SEEK_SET );

	i=0;
	j=0;
	fscanf(profile_file,"%s",record_aux);
	while (!feof(profile_file ))
	{
		if(strcmp(record_aux,"profile_name:")==0)
		{
			fscanf(profile_file,"%s",record_aux);
			MyTransactionName=atoi(record_aux);
			profiles[i].name=MyTransactionName;
		}
		fscanf(profile_file,"%s",record_aux);
		if(strcmp(record_aux,"profile_count:")==0)
		{
			fscanf(profile_file,"%s",record_aux);
			//      profiles[i].count=atoi(record_aux);
			profiles[i].count=0;
		}
		fscanf(profile_file,"%s",record_aux);
		if(strcmp(record_aux,"num_commands:")==0)
		{
			fscanf(profile_file,"%s",record_aux);
			transactions_temp_index=atoi(record_aux);
			profiles[i].num_commands=transactions_temp_index;
		}
		fscanf(profile_file,"%s",record_aux);
		while (strcmp(record_aux,"profile_user:")==0)
		{
			users[j].profile_name=MyTransactionName;
			fscanf(profile_file,"%s",record_aux);
			strcpy(users[j].profile_user,record_aux);
			j++;
			assert(j<MAX_NUM_USERS_TRANSACTIONS);
			fscanf(profile_file,"%s",record_aux);
		}
		if((transactions=(struct transaction *)malloc((transactions_temp_index)*sizeof(struct transaction)))==NULL)
		{
			ERROR_MESSAGE("transactions");
		}
		//assign the new transaction to the profiles
		profiles[MyTransactionName].tc=transactions;
		for(count=0;count<(int)transactions_temp_index;count++)
		{
			for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
			{
				transactions[count].next_command[i_next_command]=-1;
			}
		}
		for(count=0;count<(int)transactions_temp_index;count++)
		{
			i_next_command=0;
			i_next_command=read_command_int(record_aux,transactions[count].row_ID,i_next_command);
			i_next_command=read_command_int(record_aux,transactions[count].command_code,i_next_command);
			i_next_command=read_command_int(record_aux,(int &)transactions[count].CRC32,i_next_command);
			i_next_command=read_next_command(record_aux,transactions[count].next_command,i_next_command);
			i_next_command=read_command_char(record_aux,transactions[count].min_timestamp,i_next_command);
			i_next_command=read_command_char(record_aux,transactions[count].max_timestamp,i_next_command);
			fscanf(profile_file,"%s",record_aux);
		}
		i++;
	}
	LastTransactionName=++MyTransactionName;

	/*
	for(i=0;i<MAX_NUM_TRANSACTIONS;i++)
	{
	if(profiles[i].num_commands!=0)
	{
	printf("\nprofile_name: %u\n",profiles[i].name);
	printf("profile_count: %u\n",profiles[i].count);
	printf("num_commands: %u\n",profiles[i].num_commands);
	for(j=0;j<MAX_NUM_TRANSACTIONS;j++)
	{
	if ((users[j].profile_name==profiles[i].name) && (users[j].profile_user[0]!='\0'))
	{
	printf("profile_user: %s\n",users[j].profile_user);
	}
	}
	transactions=profiles[i].tc;
	for(j=0;j<(int)profiles[i].num_commands;j++)
	{
	printf("\t%i;%i;%u;<",transactions[j].row_ID,transactions[j].command_code,transactions[j].CRC32);

	i_next_command=0;
	while ((transactions[j].next_command[i_next_command]>=0) && (i_next_command<MAX_NUM_NEXT_COMMANDS-1))
	{
	if (i_next_command>0)
	{
	printf(",");
	}
	printf("%i",transactions[j].next_command[i_next_command]);
	i_next_command++;
	}

	printf(">;%s;%s\n",transactions[j].min_timestamp,transactions[j].max_timestamp);
	}
	}
	}
	*/

	for(count=0;count<MAX_NUM_USERS_TRANSACTIONS;count++)
	{
		session_profiles[count].session_ID=-1;
		session_profiles[count].timestamp[0]='\0';
		session_profiles[count].LastProfileName=-1;
		session_profiles[count].session_Transaction_ID=9999;

		for(i=0;i<MAX_NUM_SESSION_PROFILES_DETECTED;i++)
		{
			session_profiles[count].profiles[i]=0;
			session_profiles[count].row_ID[i]=-1;
		}
	}

	// Set pointer to beginning of file:
	fseek(command_file, 0L, SEEK_SET );

	i=0;
	while (!feof(command_file))
	{
		//    fscanf(profile_seq_file,"%s",record_aux);
		read_record(command_file,record_aux); //it is the sequence number of the command, but we do not use it here
		read_record(command_file,record_aux); //it is the CRC32 of the command
		string2int(record_aux,commands_crc32[i]);
		read_record(command_file,record_aux); //it is the command text, but we do not use it here
		read_record(command_file,record_aux); //it is the command text, but we do not use it here
		i++;
		assert(i<=MAX_NUM_COMMANDS);
	}
	max_commands_crc32=--i;


	//start: sniffer section

	struct transaction_packet *trans_packet;
	int new_packet;
	char RecvBuf[PAKSIZE] = {0};
	char RecvBufSplit[PAKSIZE] = {0};
	int packet_type;
	char timestamp[32];
	int pCount=0;
	char command[MAX_COMMAND_SIZE] = {0};

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

	fprintf(delay_debug_file,"delta_process_timestamp delta_recv_timestamp\n\n");

	// open raw socket, set promiscuous mode
	init_net();
#ifndef WIN32
	signal(SIGINT,sigint_detector);
#endif
	test=0;
	while(1)
	{
		if (TARGET_DB_Oracle == 1) {
			new_packet = is_oracle_packet(RecvBuf, trans_packet); // Listens the socket and returns an Oracle packet
			test=1;
		}
		if (TARGET_DB_MySQL == 1) {
			new_packet = is_mysql_packet(RecvBuf, trans_packet); // Listens the socket and returns an MySQL packet
			//TODO for some strange reason there is a repetition of every packet. So we jump one packet every two packets
			if (test==0){
				test=1;
			} else{
				test=0;
			}
		}
		if (new_packet == 1 && test==1) {
			/*
			if(port_to_be_killed==sport && pTcpheader->Flags != TH_RST)
			{
			kill_session();
			transaction_type=GOOD_TRANSACTION;
			}
			*/
			pCount++;
			packet_type=process_packet(trans_packet,RecvBufSplit,session_timestamp);//Processes the packet looking for the start of sessions, end of sessions and SQL commands. Returns the command type
			if (packet_type!=NO_PACKET_TYPE)
			{
				if (packet_type==START_SESSION_TYPE)
				{
					//create the record in sessions_transactions
					sprintf(parameter_value,"%i%i",ntohs(sess_data.client_port),ntohs(sess_data.server_port));
					string2int(parameter_value,session_ID);
					//test to see if a session_profiles for the current session already exists
					i=0;
					while((i<MAX_NUM_USERS_TRANSACTIONS-1) && (session_profiles[i].session_ID!=session_ID))
					{
						i++;
					}
					//end: test to see if a session_profiles for the current session already exists
					//if a session_profiles for the current session does not exists create it
					if(i==MAX_NUM_USERS_TRANSACTIONS-1)
					{
						//find the first empty space in session_profiles
						i=0;
						while((i<MAX_NUM_USERS_TRANSACTIONS-1) && (session_profiles[i].session_ID!=-1))
						{
							i++;
						}
						//create a session_profiles with that empty value with the session_id of the current session
						session_profiles[i].session_ID=session_ID;
						for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
						{
							session_profiles[i].profiles[count]=0;
							session_profiles[i].row_ID[count]=-1;
						}
						if (SHOW_DISPLAY=='y')
						{
							printf("Create session_profiles[%i].session_ID: %i\n",i,session_profiles[i].session_ID);
						}
					}
				}
				else
				{
					if(packet_type==END_SESSION_TYPE)
					{
						//remove the record in sessions_transactions
						sprintf(parameter_value,"%i%i",ntohs(pTcpheader->sport),ntohs(pTcpheader->dport));
						string2int(parameter_value,session_ID);
						/*
						printf("Remove session: %i\n",session_ID);
						for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
						{
						printf("session_profiles[%i].session_ID: %i\n",count,session_profiles[count].session_ID);
						}
						*/
						i=0;
						while((i<MAX_NUM_USERS_TRANSACTIONS-1) && (session_profiles[i].session_ID!=session_ID))
						{
							i++;
						}
						if(i<MAX_NUM_USERS_TRANSACTIONS-1)
						{
							session_profiles[i].session_ID=-1;
							session_profiles[i].timestamp[0]='\0';
							session_profiles[i].LastProfileName=-1;
							session_profiles[i].session_Transaction_ID=9999;
							for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
							{
								session_profiles[i].profiles[count]=0;
								session_profiles[i].row_ID[count]=-1;
							}
							if (SHOW_DISPLAY=='y')
							{
								printf("Remove session_profiles[%i].session_ID: %i\n",i,session_ID);
							}
						}
					}
					else
					{
						if(packet_type==COMMAND_TYPE)
						{
							sprintf(parameter_value,"%i%i",ntohs(pTcpheader->sport),ntohs(pTcpheader->dport));
							string2int(parameter_value,session_ID);
							strcpy(session_user,(char *)sess_data.username);
							file_line_pointer=file_line;
							file_line_pointer=line_parser(RecvBufSplit);

							first_word((unsigned char *)file_line_pointer,session_command_type);

							command_code=-1;
							if(strcmp(session_command_type,"select")==0)
							{
								command_code=SELECT_CODE;
								if((session_Transaction_ID<0))
								{
									session_Transaction_ID=0;
								}
							}
							else
							{
								if(strcmp(session_command_type,"commit")==0)
									//is a commit
								{
									command_code=COMMIT_CODE;
									session_Transaction_ID=-2;
								}
								else
								{
									if(strcmp(session_command_type,"rollback")==0)
										//is a rollback
									{
										command_code=ROLLBACK_CODE;
										session_Transaction_ID=-3;
									}
									else
									{
										if((strcmp(session_command_type,"insert")!=0)
											&& (strcmp(session_command_type,"update")!=0)
											&& (strcmp(session_command_type,"delete")!=0))
											//is a pl/sql block and is treated as a transaction
										{
											session_Transaction_ID=-1;
										}
										else
										{
											session_Transaction_ID=1;//if it is an insert, delete or update the value is 1
										}
									}
								}
							}
							if(strcmp(session_command_type,"insert")==0)
							{
								command_code=INSERT_CODE;
							}
							else
							{
								if(strcmp(session_command_type,"update")==0)
								{
									command_code=UPDATE_CODE;
								}
								else
								{
									if(strcmp(session_command_type,"delete")==0)
									{
										command_code=DELETE_CODE;
									}
									else
									{
										if(strcmp(session_command_type,"declare")==0)
										{
											command_code=DECLARE_CODE;
										}
										else
										{
											if(strcmp(session_command_type,"begin")==0)
											{
												command_code=BEGIN_CODE;
											}
										}
									}
								}
							}
							if (command_code!=-1 && (strcmp(detector_option, "command") == 0))
							{
								//detects only malicious commands
								//calculates the CRC32 of the current command
								size=0;
								while(*(RecvBufSplit+size)!=0)
								{
									size++;
								}
								session_CRC32=update_crc(0xFFFFFFFF, (unsigned char *)RecvBufSplit, size);
								for(count=0;count<max_commands_crc32;count++)
								{
									if (commands_crc32[count]==session_CRC32) break;
								}
								if (count==max_commands_crc32)
								{
									//it is a malicious command
									get_timestamp(timestamp);
									time_diff(delta_timestamp,timestamp,session_timestamp);
									//                   if (SHOW_DISPLAY=='y')
									{
										printf("MALICIOUS_COMMAND;%u;%s;%s;%s\n",session_CRC32,timestamp, delta_timestamp,file_line_pointer);
									}
									fprintf(detect_debug_file,"MALICIOUS_COMMAND;%u;%s;%s;%s\n",session_CRC32,timestamp, delta_timestamp,file_line_pointer);
									if (strcmp(kill_option, "kill") == 0)
									{
										printf("Killing session...\n");
										fprintf(detect_debug_file,"Killing session...\n");
										kill_session();
										printf("Continues the detection of malicious transactions...\n");
									}
								}
								else
									fprintf(detect_debug_file,"%i;%i;%u;%s;%s\n", session_ID,command_code,session_CRC32,session_timestamp,file_line_pointer);
								fflush(detect_debug_file);
								fflush(stdout);
							}
							if (command_code!=-1 && (strcmp(detector_option, "transaction") == 0))
							{
								//detects malicious transactions
								i=0;
								//i=index of the session_profiles from the current command
								while((i<MAX_NUM_USERS_TRANSACTIONS-1) && (session_profiles[i].session_ID!=session_ID))
								{
									i++;
								}
								//if exists a session_profiles for the current command
								if(i<MAX_NUM_USERS_TRANSACTIONS-1)
								{
									//calculates the CRC32 of the current command
									size=0;
									while(*(RecvBufSplit+size)!=0)
									{
										size++;
									}
									/*
									//because of the SQLJava
									if(command_code==COMMIT_CODE)
									{
									session_CRC32=update_crc(0xFFFFFFFF, (unsigned char *)"commit assumed", 14);
									}
									else
									*/
									{
										session_CRC32=update_crc(0xFFFFFFFF, (unsigned char *)RecvBufSplit, size);
									}
									//end of: calculates the CRC32 of the current command

									//get_timestamp(session_timestamp);
									transaction_type=GOOD_TRANSACTION;
									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
										if(session_profiles[i].profiles[count]!=0)
										{
											transaction_type=MALICIOUS_TRANSACTION;
										}
									}
									//search every profile in session_profiles
									session_profiles_aux_index=0;
									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
										if(session_profiles[i].profiles[count]!=0)
										{
											//test if the current command is the next command of that transaction
											//search for all the next commands of the transaction
											for(aux=0;aux<MAX_NUM_NEXT_COMMANDS;aux++)
											{
												next_command_row_ID=session_profiles[i].profiles[count]->tc[session_profiles[i].row_ID[count]].next_command[aux];
												if (next_command_row_ID<(int)session_profiles[i].profiles[count]->num_commands)
												{
													if((int)session_profiles[i].profiles[count]->tc[next_command_row_ID].CRC32==session_CRC32)
													{
														session_profiles_aux.profiles[session_profiles_aux_index]=session_profiles[i].profiles[count];
														session_profiles_aux.row_ID[session_profiles_aux_index]=next_command_row_ID;
														session_profiles_aux_index++;
														assert(session_profiles_aux_index<MAX_NUM_SESSION_PROFILES_DETECTED);

														strcpy(session_old_timestamp,session_profiles[i].timestamp);
														time_diff(delta_timestamp,session_timestamp,session_old_timestamp);

														if(session_profiles[i].timestamp[0]!='\0')
														{
															//if it is not the first command of the session
															if(strcmp(delta_timestamp,session_profiles[i].profiles[count]->tc[next_command_row_ID].min_timestamp)<0)
															{
																transaction_type=ANTICIPATED_TRANSACTION;
															}
															else
															{
																if(strcmp(delta_timestamp,session_profiles[i].profiles[count]->tc[next_command_row_ID].max_timestamp)>0)
																{
																	transaction_type=DELAYED_TRANSACTION;
																}
																else
																{
																	transaction_type=GOOD_TRANSACTION;
																}
															}
														}
														else
														{
															//It is the first command of the session
															transaction_type=GOOD_TRANSACTION;
														}
													}
												}
												else
												{
													if (next_command_row_ID!=-1)
													{
														//it was the last command in the transaction
														profiles[count].count++;
														if (transaction_type==MALICIOUS_TRANSACTION)
														{
															transaction_type=GOOD_TRANSACTION;
														}
													}
												}
											}
										}
									}

									fprintf(detect_debug_file,"session_Transaction_ID before %i\n",session_profiles[i].session_Transaction_ID);
									// Start of: Test if it is the beginning of a new transaction
									session_old_Transaction_ID=session_Transaction_ID;
									if(session_profiles[i].session_Transaction_ID==9999)
									{
										FlagNewTransaction=1;
									}
									else
									{
										session_old_ID=session_ID; //not using the change of session to detect the start of a transaction MUST FIX THIS
										session_old_Transaction_ID=session_profiles[i].session_Transaction_ID;
										FlagNewTransaction=Test_Start_Transaction(session_ID,session_old_ID,session_Transaction_ID,session_old_Transaction_ID);
										//test the start of transaction for the cases of read only transactions
										/*
										if(FlagNewTransaction==0)
										{
										aux=0;
										for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
										{
										if(session_profiles[i].profiles[count]!=0)
										{
										aux++;
										}
										}
										if (aux==1) //there is only one candidate transaction
										{
										//test if that transaction has ended
										if(session_profiles[i].profiles[count]->num_commands==(unsigned)(session_profiles[i].row_ID[count]+1))
										{
										FlagNewTransaction=1;
										}
										}
										}
										*/
									}
									// End of: Test if it is the beginning of a new transaction


									//			    strcpy(session_profiles_aux.timestamp,session_timestamp);
									strcpy(session_profiles[i].timestamp,session_timestamp);
									session_profiles[i].session_Transaction_ID=session_Transaction_ID;
									fprintf(detect_debug_file,"session_Transaction_ID after %i\n",session_profiles[i].session_Transaction_ID);

									/**/
									if((FlagNewTransaction!=0))
										//                  if((FlagNewTransaction!=0) && (session_old_Transaction_ID==-1))
									{
										//					  printf("session_old_Transaction_ID:%i\n",session_old_Transaction_ID);
										for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
										{
											if(session_profiles[i].row_ID[count]!=-1)
											{
												if(session_profiles[i].row_ID[count]+1==(int)session_profiles[i].profiles[count]->num_commands)
												{
													//                          printf("session_Transaction_ID:%i\n",session_Transaction_ID);
													if (SHOW_DISPLAY=='y')
													{
														printf("count: %i session_profiles[%i].LastTransactionName:%i\n",count,i,session_profiles[i].profiles[count]->name);
													}
													fprintf(detect_debug_file,"count: %i session_profiles[%i].LastTransactionName:%i\n",count,i,session_profiles[i].profiles[count]->name);
													//                    printf("session_profiles[i].LastProfileName:%i\n",session_profiles[i].LastProfileName);
													if(session_profiles[i].LastProfileName!=-1)
													{
														for(j=0;j<max_profile_sequences;j++)
														{
															if((computed_profile_sequences[j].from_transaction_name==session_profiles[i].LastProfileName) &&
																(computed_profile_sequences[j].to_transaction_name==session_profiles[i].profiles[count]->name))
																break;
														}
														if(j==max_profile_sequences)
														{
															if (SHOW_DISPLAY=='y')
															{
																printf("Transaction out of sequence\n");
															}
															fprintf(detect_debug_file,"TRANSACTION_OUT_OF_SEQUENCE\n");
														}
													}
													session_profiles[i].LastProfileName=session_profiles[i].profiles[count]->name;
													//						  printf("count: %i session_profiles[%i].LastTransactionName:%i numcommands:%i row_ID:%i\n",count,i,session_profiles[i].profiles[count]->name,session_profiles[i].profiles[count]->num_commands, session_profiles[i].row_ID[count]);
												}
											}
										}
									}
									/* */

									/*
									if (session_profiles_aux_index==0)
									{
									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
									if(session_profiles[i].row_ID[count]!=-1)
									{
									if(session_profiles[i].row_ID[count]+1==session_profiles[i].profiles[count]->num_commands)
									{
									printf("2 count: %i session_profiles[%i].LastTransactionName:%i\n",count,i,session_profiles[i].profiles[count]->name);
									if(session_profiles[i].LastProfileName!=-1)
									{
									for(j=0;j<max_profile_sequences;j++)
									{
									if((computed_profile_sequences[j].from_transaction_name==session_profiles[i].LastProfileName) &&
									(computed_profile_sequences[j].to_transaction_name==session_profiles[i].profiles[count]->name))
									break;
									}
									if(j==max_profile_sequences)
									{
									printf("Transaction out of sequence\n");
									}
									}
									//session_profiles[i].LastProfileName=session_profiles[i].profiles[count]->name;
									//						  printf("count: %i session_profiles[%i].LastTransactionName:%i numcommands:%i row_ID:%i\n",count,i,session_profiles[i].profiles[count]->name,session_profiles[i].profiles[count]->num_commands, session_profiles[i].row_ID[count]);
									}
									}
									}
									}

									*/


									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
										session_profiles[i].profiles[count]=0;
										session_profiles[i].row_ID[count]=-1;
									}
									for(count=0;count<session_profiles_aux_index;count++)
									{
										session_profiles[i].profiles[count]=session_profiles_aux.profiles[count];
										session_profiles[i].row_ID[count]=session_profiles_aux.row_ID[count];
									}
									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
										session_profiles_aux.profiles[count]=0;
										session_profiles_aux.row_ID[count]=-1;
									}


									/*
									aux=0;
									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
									if((session_profiles[i].row_ID[count]!=-1) && (session_Transaction_ID!=-1))
									{
									aux++;
									}
									}
									printf("aux:%i session_Transaction_ID:%i\n",aux,session_Transaction_ID);
									//					if(aux==1)
									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
									if((session_profiles[i].row_ID[count]!=-1) && (session_Transaction_ID!=-1))
									{
									if(session_profiles[i].row_ID[count]+1==session_profiles[i].profiles[count]->num_commands)
									{
									printf("session_profiles_aux_index:%i\n",session_profiles_aux_index);
									printf("3 count: %i session_profiles[%i].LastTransactionName:%i\n",count,i,session_profiles[i].profiles[count]->name);
									}
									}
									}
									*/

									//                  transaction_type=GOOD_TRANSACTION;
									if((session_profiles_aux_index==0) && (transaction_type==GOOD_TRANSACTION))
									{
										//The current command must be the start of a transaction or a malicious command
										//                    session_profiles[i].timestamp[0]='\0';
										transaction_type=MALICIOUS_TRANSACTION;
										j=0;
										for(count=0;count<LastTransactionName;count++)
										{
											if(((int)profiles[count].tc[0].CRC32==session_CRC32))
											{
												session_profiles[i].profiles[j]=&profiles[count];
												session_profiles[i].row_ID[j]=0;
												transaction_type=GOOD_TRANSACTION;
												j++;
												assert(j<MAX_NUM_SESSION_PROFILES_DETECTED);
											}
										}
									}

									if((transaction_old_type==MALICIOUS_TRANSACTION) && (FlagNewTransaction==0))
									{
										transaction_type=MALICIOUS_TRANSACTION;
									}

									//                  printf( "%i;%i;%u;%s;%s\n", session_ID,command_code,session_CRC32,session_timestamp,file_line_pointer);
									//                  printf( "%i;%i;%u;%s\n", session_ID,command_code,session_CRC32,session_timestamp);
									fprintf(detect_debug_file,"%i;%i;%u;%s;%s\n", session_ID,command_code,session_CRC32,session_timestamp,file_line_pointer);
									if (transaction_type==MALICIOUS_TRANSACTION)
									{
										get_timestamp(timestamp);
										time_diff(delta_timestamp,timestamp,session_timestamp);
										//                   if (SHOW_DISPLAY=='y')
										{
											printf("MALICIOUS_COMMAND;%u;%s;%s;%s\n",session_CRC32,timestamp, delta_timestamp,file_line_pointer);
										}
										fprintf(detect_debug_file,"MALICIOUS_COMMAND;%u;%s;%s;%s\n",session_CRC32,timestamp, delta_timestamp,file_line_pointer);
										fflush(detect_debug_file);
										fflush(stdout);

										//clear session_profile
										for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
										{
											session_profiles[i].profiles[count]=0;
											session_profiles[i].row_ID[count]=-1;
										}
										if (FlagNewTransaction!=0)
										{
											if (SHOW_DISPLAY=='y')
											{
												printf("Malicious Transaction\n");
											}
											fprintf(detect_debug_file,"MALICIOUS_TRANSACTION\n");
											fflush(detect_debug_file);
											fflush(stdout);
										}
										if (strcmp(kill_option, "kill") == 0)
										{
											printf("Killing session...\n");
											fprintf(detect_debug_file,"Killing session...\n");
											kill_session();
											printf("Continues the detection of malicious transactions...\n");
										}
									}
									else
									{
										if (transaction_type==ANTICIPATED_TRANSACTION)
										{
											if (SHOW_DISPLAY=='y')
											{
												printf( "ANTICIPATED_COMMAND\n");
											}
											fprintf(detect_debug_file,"ANTICIPATED_COMMAND\n");
										}
										else
										{
											if (transaction_type==DELAYED_TRANSACTION)
											{
												if (SHOW_DISPLAY=='y')
												{
													printf( "DELAYED_COMMAND\n");
												}
												fprintf(detect_debug_file,"DELAYED_COMMAND\n");
											}
										}
									}

									//If a transaction ends through a COMMIT or ROLLBACK and is not malicioous then we know now that it is ended
									//printf("session_Transaction_ID %i\n",session_Transaction_ID);
									//fprintf(detect_debug_file,"session_Transaction_ID %i\n",session_Transaction_ID);
									//test the start of transaction for the cases of read only transactions
									aux=0;
									for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
									{
										if(session_profiles[i].profiles[count]!=0)
										{
											aux++;
										}
									}
									if(aux==1)
									{
										for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
										{
											if(session_profiles[i].row_ID[count]!=-1)
											{
												if((unsigned)(session_profiles[i].row_ID[count]+1)==session_profiles[i].profiles[count]->num_commands)
												{
													//printf("session_Transaction_ID %i\n",session_Transaction_ID);
													//                        if ((session_Transaction_ID<0) && (transaction_type!=MALICIOUS_TRANSACTION))
													if (transaction_type!=MALICIOUS_TRANSACTION)
													{
														if(session_Transaction_ID<0)
														{
															if (SHOW_DISPLAY=='y')
															{
																printf("Explicit end of transaction -> session_profiles[%i].LastTransactionName:%i\n",i,session_profiles[i].profiles[count]->name);
															}
															fprintf(detect_debug_file,"Explicit end of transaction -> session_profiles[%i].LastTransactionName:%i\n",i,session_profiles[i].profiles[count]->name);
														}
														else
														{
															if (SHOW_DISPLAY=='y')
															{
																printf("Implicit end of transaction (RO)-> session_profiles[%i].LastTransactionName:%i\n",i,session_profiles[i].profiles[count]->name);
															}
															fprintf(detect_debug_file,"Implicit end of transaction (RO)-> session_profiles[%i].LastTransactionName:%i\n",i,session_profiles[i].profiles[count]->name);
														}
														//                    printf("xx session_profiles[i].LastProfileName:%i\n",session_profiles[i].LastProfileName);
														if(session_profiles[i].LastProfileName!=-1)
														{
															for(j=0;j<max_profile_sequences;j++)
															{
																if((computed_profile_sequences[j].from_transaction_name==session_profiles[i].LastProfileName) &&
																	(computed_profile_sequences[j].to_transaction_name==session_profiles[i].profiles[count]->name))
																	break;
															}
															if(j==max_profile_sequences)
															{
																if (SHOW_DISPLAY=='y')
																{
																	printf("Transaction out of sequence\n");
																}
																fprintf(detect_debug_file,"TRANSACTION_OUT_OF_SEQUENCE\n");
															}
														}
														session_profiles[i].LastProfileName=session_profiles[i].profiles[0]->name;

														for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
														{
															session_profiles[i].profiles[count]=0;
															session_profiles[i].row_ID[count]=-1;
														}
														for(count=0;count<session_profiles_aux_index;count++)
														{
															session_profiles[i].profiles[count]=session_profiles_aux.profiles[count];
															session_profiles[i].row_ID[count]=session_profiles_aux.row_ID[count];
														}
														for(count=0;count<MAX_NUM_SESSION_PROFILES_DETECTED;count++)
														{
															session_profiles_aux.profiles[count]=0;
															session_profiles_aux.row_ID[count]=-1;
														}
													}
													/*
													else
													{
													if (SHOW_DISPLAY=='y')
													{
													printf("Malicious Transaction\n");
													}
													fprintf(detect_debug_file,"MALICIOUS_TRANSACTION\n");
													}
													*/
												}
											}
										}
									}
									/*
									if ((FlagNewTransaction!=0) && (transaction_type==MALICIOUS_TRANSACTION))
									{
									if (SHOW_DISPLAY=='y')
									{
									printf("Malicious Transaction\n");
									}
									fprintf(detect_debug_file,"MALICIOUS_TRANSACTION\n");
									}
									*/
								}
								//does not exist a session_profiles for the current command
								else
								{
									//??
								}
								transaction_old_type=transaction_type;
							}
						}
					}
				}
			}
			fflush(detect_debug_file);
			fflush(stdout);
		}
	}
	//end: sniffer section

	// Close command_file
	if( fclose( command_file ) )
	{
		ERROR_MESSAGE("The file 'command.txt' was not closed" );
	}
	else
	{
		printf("The file 'command.txt' was closed\n" );
	}

	// Close profile_file
	if( fclose( profile_file ) )
	{
		ERROR_MESSAGE("The file 'profile.txt' was not closed" );
	}
	else
	{
		printf("The file 'profile.txt' was closed\n" );
	}

	// Close profile_seq_file
	if( fclose(profile_seq_file) )
	{
		ERROR_MESSAGE("The file 'prof_seq2.txt' was not closed" );
	}
	else
	{
		printf("The file 'prof_seq2.txt' was closed\n" );
	}

	// Close detect_debug_file
	if( fclose( detect_debug_file) )
	{
		ERROR_MESSAGE("The file 'detector_debug.txt' was not closed" );
	}
	else
	{
		printf("The file 'detector_debug.txt' was closed\n" );
	}

	/* Close detector_delay_debug_file */
	if( fclose( delay_debug_file ) )
	{
		ERROR_MESSAGE("The file 'detector_delay_debug.txt' was not closed" );
	}
	else
	{
		printf("The file 'detector_delay_debug.txt' was closed\n" );
	}

	/*
	int ch;
	printf("\npress any key to end.");
	ch=getchar();
	*/
}

int read_next_command(char * parameter_value,int * next_command,int start)
{
	char ch;
	int i;
	int j;
	int k;
	char num[16];

	i=start;
	j=0;
	k=0;
	ch=parameter_value[i];
	while (ch!=';')
	{
		if(ch!=',')
		{
			num[j]=ch;
			j++;
			assert(j<16);
		}
		else
		{
			num[j]='\0';
			next_command[k]=atoi(num);
			j=0;
			k++;
			assert(k<MAX_NUM_NEXT_COMMANDS);
		}
		i++;
		assert(i<256);
		ch=parameter_value[i];
	}
	num[j]='\0';
	next_command[k]=atoi(num);
	return ++i;
}


int read_command_int(char * parameter_value,int & command_int,int start)
{
	char ch;
	int i;
	int j;
	int k;
	char num[16];

	i=start;
	j=0;
	k=0;
	ch=parameter_value[i];
	while ((ch!='\0') && (ch!=';'))
	{
		num[j]=ch;
		j++;
		assert(j<16);
		i++;
		assert(i<256);
		ch=parameter_value[i];
	}
	num[j]='\0';
	//  command_int=atoi(num);
	string2int(num,command_int);
	return ++i;
}

int read_command_char(char * parameter_value,char * command_char,int start)
{
	int ch;
	int i;
	int j;
	int k;

	i=start;
	j=0;
	k=0;
	ch=parameter_value[i];
	while ((ch!='\0') && (ch!=';'))
	{
		command_char[j]=ch;
		j++;
		assert(j<16);
		i++;
		assert(i<256);
		ch=parameter_value[i];
	}
	command_char[j]='\0';
	return ++i;
}

#ifndef WIN32
void sigint_detector(int signum)
{
	struct ifreq ifr;

	if (sock == -1)
		return;
	/*
	int i;
	int j;
	int i_next_command;
	for(i=0;i<MAX_NUM_TRANSACTIONS;i++)
	{
	if(profiles[i].num_commands!=0)
	{
	printf("\nprofile_name: %u\n",profiles[i].name);
	printf("profile_count: %u\n",profiles[i].count);
	printf("num_commands: %u\n",profiles[i].num_commands);
	for(j=0;j<MAX_NUM_TRANSACTIONS;j++)
	{
	if ((users[j].profile_name==profiles[i].name) && (users[j].profile_user[0]!='\0'))
	{
	printf("profile_user: %s\n",users[j].profile_user);
	}
	}
	transactions=profiles[i].tc;
	for(j=0;j<(int)profiles[i].num_commands;j++)
	{
	printf("\t%i;%i;%u;<",transactions[j].row_ID,transactions[j].command_code,transactions[j].CRC32);

	i_next_command=0;
	while ((transactions[j].next_command[i_next_command]>=0) && (i_next_command<MAX_NUM_NEXT_COMMANDS-1))
	{
	if (i_next_command>0)
	{
	printf(",");
	}
	printf("%i",transactions[j].next_command[i_next_command]);
	i_next_command++;
	}

	printf(">;%s;%s\n",transactions[j].min_timestamp,transactions[j].max_timestamp);
	}
	}
	}
	*/

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
