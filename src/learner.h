//learner functions

#define MAX_FILE_LINE_LENGTH 10240
#define MAX_COMMAND_LENGTH 10240
//#define MAX_NUM_COMMANDS 65536
#define MAX_NUM_COMMANDS 500000
#define MAX_NUM_TRANSACTIONS 10240
#define MAX_NUM_USERS_TRANSACTIONS 10240
#define MAX_NUM_NEXT_COMMANDS 16
//#define MAX_NUM_PROFILE_SEQUENCES 16384
#define MAX_NUM_PROFILE_SEQUENCES 10000000
#define MAX_NUM_COMMAND_SEQUENCES 10000000

#define MAX_FILE_NAME 256

void option_learner(int learn_also_read_only);
void option_learner_files(int learn_also_read_only,char *aud_file_name,char *profile_file_name,char *profile_seq_file_name,char *profile_time_file_name,char *profile_seq2_file_name,char *command_file_name,char *command_seq_file_name,char *command_time_file_name,char *command_seq2_file_name);
void read_record(FILE *read_file,char * parameter_value);
int Test_Start_Transaction(int session_ID,int session_old_ID,int session_transaction_ID,int session_old_transaction_ID);
unsigned int Detect_Loop(struct transaction *transactions_temp, unsigned int transactions_temp_index);
void delete_transaction(struct transaction *transactions_temp,int index,unsigned int transactions_temp_index);
int Compare_Transactions(struct profile *profiles,struct transaction *transactions_temp,unsigned int transactions_temp_index);
void quick_sort(struct computed_profile_sequence computed_profile_sequences[MAX_NUM_PROFILE_SEQUENCES], int lb, int ub);
void quick_sort2(struct computed_profile_sequence computed_profile_sequences[MAX_NUM_PROFILE_SEQUENCES], int lb, int ub);
void quick_sort_profiles(struct profile profiles[MAX_NUM_TRANSACTIONS], int lb, int ub);
void learn_read_only_profiles(struct profile *profiles,int &count_profiles,struct user *users,struct profile_sequence *profile_sequences);

//command_code of the struct transaction
#define SELECT_CODE 0
#define INSERT_CODE 1
#define UPDATE_CODE 2
#define DELETE_CODE 3
#define DECLARE_CODE 4
#define BEGIN_CODE 5

#define COMMIT_CODE 8
#define ROLLBACK_CODE 9

//struct transaction has the information about each command belonging to a transaction
struct transaction
{
  int  row_ID;					//number identifying the order of the command inside the transaction
  int  command_code;				//code of the command according to the #defines above
  unsigned int CRC32;				//CRC32 of the command text
  int next_command[MAX_NUM_NEXT_COMMANDS];	//array of the following commands possibilities
  char min_timestamp[32];			//minimum time stamp from the previous command
  char max_timestamp[32];			//maxmimum time stamp from the previous command
};

//struct profile has the complete transaction information contained in its profile
struct profile
{
  int  name;					//name (number) of the profile
  unsigned int  count;				//number of times this profile has been detected during the learning phase
  unsigned int num_commands;			//number of commands contained in the profile
  transaction *tc;				//pointer to an array of transaction struct
};

//struct profile_sequence has the sequence of execution of profiles
struct profile_sequence
{
  int session_ID;				//concatenation of the port of the client and the port of the server
  int  row_ID;				//order of the profile in the profile_sequence
  int  transaction_name;			//name of the profile
};

//struct computed_profile_sequence has the resume of the sequence of execution of profiles
struct computed_profile_sequence
{
  int from_transaction_name;			//the initial profile
  int to_transaction_name;			//the next profile
  int percentage;				//number of times the initial profile is followed by the next profile during the learning phase
};

//struct command has the complete transaction information contained in its command
struct command
{
  int  name;					//name (number) of the command
  int  command_crc32;				//crc32 of the command text
  char *command_text;	//command text
  unsigned int  count;				//number of times this command has been detected during the learning phase
};

//struct command_sequence has the sequence of execution of commands
struct command_sequence
{
  int session_ID;				//concatenation of the port of the client and the port of the server
  int  row_ID;				//order of the command in the command_sequence
  int  command_crc32;				//name of the command
};

//struct computed_command_sequence has the resume of the sequence of execution of commands
struct computed_command_sequence
{
  int from_command_crc32;			//the initial command
  int to_command_crc32;				//the next command
  int percentage;				//number of times the initial command is followed by the next command during the learning phase
};

//struct user has the profile and the user associated to it
struct user
{
  int profile_name;				//name (number) of the profile
  char profile_user[16];			//name of the database user that can execute the profile
};


//#define TESTE

#ifdef TESTE
long ponteirosAlocados [10000];

void iniciaMem()
{
  for(int i = 0; i< 10000; i++) ponteirosAlocados[i]=0;
}

void * aloca(long size)
{
  int i;
  void * mem = malloc(size);

  for(i = 0; i< 10000; i++) if (ponteirosAlocados[i] == 0)
    {
      ponteirosAlocados[i]=(long) mem;
      break;
    }

  if (i == 10000) printf("O ARRAY TEM DE SER MAIOR\n");

  return mem;
}

void desaloca(void * mem)
{
  int i;

  for(i = 0; i< 10000; i++) if (ponteirosAlocados[i] == (long) mem)
    {
      ponteirosAlocados[i]= 0;
      break;
    }

  if (i == 10000)
  {
    printf("PROBLEMA\n");
    exit(1);
  }
  else
  {
    free(mem);
  }
}
#else
#define aloca(X) malloc(X)
#define desaloca(X) free(X)
#endif

void option_learner(int learn_also_read_only)//the parameter is learn_also_read_only and if it is 1 then there will be also learned the read only transaction
{
  char aud_file_name[MAX_FILE_NAME]="";
  char profile_file_name[MAX_FILE_NAME]="";
  char profile_seq_file_name[MAX_FILE_NAME]="";
  char profile_seq2_file_name[MAX_FILE_NAME]="";
  char profile_time_file_name[MAX_FILE_NAME]="";
  char command_file_name[MAX_FILE_NAME]="";
  char command_seq_file_name[MAX_FILE_NAME]="";
  char command_seq2_file_name[MAX_FILE_NAME]="";
  char command_time_file_name[MAX_FILE_NAME]="";
  char file_name_remove[MAX_FILE_NAME]="";
  char file_extension[32]="";
  int count_file_name;
  int count;

  count_file_name=count_file_radical("aud", ".txt");
  //  count_file_name++;
  if(strcmp(append_files,"all")==0)
  {
    for(count=0;count<=count_file_name;count++)
    {
      // Open for write (will fail if file "session.txt" does not exist)
      strcpy(aud_file_name,"aud");
      strcpy(file_extension,".txt");
      file_radical(aud_file_name, file_extension,count);
      if( (aud_file  = fopen( aud_file_name, "rb" )) == NULL )
        printf( "The file '%s' was not opened\n",aud_file_name);
      else
        printf( "The file '%s' was opened\n",aud_file_name);

      // Open for read (will fail if file "profile.txt" does not exist)
      strcpy(profile_file_name,"profile");
      strcpy(file_extension,".txt");
      file_radical(profile_file_name, file_extension,count);
      if( (profile_file  = fopen( profile_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",profile_file_name);
      else
        printf( "The file '%s' was opened\n",profile_file_name);

      // Open for read (will fail if file "session.txt" does not exist)
      strcpy(profile_seq_file_name,"prof_seq");
      strcpy(file_extension,".txt");
      file_radical(profile_seq_file_name, file_extension,count);
      if( (profile_seq_file  = fopen( profile_seq_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",profile_seq_file_name);
      else
        printf( "The file '%s' was opened\n",profile_seq_file_name);

      // Open for read (will fail if file "session.txt" does not exist)
      strcpy(profile_seq2_file_name,"prof_seq2");
      strcpy(file_extension,".txt");
      file_radical(profile_seq2_file_name, file_extension,count);
      if( (profile_seq2_file  = fopen( profile_seq2_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",profile_seq2_file_name);
      else
        printf( "The file '%s' was opened\n",profile_seq2_file_name);

      // Open for read (will fail if file "session.txt" does not exist)
      strcpy(profile_time_file_name,"profile_time");
      strcpy(file_extension,".txt");
      file_radical(profile_time_file_name, file_extension,count);
      if( (profile_time_file  = fopen( profile_time_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",profile_time_file_name);
      else
        printf( "The file '%s' was opened\n",profile_time_file_name);

      // Open for read (will fail if file "command.txt" does not exist)
      strcpy(command_file_name,"command");
      strcpy(file_extension,".txt");
      file_radical(command_file_name, file_extension,count);
      if( (command_file  = fopen( command_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",command_file_name);
      else
        printf( "The file '%s' was opened\n",command_file_name);

      // Open for read (will fail if file "command_seq.txt" does not exist)
      strcpy(command_seq_file_name,"command_seq");
      strcpy(file_extension,".txt");
      file_radical(command_seq_file_name, file_extension,count);
      if( (command_seq_file  = fopen( command_seq_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",command_seq_file_name);
      else
        printf( "The file '%s' was opened\n",command_seq_file_name);

      // Open for read (will fail if file "command_seq.txt" does not exist)
      strcpy(command_seq2_file_name,"command_seq2");
      strcpy(file_extension,".txt");
      file_radical(command_seq2_file_name, file_extension,count);
      if( (command_seq2_file  = fopen( command_seq2_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",command_seq2_file_name);
      else
        printf( "The file '%s' was opened\n",command_seq2_file_name);

      // Open for read (will fail if file "session.txt" does not exist)
      strcpy(command_time_file_name,"command_time");
      strcpy(file_extension,".txt");
      file_radical(command_time_file_name, file_extension,count);
      if( (command_time_file  = fopen( command_time_file_name, "w+" )) == NULL )
        printf( "The file '%s' was not opened\n",command_time_file_name);
      else
        printf( "The file '%s' was opened\n",command_time_file_name);

      option_learner_files(learn_also_read_only,aud_file_name,profile_file_name,profile_seq_file_name,profile_time_file_name,profile_seq2_file_name,command_file_name,command_seq_file_name,command_time_file_name,command_seq2_file_name);
    }
  }
  if((strcmp(append_files,"last")==0) || (strcmp(append_files,"merge")==0))
  {
    count=count_file_name;
    // Open for write (will fail if file "session.txt" does not exist)
    strcpy(aud_file_name,"aud");
    strcpy(file_extension,".txt");
    file_radical(aud_file_name, file_extension,count);
    if( (aud_file  = fopen( aud_file_name, "rb" )) == NULL )
      printf( "The file '%s' was not opened\n",aud_file_name);
    else
      printf( "The file '%s' was opened\n",aud_file_name);

    // Open for read (will fail if file "profile.txt" does not exist)
    strcpy(profile_file_name,"profile");
    strcpy(file_extension,".txt");
    file_radical(profile_file_name, file_extension,count);
    if( (profile_file  = fopen( profile_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",profile_file_name);
    else
      printf( "The file '%s' was opened\n",profile_file_name);

    // Open for read (will fail if file "session.txt" does not exist)
    strcpy(profile_seq_file_name,"prof_seq");
    strcpy(file_extension,".txt");
    file_radical(profile_seq_file_name, file_extension,count);
    if( (profile_seq_file  = fopen( profile_seq_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",profile_seq_file_name);
    else
      printf( "The file '%s' was opened\n",profile_seq_file_name);

    // Open for read (will fail if file "session.txt" does not exist)
    strcpy(profile_seq2_file_name,"prof_seq2");
    strcpy(file_extension,".txt");
    file_radical(profile_seq2_file_name, file_extension,count);
    if( (profile_seq2_file  = fopen( profile_seq2_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",profile_seq2_file_name);
    else
      printf( "The file '%s' was opened\n",profile_seq2_file_name);

    // Open for write (will fail if file "session.txt" does not exist)
    strcpy(profile_time_file_name,"prof_time");
    strcpy(file_extension,".txt");
    file_radical(profile_time_file_name, file_extension,count);
    if( (profile_time_file  = fopen( profile_time_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",profile_time_file_name);
    else
      printf( "The file '%s' was opened\n",profile_time_file_name);

    // Open for write (will fail if file "command.txt" does not exist)
    strcpy(command_file_name,"command");
    strcpy(file_extension,".txt");
    file_radical(command_file_name, file_extension,count);
    if( (command_file  = fopen( command_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",command_file_name);
    else
      printf( "The file '%s' was opened\n",command_file_name);

    // Open for read (will fail if file "command.txt" does not exist)
    strcpy(command_seq_file_name,"command_seq");
    strcpy(file_extension,".txt");
    file_radical(command_seq_file_name, file_extension,count);
    if( (command_seq_file  = fopen( command_seq_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",command_seq_file_name);
    else
      printf( "The file '%s' was opened\n",command_seq_file_name);

    // Open for read (will fail if file "command_seq2.txt" does not exist)
    strcpy(command_seq2_file_name,"command_seq2");
    strcpy(file_extension,".txt");
    file_radical(command_seq2_file_name, file_extension,count);
    if( (command_seq2_file  = fopen( command_seq2_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",command_seq2_file_name);
    else
      printf( "The file '%s' was opened\n",command_seq2_file_name);

    // Open for read (will fail if file "command_time.txt" does not exist)
    strcpy(command_time_file_name,"command_time");
    strcpy(file_extension,".txt");
    file_radical(command_time_file_name, file_extension,count);
    if( (command_time_file  = fopen( command_time_file_name, "w+" )) == NULL )
      printf( "The file '%s' was not opened\n",command_time_file_name);
    else
      printf( "The file '%s' was opened\n",command_time_file_name);

    option_learner_files(learn_also_read_only,aud_file_name,profile_file_name,profile_seq_file_name,profile_time_file_name,profile_seq2_file_name,command_file_name,command_seq_file_name,command_time_file_name,command_seq2_file_name);
  }
}

void option_learner_files(int learn_also_read_only,char *aud_file_name,char *profile_file_name,char *profile_seq_file_name,char *profile_time_file_name, char *profile_seq2_file_name,char *command_file_name,char *command_seq_file_name,char *command_time_file_name,char *command_seq2_file_name)//the parameter is learn_also_read_only and if it is 1 then there will be also learned the read only transaction
{
  //  struct transaction transactions_temp[MAX_NUM_COMMANDS]={0};
  struct transaction *transactions_temp=NULL;
  int transactions_temp_index=0;
  struct transaction *transactions=NULL;
  //   struct profile profiles[MAX_NUM_TRANSACTIONS]={0};
  struct profile *profiles=NULL;
  //  struct profile_sequence profile_sequences[MAX_NUM_PROFILE_SEQUENCES]={0};
  struct profile_sequence *profile_sequences=NULL;
  //  struct computed_profile_sequence computed_profile_sequences[MAX_NUM_PROFILE_SEQUENCES]={0};
  struct computed_profile_sequence *computed_profile_sequences=NULL;
  //  struct user users[MAX_NUM_USERS_TRANSACTIONS]={0};
  struct user *users=NULL;
  struct command *commands=NULL;
  struct command_sequence *command_sequences=NULL;
  struct computed_command_sequence *computed_command_sequences=NULL;
  char *command_text;
  int profile_sequences_index=0;
  int command_sequences_index=0;
  int i;
  int j;
  int count;
  int i_next_command;
  int i_next_command_temp;

  int FirstTransaction=0;
  int FlagNewTransaction=0;

  char record_aux[16]; //MAX_NUM_COMMANDS

  int session_ID;
  char session_user[16];
  int command_code;
  char session_command_type[16];
  //  char session_command[MAX_COMMAND_LENGTH];
  char *session_command=NULL;
  int session_CRC32;
  char session_timestamp[32];
  int session_Transaction_ID=0;
  int MyTransactionName=0;
  int FlagDifferentTransaction=-1;


  int session_old_ID=0;
  char session_old_timestamp[32]="";
  int session_old_Transaction_ID=0;

  char delta_timestamp[32]={0};

  int count_profile_sequences;
  int count_computed_profile_sequences;
  int from_transaction_name;
  int to_transaction_name;

  int count_computed_command_sequences;
  int from_command_crc32;
  int to_command_crc32;

  char initial_session_timestamp[32];
  char session_timestamp_diff[32];
  int command_number=0;
  int command_name=0;
  int main_length;

#ifdef TESTE
  iniciaMem();
#endif

  if((transactions_temp=(struct transaction *)malloc((MAX_NUM_COMMANDS)*sizeof(struct transaction)))==NULL)
    ERROR_MESSAGE("transactions_temp");
  if((profile_sequences=(struct profile_sequence *)malloc((MAX_NUM_PROFILE_SEQUENCES)*sizeof(struct profile_sequence)))==NULL)
    ERROR_MESSAGE("profile_sequences");
  if((computed_profile_sequences=(struct computed_profile_sequence *)malloc((MAX_NUM_PROFILE_SEQUENCES)*sizeof(struct computed_profile_sequence)))==NULL)
    ERROR_MESSAGE("computed_profile_sequences");
  if((profiles=(struct profile *)malloc((MAX_NUM_TRANSACTIONS)*sizeof(struct profile)))==NULL)
    ERROR_MESSAGE("profiles");
  if((command_sequences=(struct command_sequence *)malloc((MAX_NUM_COMMAND_SEQUENCES)*sizeof(struct command_sequence)))==NULL)
    ERROR_MESSAGE("command_sequences");
  if((computed_command_sequences=(struct computed_command_sequence *)malloc((MAX_NUM_COMMAND_SEQUENCES)*sizeof(struct computed_command_sequence)))==NULL)
    ERROR_MESSAGE("computed_command_sequences");
  if((commands=(struct command *)malloc((MAX_NUM_COMMANDS)*sizeof(struct command)))==NULL)
    ERROR_MESSAGE("commands");
  if((session_command=(char *)malloc((MAX_COMMAND_LENGTH)*sizeof(char)))==NULL)
    ERROR_MESSAGE("session_command");
  if((users=(struct user *)malloc((MAX_NUM_USERS_TRANSACTIONS)*sizeof(struct user)))==NULL)
    ERROR_MESSAGE("users");

  for(count=0;count<MAX_NUM_COMMANDS;count++)
  {
    transactions_temp[count].row_ID='\0';
    transactions_temp[count].CRC32='\0';
    for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
    {
      transactions_temp[count].next_command[i_next_command]=-1;
    }
    transactions_temp[count].min_timestamp[0]='\0';
    transactions_temp[count].max_timestamp[0]='\0';
  }
  for(count=0;count<MAX_NUM_PROFILE_SEQUENCES;count++)
  {
    profile_sequences[count].session_ID=-1;
    profile_sequences[count].row_ID=-1;
    profile_sequences[count].transaction_name=-1;
  }
  for(count=0;count<MAX_NUM_PROFILE_SEQUENCES;count++)
  {
    computed_profile_sequences[count].from_transaction_name=-1;
    computed_profile_sequences[count].to_transaction_name=-1;
    computed_profile_sequences[count].percentage=-1;
  }
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
  session_command[0]='\0';

  // Set pointer to beginning of file:
  fseek(aud_file, 0L, SEEK_SET );

  while (!feof(aud_file ))
  {
    read_record(aud_file,record_aux);
    session_ID=atoi(record_aux);
    if(session_ID>0)
    {
      read_record(aud_file,session_user);
      read_record(aud_file,session_command_type);
      read_record(aud_file,session_command);
      read_record(aud_file,record_aux);
      string2int(record_aux,session_CRC32);
      read_record(aud_file,session_timestamp);

      /*
            //start debug
            if((session_CRC32==203218222) && (strcmp(session_timestamp,"20/05/2006 01:57:16.593")==0))
            {
              printf("session_user %s session_CRC32 %i session_timestamp %s\n",session_user,session_CRC32,session_timestamp);
            }
            //end debug
            if (profile_sequences_index>MAX_NUM_PROFILE_SEQUENCES)
            {
              printf("profile_sequences_index: %i is bigger than the allowable value %i\n",profile_sequences_index,MAX_NUM_PROFILE_SEQUENCES);
              printf("session_user %s session_CRC32 %i session_timestamp %s\n",session_user,session_CRC32,session_timestamp);
              exit(1);
            }
      */

      if(command_number==0)
      {
        strcpy(initial_session_timestamp,session_timestamp);
      }
      command_number++;

      //start command file processing
      main_length=0;
      while (*(session_command+main_length)!=0)
      {
        main_length++;
      }
      main_length++;
      if(command_name==0)
      {
        if((command_text=(char *)malloc((main_length)*sizeof(char)))==NULL)
          ERROR_MESSAGE("command_text");
        strncpy(command_text,session_command,main_length);
        commands[command_name].name=command_name;
        commands[command_name].command_crc32=session_CRC32;
        commands[command_name].command_text=command_text;
        commands[command_name].count=1;
            time_diff(session_timestamp_diff,session_timestamp,initial_session_timestamp);
            fprintf(command_time_file,"%i %i %s %s\n",command_number,command_name,session_timestamp,session_timestamp_diff);
            fflush(command_time_file);
        command_name++;
      }
      else
      {
        for(count=0;count<command_name;count++)
        {
          if(commands[count].command_crc32==session_CRC32)
          {
            commands[count].count++;
            //printf("session_CRC32 %u %u\n",session_CRC32,commands[count].count);
            break;
          }
        }
        if(commands[count].command_crc32!=session_CRC32)
        {
          if((command_text=(char *)malloc((main_length)*sizeof(char)))==NULL)
            ERROR_MESSAGE("command_text");
          strncpy(command_text,session_command,main_length);
          commands[command_name].name=command_name;
          commands[command_name].command_crc32=session_CRC32;
          commands[command_name].command_text=command_text;
          commands[command_name].count=1;
            time_diff(session_timestamp_diff,session_timestamp,initial_session_timestamp);
            fprintf(command_time_file,"%i %i %s %s\n",command_number,command_name,session_timestamp,session_timestamp_diff);
            fflush(command_time_file);
          command_name++;
        }
      }
      //end command file processing

      //start command file sequence processing
      command_sequences[command_sequences_index].session_ID=session_ID;
      command_sequences[command_sequences_index].row_ID=command_sequences_index;
      command_sequences[command_sequences_index].command_crc32=session_CRC32;
      command_sequences_index++;
      //end command file sequence processing

      //calculate Transaction_ID
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
              //is a pl/sql block as is treated as a transaction
            {
              session_Transaction_ID=-1;
            }
            else
            {
              session_Transaction_ID=1;
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

      // Start of: Test if it is the beginning of a new transaction
      if (FirstTransaction==0)
        FlagNewTransaction=1;
      else
      {
        FlagNewTransaction=Test_Start_Transaction(session_ID,session_old_ID,session_Transaction_ID,session_old_Transaction_ID);
      }
      // End of: Test if it is the beginning of a new transaction

      //      printf( "%i;%s;%u;%i;%i\n", session_ID,session_command_type,session_CRC32,session_Transaction_ID,FlagNewTransaction);

      //if it is a new transaction
      if (FlagNewTransaction==1)
      {

        //start: process the transaction that ended in the last command
        if(FirstTransaction!=0)
        {
          //start: Detect loops
          transactions_temp_index=Detect_Loop(transactions_temp,transactions_temp_index);
          //end: Detect loops

          //start: Compare just ended transaction with already existing ones
          FlagDifferentTransaction=Compare_Transactions(profiles,transactions_temp,transactions_temp_index);
          //end: Compare just ended transaction with already existing ones

          // If the new transaction is different from the existing ones copy the new transaction to the profiles
          if (FlagDifferentTransaction==-1)
          {
            //copy the new transaction to the profiles
            assert(transactions_temp_index>0);
            if((transactions=(struct transaction *)malloc((transactions_temp_index)*sizeof(struct transaction)))==NULL)
            {
              ERROR_MESSAGE("learner.h: transactions");
            }
            for(count=0;count<(int)transactions_temp_index;count++)
            {
              transactions[count].row_ID=transactions_temp[count].row_ID;
              transactions[count].command_code=transactions_temp[count].command_code;
              transactions[count].CRC32=transactions_temp[count].CRC32;
              for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
              {
                transactions[count].next_command[i_next_command]=transactions_temp[count].next_command[i_next_command];
              }
              strcpy(transactions[count].min_timestamp,transactions_temp[count].min_timestamp);
              strcpy(transactions[count].max_timestamp,transactions_temp[count].max_timestamp);
            }
            //assign the new transaction to the profiles
            profiles[MyTransactionName].name=MyTransactionName;
            profiles[MyTransactionName].count++;
            profiles[MyTransactionName].tc=transactions;
            profiles[MyTransactionName].num_commands=transactions_temp_index;
            users[MyTransactionName].profile_name=MyTransactionName;
            strcpy(users[MyTransactionName].profile_user,session_user);

            //register the profile_sequences
            profile_sequences[profile_sequences_index].session_ID=session_ID;
            profile_sequences[profile_sequences_index].row_ID=profile_sequences_index;
            profile_sequences[profile_sequences_index].transaction_name=MyTransactionName;
            profile_sequences_index++;
            assert(profile_sequences_index<=MAX_NUM_PROFILE_SEQUENCES);

            MyTransactionName++;
            assert(MyTransactionName<MAX_NUM_TRANSACTIONS);
            time_diff(session_timestamp_diff,session_timestamp,initial_session_timestamp);
            /*
            	  //start debug
            	  if(command_number==15358)
            	  {
            	  printf("session_user %s session_CRC32 %i session_timestamp %s\n",session_user,session_CRC32,session_timestamp);
            	  }
            	  //end debug
            	  */

            fprintf(profile_time_file,"%i %i %s %s\n",command_number,MyTransactionName,session_timestamp,session_timestamp_diff);
            fflush(profile_time_file);
          }
          // If the new transaction is equal from the existing ones updates the MIN_TIMESTAMP and the MAX_TIMESTAMP
          else
          {
            //update statistics
            profiles[FlagDifferentTransaction].count++;
            //Update Timestamps
            for(count=0;count<(int)transactions_temp_index;count++)
            {
              //updates the min_timestamp
              if(strcmp(transactions_temp[count].min_timestamp,profiles[FlagDifferentTransaction].tc[count].min_timestamp)<0)
              {
                strcpy(profiles[FlagDifferentTransaction].tc[count].min_timestamp,transactions_temp[count].min_timestamp);
              }
              //updates the max_timestamp
              if(strcmp(transactions_temp[count].max_timestamp,profiles[FlagDifferentTransaction].tc[count].max_timestamp)>0)
              {
                strcpy(profiles[FlagDifferentTransaction].tc[count].max_timestamp,transactions_temp[count].max_timestamp);
              }
            }
            //Update the next_command[]
            for(count=0;count<(int)transactions_temp_index;count++)
            {
              for(i_next_command_temp=0;i_next_command_temp<MAX_NUM_NEXT_COMMANDS;i_next_command_temp++)
              {
                i_next_command=0;
                while ((i_next_command<MAX_NUM_NEXT_COMMANDS) && (transactions_temp[count].next_command[i_next_command_temp]!=profiles[FlagDifferentTransaction].tc[count].next_command[i_next_command]))
                {
                  i_next_command++;
                }
                if (i_next_command==MAX_NUM_NEXT_COMMANDS)
                {
                  i_next_command=0;
                  while ((i_next_command<MAX_NUM_NEXT_COMMANDS) && (profiles[FlagDifferentTransaction].tc[count].next_command[i_next_command]>=0))
                  {
                    i_next_command++;
                  }
                  if (i_next_command!=MAX_NUM_NEXT_COMMANDS)
                  {
                    profiles[FlagDifferentTransaction].tc[count].next_command[i_next_command]=transactions_temp[count].next_command[i_next_command_temp];
                  }
                  else
                  {
                    printf("\nMAX_NUM_NEXT_COMMANDS exceeded!!\n");
                  }
                }
              }
            }

            //register the profile_sequences
            profile_sequences[profile_sequences_index].session_ID=session_ID;
            profile_sequences[profile_sequences_index].row_ID=profile_sequences_index;
            profile_sequences[profile_sequences_index].transaction_name=FlagDifferentTransaction;
            profile_sequences_index++;
            assert(profile_sequences_index<=MAX_NUM_PROFILE_SEQUENCES);
          }

          //reset the temporary structure
          for(count=0;count<(int)transactions_temp_index;count++)
          {
            transactions_temp[count].row_ID='\0';
            transactions_temp[count].CRC32='\0';
            for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
            {
              transactions_temp[count].next_command[i_next_command]=-1;
            }
            transactions_temp[count].min_timestamp[0]='\0';
            transactions_temp[count].max_timestamp[0]='\0';
          }
          transactions_temp_index=0;
        }
        //end: process the transaction that ended in the last command

        strcpy(session_old_timestamp,session_timestamp);
        time_diff(delta_timestamp,session_timestamp,session_old_timestamp);
        //process the current command
        transactions_temp[transactions_temp_index].row_ID=transactions_temp_index;
        transactions_temp[transactions_temp_index].command_code=command_code;
        transactions_temp[transactions_temp_index].CRC32=session_CRC32;
        for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
        {
          transactions_temp[transactions_temp_index].next_command[i_next_command]=-1;
        }
        transactions_temp[transactions_temp_index].next_command[0]=transactions_temp_index+1;
        strcpy(transactions_temp[transactions_temp_index].min_timestamp,delta_timestamp);
        strcpy(transactions_temp[transactions_temp_index].max_timestamp,delta_timestamp);
        transactions_temp_index++;
        assert(transactions_temp_index<=MAX_NUM_COMMANDS);
      }
      //it is a new command of an already started transaction
      else
      {
        time_diff(delta_timestamp,session_timestamp,session_old_timestamp);
        transactions_temp[transactions_temp_index].row_ID=transactions_temp_index;
        transactions_temp[transactions_temp_index].command_code=command_code;
        transactions_temp[transactions_temp_index].CRC32=session_CRC32;
        for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
        {
          transactions_temp[transactions_temp_index].next_command[i_next_command]=-1;
        }
        transactions_temp[transactions_temp_index].next_command[0]=transactions_temp_index+1;
        strcpy(transactions_temp[transactions_temp_index].min_timestamp,delta_timestamp);
        strcpy(transactions_temp[transactions_temp_index].max_timestamp,delta_timestamp);
        transactions_temp_index++;
        assert(transactions_temp_index<=MAX_NUM_COMMANDS);
      }

      FirstTransaction=1;
      session_old_Transaction_ID=session_Transaction_ID;
      session_old_ID=session_ID;
      strcpy(session_old_timestamp,session_timestamp);
    }
  }
  //start: the last transaction must be considered too
  if(FirstTransaction!=0)
  {
    //start: Detect loops
    transactions_temp_index=Detect_Loop(transactions_temp,transactions_temp_index);
    //end: Detect loops

    //start: Compare just ended transaction with already existing ones
    FlagDifferentTransaction=Compare_Transactions(profiles,transactions_temp,transactions_temp_index);
    //end: Compare just ended transaction with already existing ones

    // If the new transaction is different from the existing ones copy the new transaction to the profiles
    if (FlagDifferentTransaction==-1)
    {
      //copy the new transaction to the profiles
      assert(transactions_temp_index>0);
      if((transactions=(struct transaction *)malloc((transactions_temp_index)*sizeof(struct transaction)))==NULL)
      {
        ERROR_MESSAGE("learner.h: transactions");
      }
      for(count=0;count<(int)transactions_temp_index;count++)
      {
        transactions[count].row_ID=transactions_temp[count].row_ID;
        transactions[count].command_code=transactions_temp[count].command_code;
        transactions[count].CRC32=transactions_temp[count].CRC32;
        for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
        {
          transactions[count].next_command[i_next_command]=transactions_temp[count].next_command[i_next_command];
        }
        strcpy(transactions[count].min_timestamp,transactions_temp[count].min_timestamp);
        strcpy(transactions[count].max_timestamp,transactions_temp[count].max_timestamp);
      }
      //assign the new transaction to the profiles
      profiles[MyTransactionName].name=MyTransactionName;
      profiles[MyTransactionName].count++;
      profiles[MyTransactionName].tc=transactions;
      profiles[MyTransactionName].num_commands=transactions_temp_index;
      users[MyTransactionName].profile_name=MyTransactionName;
      strcpy(users[MyTransactionName].profile_user,session_user);

      //register the profile_sequences
      profile_sequences[profile_sequences_index].session_ID=session_old_ID;
      profile_sequences[profile_sequences_index].row_ID=profile_sequences_index;
      profile_sequences[profile_sequences_index].transaction_name=MyTransactionName;
      profile_sequences_index++;
      assert(profile_sequences_index<=MAX_NUM_PROFILE_SEQUENCES);

      MyTransactionName++;
      assert(MyTransactionName<MAX_NUM_TRANSACTIONS);
      time_diff(session_timestamp_diff,session_timestamp,initial_session_timestamp);
      fprintf(profile_time_file,"%i %i %s %s\n",command_number,MyTransactionName,session_timestamp,session_timestamp_diff);
    }
    // If the new transaction is equal from the existing ones updates the MIN_TIMESTAMP and the MAX_TIMESTAMP
    else
    {
      //update statistics
      profiles[FlagDifferentTransaction].count++;
      //Update Timestamps
      for(count=0;count<(int)transactions_temp_index;count++)
      {
        //updates the min_timestamp
        if(strcmp(transactions_temp[count].min_timestamp,profiles[FlagDifferentTransaction].tc[count].min_timestamp)<0)
        {
          strcpy(profiles[FlagDifferentTransaction].tc[count].min_timestamp,transactions_temp[count].min_timestamp);
        }
        //updates the max_timestamp
        if(strcmp(transactions_temp[count].max_timestamp,profiles[FlagDifferentTransaction].tc[count].max_timestamp)>0)
        {
          strcpy(profiles[FlagDifferentTransaction].tc[count].max_timestamp,transactions_temp[count].max_timestamp);
        }
      }
      //Update the next_command[]
      for(count=0;count<(int)transactions_temp_index;count++)
      {
        for(i_next_command_temp=0;i_next_command_temp<MAX_NUM_NEXT_COMMANDS;i_next_command_temp++)
        {
          i_next_command=0;
          while ((i_next_command<MAX_NUM_NEXT_COMMANDS) && (transactions_temp[count].next_command[i_next_command_temp]!=profiles[FlagDifferentTransaction].tc[count].next_command[i_next_command]))
          {
            i_next_command++;
          }
          if (i_next_command==MAX_NUM_NEXT_COMMANDS)
          {
            i_next_command=0;
            while ((i_next_command<MAX_NUM_NEXT_COMMANDS) && (profiles[FlagDifferentTransaction].tc[count].next_command[i_next_command]>=0))
            {
              i_next_command++;
            }
            if (i_next_command!=MAX_NUM_NEXT_COMMANDS)
            {
              profiles[FlagDifferentTransaction].tc[count].next_command[i_next_command]=transactions_temp[count].next_command[i_next_command_temp];
            }
            else
            {
              printf("\nMAX_NUM_NEXT_COMMANDS exceeded!!\n");
            }
          }
        }
      }

      //register the profile_sequences
      profile_sequences[profile_sequences_index].session_ID=session_old_ID;
      profile_sequences[profile_sequences_index].row_ID=profile_sequences_index;
      profile_sequences[profile_sequences_index].transaction_name=FlagDifferentTransaction;
      profile_sequences_index++;
      assert(profile_sequences_index<MAX_NUM_PROFILE_SEQUENCES);
    }

    //reset the temporary structure
    for(count=0;count<(int)transactions_temp_index;count++)
    {
      transactions_temp[count].row_ID='\0';
      transactions_temp[count].command_code='\0';
      transactions_temp[count].CRC32='\0';
      for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
      {
        transactions_temp[count].next_command[i_next_command]=-1;
      }
      transactions_temp[count].min_timestamp[0]='\0';
      transactions_temp[count].max_timestamp[0]='\0';
    }
    transactions_temp_index=0;
  }
  //end: the last transaction must be considered too

  //The profiles will be sorted from which count the most to which count the least
  quick_sort_profiles(profiles, 0, MyTransactionName-1);
  printf("count_commands: %i\n",command_name);
  printf("count_profiles: %i\n",MyTransactionName);
  if(learn_also_read_only==1)//the parameter is learn_also_read_only and if it is 1 then there will be also learned the read only transaction
  {
    learn_read_only_profiles(profiles,MyTransactionName,users,profile_sequences);
    printf("count_profiles after the learn_read_only_profiles: %i\n",MyTransactionName);
    quick_sort_profiles(profiles, 0, MyTransactionName-1);
  }

  //reorder the name of the profiles
  i=-1;
  for(count=0;count<MyTransactionName;count++)
  {
    if(profiles[count].num_commands!=0)
    {
      i++;
    }
  }

  for(count=MyTransactionName;count>=0;count--)//it is count backwards because of the profiles[count].name=0. -0=0!
  {
    if(profiles[count].num_commands!=0)
    {
      //when changing the profile name the transaction_name of the profile_sequence must also be changed
      for(int count_i=0;count_i<MAX_NUM_PROFILE_SEQUENCES;count_i++)
      {
        if (profile_sequences[count_i].session_ID>0)
        {
          if(profile_sequences[count_i].transaction_name==profiles[count].name)
          {
            profile_sequences[count_i].transaction_name=-i; //it is used the - sign to mark the records changed
          }
        }
      }
      profiles[count].name=i;
      i--;
    }
  }
  //now it is necessary to revert the records changed to their correct values
  for(int count_i=0;count_i<MAX_NUM_PROFILE_SEQUENCES;count_i++)
  {
    if (profile_sequences[count_i].transaction_name<0)
    {
      profile_sequences[count_i].transaction_name=-profile_sequences[count_i].transaction_name;
    }
  }

  /*
  //show the profiles on screen
  for(i=0;i<MAX_NUM_TRANSACTIONS;i++)
  {
  if(profiles[i].num_commands!=0)
  {
  printf("\nName: %u\n",profiles[i].name);
  printf("Num_commands: %u\n",profiles[i].num_commands);
  for(j=0;j<MAX_NUM_TRANSACTIONS;j++)
  {
  if ((users[j].profile_name==profiles[i].name) && (users[j].profile_user[0]!='\0'))
  {
  printf("Profile_user: %s\n",users[j].profile_user);
  }
  }
  transactions=profiles[i].tc;
  for(j=0;j<(int)profiles[i].num_commands;j++)
  {
  printf("\t%i;%i;%u;<",transactions[j].row_ID,transactions[j].command_code,transactions[j].CRC32);
   
  i_next_command=0;
  while ((transactions[j].next_command[i_next_command]>=0) && (i_next_command<MAX_NUM_NEXT_COMMANDS))
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


  for(i=0;i<MAX_NUM_TRANSACTIONS;i++)
  {
    if(profiles[i].num_commands!=0)
    {
      fprintf(profile_file,"profile_name: %u\n",profiles[i].name);
      fprintf(profile_file,"profile_count: %u\n",profiles[i].count);
      fprintf(profile_file,"num_commands: %u\n",profiles[i].num_commands);
      for(j=0;j<MAX_NUM_TRANSACTIONS;j++)
      {
        if ((users[j].profile_name==profiles[i].name) && (users[j].profile_user[0]!='\0'))
        {
          fprintf(profile_file,"profile_user: %s\n",users[j].profile_user);
        }
      }
      transactions=profiles[i].tc;
      for(j=0;j<(int)profiles[i].num_commands;j++)
      {
        fprintf(profile_file,"%i;%i;%u;",transactions[j].row_ID,transactions[j].command_code,transactions[j].CRC32);

        i_next_command=0;
        while ((transactions[j].next_command[i_next_command]>=0) && (i_next_command<MAX_NUM_NEXT_COMMANDS))
        {
          if (i_next_command>0)
          {
            fprintf(profile_file,",");
          }
          fprintf(profile_file,"%i",transactions[j].next_command[i_next_command]);
          i_next_command++;
          assert(i_next_command<MAX_NUM_NEXT_COMMANDS);
        }

        fprintf(profile_file,";%s;%s\n",transactions[j].min_timestamp,transactions[j].max_timestamp);
      }
    }
  }

  count_profile_sequences=0;

  for(i=0;i<MAX_NUM_PROFILE_SEQUENCES;i++)
  {
    if(profile_sequences[i].session_ID>0)
    {
      fprintf(profile_seq_file,"%i;%i;%i\n", profile_sequences[i].session_ID, profile_sequences[i].row_ID, profile_sequences[i].transaction_name);
      count_profile_sequences++;
      assert(count_profile_sequences<MAX_NUM_PROFILE_SEQUENCES);
    }
  }

  //start write in the command_file
  for(count=0;count<command_name;count++)
  {
    fprintf(command_file,"%u;%u;%s;%u\n",commands[count].name,commands[count].command_crc32,   commands[count].command_text,commands[count].count);
  }
  //end write in the command_file_sequence

  //start write in the command_file
  for(count=0;count<command_sequences_index;count++)
  {
    fprintf(command_seq_file,"%u;%u;%u\n",command_sequences[count].session_ID,command_sequences[count].row_ID,command_sequences[count].command_crc32);
  }
  //end write in the command_file_sequence

  /* Close command_time_file */
  if( fclose(command_time_file) )
    printf("The file '%s' was not closed",command_time_file_name );
  else
    printf("The file '%s' was closed\n",command_time_file_name );

  /* Close command_seq_file */
  if( fclose( command_seq_file ) )
    printf("The file '%s' was not closed",command_seq_file_name );
  else
    printf("The file '%s' was closed\n",command_seq_file_name );

  /* Close command_file */
  if( fclose( command_file ) )
    printf("The file '%s' was not closed",command_file_name );
  else
    printf("The file '%s' was closed\n",command_file_name );

  /* Close profile_time_file */
  if( fclose(profile_time_file) )
    printf("The file '%s' was not closed",profile_time_file_name );
  else
    printf("The file '%s' was closed\n",profile_time_file_name );

  /* Close profile_seq_file */
  if( fclose( profile_seq_file ) )
    printf("The file '%s' was not closed",profile_seq_file_name );
  else
    printf("The file '%s' was closed\n",profile_seq_file_name );

  /* Close profile_file */
  if( fclose( profile_file ) )
    printf("The file '%s' was not closed",profile_file_name );
  else
    printf("The file '%s' was closed\n",profile_file_name );

  /* Close aud_file */
  if( fclose( aud_file ) )
    printf("The file '%s' was not closed",aud_file_name );
  else
    printf("The file '%s' was closed\n",aud_file_name );

  count_computed_profile_sequences=0;
  for(i=0;i<count_profile_sequences-1;i++)
  {
    from_transaction_name=profile_sequences[i].transaction_name;
    to_transaction_name=profile_sequences[i+1].transaction_name;
    for(j=0;j<count_computed_profile_sequences;j++)
    {
      if((from_transaction_name==computed_profile_sequences[j].from_transaction_name) && (to_transaction_name==computed_profile_sequences[j].to_transaction_name))
      {
        break;
      }
    }
    if(j==count_computed_profile_sequences)
    {
      //there is no record of this sequence of profiles
      computed_profile_sequences[count_computed_profile_sequences].from_transaction_name=from_transaction_name;
      computed_profile_sequences[count_computed_profile_sequences].to_transaction_name=to_transaction_name;
      computed_profile_sequences[count_computed_profile_sequences].percentage=1;
      count_computed_profile_sequences++;
      assert(count_computed_profile_sequences<MAX_NUM_PROFILE_SEQUENCES);

    }
    else
    {
      computed_profile_sequences[j].percentage++;
    }
  }

  /*
  for(count=0;count<count_computed_profile_sequences;count++)
  {
  printf("%i;%i;%i\n",computed_profile_sequences[count].from_transaction_name,computed_profile_sequences[count].to_transaction_name,computed_profile_sequences[count].percentage);
  }
  */

  //sort by from_transaction_name
  quick_sort(computed_profile_sequences,0,count_computed_profile_sequences-1);
  //  int from_transaction_name;
  int from_transaction_name_old;
  int start_index=0;
  from_transaction_name=computed_profile_sequences[0].from_transaction_name;
  from_transaction_name_old=from_transaction_name;
  //sort by to_transaction_name
  for(count=0;count<count_computed_profile_sequences;count++)
  {
    from_transaction_name=computed_profile_sequences[count].from_transaction_name;
    if(from_transaction_name_old!=from_transaction_name)
    {
      quick_sort2(computed_profile_sequences,start_index,count-1);
      from_transaction_name_old=from_transaction_name;
      start_index=count;
    }
  }


  for(count=0;count<count_computed_profile_sequences;count++)
  {
    fprintf(profile_seq2_file,"%i;%i;%i\n",computed_profile_sequences[count].from_transaction_name,computed_profile_sequences[count].to_transaction_name,computed_profile_sequences[count].percentage);
  }


//start calculate the computed command sequences
//TODO Quicksort of the commands and of the sequence of commands 
  count_computed_command_sequences=0;
  for(i=0;i<command_sequences_index-1;i++)
  {
    from_command_crc32=command_sequences[i].command_crc32;
    to_command_crc32=command_sequences[i+1].command_crc32;
    for(j=0;j<count_computed_command_sequences;j++)
    {
      if((from_command_crc32==computed_command_sequences[j].from_command_crc32) && (to_command_crc32==computed_command_sequences[j].to_command_crc32))
      {
        break;
      }
    }
    if(j==count_computed_command_sequences)
    {
      //there is no record of this sequence of profiles
      computed_command_sequences[count_computed_command_sequences].from_command_crc32=from_command_crc32;
      computed_command_sequences[count_computed_command_sequences].to_command_crc32=to_command_crc32;
      computed_command_sequences[count_computed_command_sequences].percentage=1;
      count_computed_command_sequences++;
      assert(count_computed_command_sequences<MAX_NUM_PROFILE_SEQUENCES);
    }
    else
    {
      computed_command_sequences[j].percentage++;
    }
  }

  for(count=0;count<count_computed_command_sequences;count++)
  {
    fprintf(command_seq2_file,"%u;%u;%i\n",computed_command_sequences[count].from_command_crc32,computed_command_sequences[count].to_command_crc32,computed_command_sequences[count].percentage);
  }
//end calculate the computed command sequences

  // Close profile_seq_file
  if( fclose( command_seq2_file ) )
    printf("The file '%s' was not closed\n",command_seq2_file_name );
  else
    printf("The file '%s' was closed\n",command_seq2_file_name );

  // Close profile_seq_file
  if( fclose( profile_seq2_file ) )
    printf("The file '%s' was not closed\n",profile_seq2_file_name );
  else
    printf("The file '%s' was closed\n",profile_seq2_file_name );


  assert(session_command!=NULL);
  if (session_command!=NULL)
    free(session_command);
  session_command=NULL;

  assert(transactions_temp!=NULL);
  if (transactions_temp!=NULL)
    free(transactions_temp);
  transactions_temp=NULL;

  assert(profile_sequences!=NULL);
  if (profile_sequences!=NULL)
    free(profile_sequences);
  profile_sequences=NULL;

  assert(computed_profile_sequences!=NULL);
  if (computed_profile_sequences!=NULL)
    free(computed_profile_sequences);
  computed_profile_sequences=NULL;

  for(count=0;count<MAX_NUM_TRANSACTIONS;count++)
  {
    if (profiles[count].tc!=NULL)
    {
      free(profiles[count].tc);
      profiles[count].tc=NULL;
    }
  }
  assert(profiles!=NULL);
  if (profiles!=NULL)
    free(profiles);
  profiles=NULL;

  assert(users!=NULL);
  if (users!=NULL)
    free(users);
  users=NULL;


  /*
    int ch;
    printf("\npress any key to end.");
    ch=getchar();
  */
}

void read_record(FILE *read_file,char * parameter_value)
{
  int count;
  int ch;

  count=0;
  do
  {
    ch=fgetc(read_file);
    if(ch!=13)
    {
      parameter_value[count]=ch;
    }
    count++;
  }
  while (!feof(read_file) && (ch!=';') && (ch!=10));
  parameter_value[count-1]='\0';
}

//
// Start Test_Start_Transaction
//
int Test_Start_Transaction(int session_ID,int session_old_ID,int session_transaction_ID,int session_old_transaction_ID)
{
  //
  // Start of: Test if it is the start of a new transaction
  //
  int FlagNewTransaction;

  /*
    FlagNewTransaction=1;
    if (((session_transaction_ID==session_old_transaction_ID) && (session_transaction_ID!=-1)) //it is not a pl/sql block (-1) and neither was the previous command
        || ((session_old_transaction_ID==0) && (session_transaction_ID==1)) //the last command was a select (0) and the current is an insert (1), delete (1) or update (1)
        || (((session_old_transaction_ID>=0) || (session_old_transaction_ID<-1)) && (session_transaction_ID<-1))) //it the current command is a commit (-2) or rollback (-3) and the previous command was not a pl/sql block (-1)
    {
      FlagNewTransaction=0;
    }
  */

  if ((session_old_transaction_ID<0) || (session_ID!=session_old_ID))
  {
    FlagNewTransaction=1;
  }
  else
  {
    FlagNewTransaction=0;
  }

  // FlagNewTransaction is 1 if the old transaction has ended and a new one has started
  return FlagNewTransaction;
}
//
// End of: Test_Start_Transaction
//

//
// Start of: Detect_Loop
//
unsigned int Detect_Loop(struct transaction *transactions_temp,unsigned int transactions_temp_index)
{
  int count;
  int aux;
  int i;
  int j;
  int k;
  int FlagLoop;
  int CountMatch;
  int NewCountMatch;
  int i_next_command;

  //j is the number of commands contained in the loop
  for(j=1;j<=((int)transactions_temp_index+1)/2;j++)
  {
    i=0;
    count=0;
    NewCountMatch=0;

    //count is the position of the start command of the loop being searched
    while (count<(int)(transactions_temp_index-2*j+1))
    {
      CountMatch=-1;
      for(k=0;k<j;k++)
      {
        i=k;
        FlagLoop=1;
        NewCountMatch=0;
        do
        {
          i=i+j;
          if (count+i>=(int)transactions_temp_index)
          {
            FlagLoop=0;
            break;
          }
          if (transactions_temp[count+k].CRC32!=transactions_temp[count+i].CRC32)
          {
            i=i-j;
            FlagLoop=0;
          }
          else
          {
            NewCountMatch++;
          }
        }
        while((FlagLoop==1) && (count+i+j<(int)transactions_temp_index));
        if((NewCountMatch==0) && (FlagLoop==0))
        {
          CountMatch=-1;
          break;
        }
        if ((NewCountMatch>0) && (NewCountMatch<CountMatch))
        {
          CountMatch=NewCountMatch;
        }
        else
        {
          if (CountMatch==-1)
          {
            CountMatch=NewCountMatch;
          }
        }
      }
      if(CountMatch>0)
      {

        for(aux=0;aux<=i-k;aux++)
        {
          //updates the min_timestamp
          if(strcmp(transactions_temp[count+k+aux].min_timestamp,transactions_temp[count+k-j+aux].min_timestamp)<0)
          {
            strcpy(transactions_temp[count+k-j+aux].min_timestamp,transactions_temp[count+k+aux].min_timestamp);
          }
          //updates the max_timestamp
          if(strcmp(transactions_temp[count+k+aux].max_timestamp,transactions_temp[count+k-j+aux].max_timestamp)>0)
          {
            strcpy(transactions_temp[count+k-j+aux].max_timestamp,transactions_temp[count+k+aux].max_timestamp);
          }
        }
        //        for(aux=0;aux<=i-k;aux++)
        for(aux=0;aux<CountMatch*j;aux++)
        {
          //deletes the repeated command
          delete_transaction(transactions_temp,count+k,transactions_temp_index);
          transactions_temp_index--;
        }

        i_next_command=0;
        while ((transactions_temp[count+k-1].next_command[i_next_command]>=0) && (i_next_command<MAX_NUM_NEXT_COMMANDS))
        {
          i_next_command++;
        }
        if (i_next_command!=MAX_NUM_NEXT_COMMANDS)
        {
          transactions_temp[count+j-1].next_command[i_next_command]=count;
        }
        else
        {
          printf("\nMAX_NUM_NEXT_COMMANDS exceeded!!\n");
        }

        //        printf("j:%i i:%i count:%i CountMatch:%i transactions_temp_index:%i\n",j,i,count,CountMatch,transactions_temp_index);
      }
      count++;
    }
  }

  return transactions_temp_index;
}
//
// End of: Detect_Loop
//
void delete_transaction(struct transaction *transactions_temp,int index,unsigned int transactions_temp_index)
{
  int count;
  int i_next_command;

  for(count=index;count<(int)transactions_temp_index;count++)
  {
    transactions_temp[count].command_code=transactions_temp[count+1].command_code;
    transactions_temp[count].CRC32=transactions_temp[count+1].CRC32;
    strcpy(transactions_temp[count].min_timestamp,transactions_temp[count+1].min_timestamp);
    strcpy(transactions_temp[count].max_timestamp,transactions_temp[count+1].max_timestamp);
  }
  transactions_temp[count].row_ID='\0';
  transactions_temp[count].CRC32='\0';
  for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
  {
    transactions_temp[count].next_command[i_next_command]=-1;
  }
  transactions_temp[count].min_timestamp[0]='\0';
  transactions_temp[count].max_timestamp[0]='\0';
}


int Compare_Transactions(struct profile *profiles,struct transaction *transactions_temp,unsigned int transactions_temp_index)
{
  int i;
  unsigned int count;
  int match=-1;

  i=0;
  while(profiles[i].name!=-1)
  {
    if(profiles[i].num_commands==transactions_temp_index)
    {
      for(count=0;count<profiles[i].num_commands;count++)
      {
        if(profiles[i].tc[count].CRC32==transactions_temp[count].CRC32)
        {
          match=i;
        }
        else
        {
          match=-1;
          break;
        }
      }
    }
    if(match>-1)
    {
      break;
    }
    i++;
    assert(i<MAX_NUM_TRANSACTIONS);
  }
  //  printf("match: %i\n",match);
  return match;
}


void quick_sort(struct computed_profile_sequence computed_profile_sequences[MAX_NUM_PROFILE_SEQUENCES], int lb, int ub)
{
  struct computed_profile_sequence a;              /* key holder */
  struct computed_profile_sequence temp;           /* temporary variable, used in swapping */
  int up, down;

  if (lb >= ub)
    return;

  a.from_transaction_name = computed_profile_sequences[ub].from_transaction_name;
  a.to_transaction_name = computed_profile_sequences[ub].to_transaction_name;
  a.percentage = computed_profile_sequences[ub].percentage;
  up = ub;
  down = lb;

  do
  {
    while ((computed_profile_sequences[down].from_transaction_name <= a.from_transaction_name)&& (down < up))         // scan the keys from left to right
    {
      down++;
      assert(down<MAX_NUM_PROFILE_SEQUENCES);
    }
    while ((computed_profile_sequences[up].from_transaction_name >= a.from_transaction_name)&& (down < up))             // scan the keys from right to left
    {
      up--;
      assert(up>=0);
    }
    if (down < up)
    {
      //interchange records
      temp.from_transaction_name = computed_profile_sequences[down].from_transaction_name;
      temp.to_transaction_name = computed_profile_sequences[down].to_transaction_name;
      temp.percentage = computed_profile_sequences[down].percentage;

      computed_profile_sequences[down].from_transaction_name = computed_profile_sequences[up].from_transaction_name;
      computed_profile_sequences[down].to_transaction_name = computed_profile_sequences[up].to_transaction_name;
      computed_profile_sequences[down].percentage = computed_profile_sequences[up].percentage;

      computed_profile_sequences[up].from_transaction_name = temp.from_transaction_name;
      computed_profile_sequences[up].to_transaction_name = temp.to_transaction_name;
      computed_profile_sequences[up].percentage= temp.percentage;
    }
  }
  while (down < up);

  // interchange records
  temp.from_transaction_name = computed_profile_sequences[down].from_transaction_name;
  temp.to_transaction_name = computed_profile_sequences[down].to_transaction_name;
  temp.percentage = computed_profile_sequences[down].percentage;

  computed_profile_sequences[down].from_transaction_name = computed_profile_sequences[ub].from_transaction_name;
  computed_profile_sequences[down].to_transaction_name = computed_profile_sequences[ub].to_transaction_name;
  computed_profile_sequences[down].percentage = computed_profile_sequences[ub].percentage;

  computed_profile_sequences[ub].from_transaction_name = temp.from_transaction_name;
  computed_profile_sequences[ub].to_transaction_name = temp.to_transaction_name;
  computed_profile_sequences[ub].percentage= temp.percentage;

  quick_sort(computed_profile_sequences, lb, down-1);         /* recursive call - sort first subtable */
  quick_sort(computed_profile_sequences, down+1, ub);         /* recursive call - sort second subtable */
}

void quick_sort2(struct computed_profile_sequence computed_profile_sequences[MAX_NUM_PROFILE_SEQUENCES], int lb, int ub)
{
  struct computed_profile_sequence a;              /* key holder */
  struct computed_profile_sequence temp;           /* temporary variable, used in swapping */
  int up, down;

  if (lb >= ub)
    return;

  a.from_transaction_name = computed_profile_sequences[ub].from_transaction_name;
  a.to_transaction_name = computed_profile_sequences[ub].to_transaction_name;
  a.percentage = computed_profile_sequences[ub].percentage;
  up = ub;
  down = lb;

  do
  {
    while ((computed_profile_sequences[down].to_transaction_name <= a.to_transaction_name)&& (down < up))         // scan the keys from left to right
    {
      down++;
      assert(down<MAX_NUM_PROFILE_SEQUENCES);
    }
    while ((computed_profile_sequences[up].to_transaction_name >= a.to_transaction_name)&& (down < up))             // scan the keys from right to left
    {
      up--;
      assert(up>=0);
    }
    if (down < up)
    {
      //interchange records
      temp.from_transaction_name = computed_profile_sequences[down].from_transaction_name;
      temp.to_transaction_name = computed_profile_sequences[down].to_transaction_name;
      temp.percentage = computed_profile_sequences[down].percentage;

      computed_profile_sequences[down].from_transaction_name = computed_profile_sequences[up].from_transaction_name;
      computed_profile_sequences[down].to_transaction_name = computed_profile_sequences[up].to_transaction_name;
      computed_profile_sequences[down].percentage = computed_profile_sequences[up].percentage;

      computed_profile_sequences[up].from_transaction_name = temp.from_transaction_name;
      computed_profile_sequences[up].to_transaction_name = temp.to_transaction_name;
      computed_profile_sequences[up].percentage= temp.percentage;
    }
  }
  while (down < up);

  // interchange records
  temp.from_transaction_name = computed_profile_sequences[down].from_transaction_name;
  temp.to_transaction_name = computed_profile_sequences[down].to_transaction_name;
  temp.percentage = computed_profile_sequences[down].percentage;

  computed_profile_sequences[down].from_transaction_name = computed_profile_sequences[ub].from_transaction_name;
  computed_profile_sequences[down].to_transaction_name = computed_profile_sequences[ub].to_transaction_name;
  computed_profile_sequences[down].percentage = computed_profile_sequences[ub].percentage;

  computed_profile_sequences[ub].from_transaction_name = temp.from_transaction_name;
  computed_profile_sequences[ub].to_transaction_name = temp.to_transaction_name;
  computed_profile_sequences[ub].percentage= temp.percentage;

  quick_sort2(computed_profile_sequences, lb, down-1);         /* recursive call - sort first subtable */
  quick_sort2(computed_profile_sequences, down+1, ub);         /* recursive call - sort second subtable */
}

void quick_sort_profiles(struct profile profiles[MAX_NUM_TRANSACTIONS], int lb, int ub)
{
  struct profile a;              /* key holder */
  struct profile temp;           /* temporary variable, used in swapping */
  int up, down;

  if (lb >= ub)
    return;

  a.name = profiles[ub].name;
  a.count = profiles[ub].count;
  a.num_commands = profiles[ub].num_commands;
  a.tc=profiles[ub].tc;

  up = ub;
  down = lb;

  do
  {
    //It will be sorted from largest to smallest, therefore I've changed the comparison signs (>= instead of <= and < instead of >
    //and the && condition
    while ((profiles[down].count >= a.count) && (down < up))         // scan the keys from left to right
    {
      down++;
      assert(down<MAX_NUM_TRANSACTIONS);
    }
    while ((profiles[up].count <= a.count) && (down < up))             // scan the keys from right to left
    {
      up--;
      assert(up>=0);
    }
    if (down < up)
    {
      //interchange records
      temp.name = profiles[down].name;
      temp.count = profiles[down].count;
      temp.num_commands = profiles[down].num_commands;
      temp.tc=profiles[down].tc;

      profiles[down].name = profiles[up].name;
      profiles[down].count = profiles[up].count;
      profiles[down].num_commands = profiles[up].num_commands;
      profiles[down].tc = profiles[up].tc;

      profiles[up].name = temp.name;
      profiles[up].count = temp.count;
      profiles[up].num_commands = temp.num_commands;
      profiles[up].tc = temp.tc;

    }
  }
  while (down < up);

  // interchange records
  temp.name = profiles[down].name;
  temp.count = profiles[down].count;
  temp.num_commands = profiles[down].num_commands;
  temp.tc=profiles[down].tc;

  profiles[down].name = profiles[ub].name;
  profiles[down].count = profiles[ub].count;
  profiles[down].num_commands = profiles[ub].num_commands;
  profiles[down].tc = profiles[ub].tc;

  profiles[ub].name = temp.name;
  profiles[ub].count = temp.count;
  profiles[ub].num_commands = temp.num_commands;
  profiles[ub].tc = temp.tc;



  quick_sort_profiles(profiles, lb, down-1);         /* recursive call - sort first subtable */
  quick_sort_profiles(profiles, down+1, ub);         /* recursive call - sort second subtable */
}

void learn_read_only_profiles(struct profile *profiles,int &count_profiles,struct user *users,struct profile_sequence *profile_sequences)
{
  struct transaction *transactions;
  int MatchTransaction,CountMatch,CountMatch2,PartialCountMatch2;
  int MyTransactionName;
  int transactions_temp_index;
  int i,j,count,ii;
  int i_next_command,j_next_command;

  MyTransactionName=count_profiles;
  for(i=0;i<count_profiles;i++)
  {
    //if the profile does not exist anymore then read the next profile
    if (profiles[i].name==-1)
    {
      continue;
    }
    //search for other profiles with similar ends
    for(j=0;j<count_profiles;j++)
    {
      //if the profile does not exist anymore then read the next profile is not the same of i (j!=i)
      if ((profiles[j].name==-1) || (i==j))
      {
        continue;
      }
      CountMatch=0;
      if (profiles[j].num_commands<profiles[i].num_commands)
      {
        for (count=1;count<(int)profiles[j].num_commands+1;count++)
        {
          if (profiles[j].tc[profiles[j].num_commands-count].CRC32==profiles[i].tc[profiles[i].num_commands-count].CRC32)
          {
            CountMatch++;
          }
          else
          {
            CountMatch=0;
            break;
          }
        }
        if (CountMatch==(int)profiles[j].num_commands)
        {
          MatchTransaction=j;
        }
      }
      //the result of the subtraction must be only select statements
      if (CountMatch>0)
      {
        for (count=0;count<(int)profiles[i].num_commands-CountMatch;count++)
        {
          if (profiles[i].tc[count].command_code!=SELECT_CODE)
          {
            CountMatch=0;
            break;
          }
        }
      }

      if (CountMatch>0)
      {
        printf("Profile %i can be subtracted from Profile %i\n",profiles[MatchTransaction].name,profiles[i].name);
        //Test if this select only transaction is in the beginning of another transaction
        //Only in that case it is considered a new select only transaction
        for (ii = 0; ii < count_profiles; ii++)
        {
          CountMatch2=0;
          PartialCountMatch2=0;
          //if the profile does not exist anymore then read the next profile
          if ((profiles[ii].name==-1) || (ii==i) || (ii==MatchTransaction))
          {
            continue;
          }
          if (profiles[i].num_commands-CountMatch<profiles[ii].num_commands)
          {
            for (count=0;count<CountMatch;count++)
            {
              if (profiles[ii].tc[count].CRC32==profiles[i].tc[count].CRC32)
              {
                PartialCountMatch2++;
              }
              else
              {
                PartialCountMatch2=0;
                break;
              }
            }
            if (PartialCountMatch2>0)
            {
              if (profiles[ii].tc[count+1].CRC32!=profiles[i].tc[count+1].CRC32)
              {
                PartialCountMatch2++;
              }
              else
              {
                PartialCountMatch2=0;
              }
            }
            if (PartialCountMatch2==(int)profiles[i].num_commands-CountMatch)
            {
              CountMatch2++;
              break;
            }
          }
        }
        //If the select only transaction appears in two or more transactions then it is a good select only transaction
        if (CountMatch2>0)
        {
          printf("There are other profiles with the same start commands\n");
          printf("New Read Only Profile\n");
          transactions_temp_index=profiles[i].num_commands-CountMatch;

          //updates the next command of the profiles[MatchTransaction] with those of profiles[i]
          for(count=0;count<(int)transactions_temp_index-1;count++)
          {
            for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS-transactions_temp_index;i_next_command++)
            {
              for(j_next_command=0;j_next_command<MAX_NUM_NEXT_COMMANDS;j_next_command++)
              {
                if(profiles[i].tc[count+transactions_temp_index].next_command[i_next_command]-transactions_temp_index==profiles[MatchTransaction].tc[count].next_command[j_next_command])
                {
                  break;
                }
              }
              if((j_next_command==MAX_NUM_NEXT_COMMANDS) && (profiles[i].tc[count+transactions_temp_index].next_command[i_next_command]>=0))
              {
                j_next_command=0;
                while(profiles[MatchTransaction].tc[count].next_command[j_next_command]!=-1)
                {
                  j_next_command++;
                  assert(j_next_command<MAX_NUM_NEXT_COMMANDS);
                }
                profiles[MatchTransaction].tc[count].next_command[j_next_command]=profiles[i].tc[count+transactions_temp_index].next_command[i_next_command]-transactions_temp_index;
              }
            }
            //Update Timestamps
            //updates the min_timestamp
            if(strcmp(profiles[i].tc[count+transactions_temp_index].min_timestamp,profiles[MatchTransaction].tc[count].min_timestamp)<0)
            {
              strcpy(profiles[MatchTransaction].tc[count].min_timestamp,profiles[i].tc[count+transactions_temp_index].min_timestamp);
            }
            //updates the max_timestamp
            if(strcmp(profiles[i].tc[count+transactions_temp_index].max_timestamp,profiles[MatchTransaction].tc[count].max_timestamp)>0)
            {
              strcpy(profiles[MatchTransaction].tc[count].max_timestamp,profiles[i].tc[count+transactions_temp_index].max_timestamp);
            }
          }

          //New record of a read only transaction in Transactions
          //copy the new transaction to the profiles
          assert(transactions_temp_index>0);
          if((transactions=(struct transaction *)malloc((transactions_temp_index)*sizeof(struct transaction)))==NULL)
          {
            ERROR_MESSAGE("learner.h: transactions");
          }
          for(count=0;count<(int)transactions_temp_index;count++)
          {
            transactions[count].row_ID=profiles[i].tc[count].row_ID;
            transactions[count].command_code=profiles[i].tc[count].command_code;
            transactions[count].CRC32=profiles[i].tc[count].CRC32;
            for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
            {
              transactions[count].next_command[i_next_command]=profiles[i].tc[count].next_command[i_next_command];
            }
            strcpy(transactions[count].min_timestamp,profiles[i].tc[count].min_timestamp);
            strcpy(transactions[count].max_timestamp,profiles[i].tc[count].max_timestamp);
          }
          //assign the new transaction to the profiles
          profiles[MyTransactionName].name=MyTransactionName;
          profiles[MyTransactionName].count=profiles[i].count;
          profiles[MyTransactionName].tc=transactions;
          profiles[MyTransactionName].num_commands=transactions_temp_index;

          users[MyTransactionName].profile_name=MyTransactionName;
          strcpy(users[MyTransactionName].profile_user,users[i].profile_user);

          //register the profile_sequences
          for(int count_i=0;count_i<MAX_NUM_PROFILE_SEQUENCES-1;count_i++)
          {
            if(profile_sequences[count_i].transaction_name==profiles[i].name)
            {
              for(int count_j=MAX_NUM_PROFILE_SEQUENCES-1;count_j>count_i+1;count_j--)
              {
                profile_sequences[count_j].session_ID=profile_sequences[count_j-1].session_ID;
                profile_sequences[count_j].row_ID=profile_sequences[count_j-1].row_ID+1;
                profile_sequences[count_j].transaction_name=profile_sequences[count_j-1].transaction_name;
              }
              profile_sequences[count_i+1].transaction_name=profiles[MatchTransaction].name;
              profile_sequences[count_i+1].row_ID=profile_sequences[count_i].row_ID+1;
              profile_sequences[count_i+1].session_ID=profile_sequences[count_i].session_ID;
              profile_sequences[count_i].transaction_name=MyTransactionName;
              profile_sequences[count_i].session_ID=profile_sequences[count_i-1].session_ID;
            }
          }

          //add the profiles[i].count to the profiles[MatchTransaction].count
          profiles[MatchTransaction].count+=profiles[i].count;

          //Find all the other transactions where the start is equal to the new read only transaction and remove the equal initial commands
          for (ii = 0; ii < count_profiles; ii++)
          {
            //if the profile does not exist anymore then read the next profile
            if ((profiles[ii].name==-1) || (ii==MyTransactionName))
            {
              continue;
            }
            if (profiles[MyTransactionName].num_commands<profiles[ii].num_commands)
            {
              PartialCountMatch2=0;
              for (count=0;count<(int)profiles[MyTransactionName].num_commands;count++)
              {
                if (profiles[ii].tc[count].CRC32==profiles[MyTransactionName].tc[count].CRC32)
                {
                  PartialCountMatch2++;
                }
                else
                {
                  PartialCountMatch2=0;
                  break;
                }
              }
              if (PartialCountMatch2==(int)profiles[MyTransactionName].num_commands)
              {
                printf("profiles[%i].name: %i has the same beginning\n",ii,profiles[ii].name);

                //The profiles[ii] has the same beginning of profiles[i], but before removing this beginning we must
                //update the next command of the profiles[MatchTransaction] with those of profiles[i]
                for(count=0;count<(int)transactions_temp_index-1;count++)
                {
                  for(i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS-transactions_temp_index;i_next_command++)
                  {
                    for(j_next_command=0;j_next_command<MAX_NUM_NEXT_COMMANDS;j_next_command++)
                    {
                      if(profiles[i].tc[count+transactions_temp_index].next_command[i_next_command]-transactions_temp_index==profiles[ii].tc[count].next_command[j_next_command])
                      {
                        break;
                      }
                    }
                    if((j_next_command==MAX_NUM_NEXT_COMMANDS) && (profiles[i].tc[count+transactions_temp_index].next_command[i_next_command]>=0))
                    {
                      j_next_command=0;
                      while(profiles[ii].tc[count].next_command[j_next_command]!=-1)
                      {
                        j_next_command++;
                        assert(j_next_command<MAX_NUM_NEXT_COMMANDS);
                      }
                      profiles[ii].tc[count].next_command[j_next_command]=profiles[i].tc[count+transactions_temp_index].next_command[i_next_command]-transactions_temp_index;
                    }
                  }
                  //Update Timestamps
                  //updates the min_timestamp
                  if(strcmp(profiles[i].tc[count+transactions_temp_index].min_timestamp,profiles[ii].tc[count].min_timestamp)<0)
                  {
                    strcpy(profiles[ii].tc[count].min_timestamp,profiles[i].tc[count+transactions_temp_index].min_timestamp);
                  }
                  //updates the max_timestamp
                  if(strcmp(profiles[i].tc[count+transactions_temp_index].max_timestamp,profiles[ii].tc[count].max_timestamp)>0)
                  {
                    strcpy(profiles[ii].tc[count].max_timestamp,profiles[i].tc[count+transactions_temp_index].max_timestamp);
                  }
                }

                //The profiles[ii] has the same beginning of profiles[i], then this beginning must be removed
                profiles[ii].num_commands-=PartialCountMatch2;
                //                for(count=0;count<PartialCountMatch2+1;count++)
                for(count=0;count<PartialCountMatch2;count++)
                {
                  profiles[ii].tc[count].row_ID=profiles[ii].tc[count+PartialCountMatch2].row_ID-PartialCountMatch2;
                  profiles[ii].tc[count].command_code=profiles[ii].tc[count+PartialCountMatch2].command_code;
                  profiles[ii].tc[count].CRC32=profiles[ii].tc[count+PartialCountMatch2].CRC32;
                  for(int i_next_command=0;i_next_command<MAX_NUM_NEXT_COMMANDS;i_next_command++)
                  {
                    profiles[ii].tc[count].next_command[i_next_command]=profiles[ii].tc[count+PartialCountMatch2].next_command[i_next_command]-PartialCountMatch2;
                  }
                  strcpy(profiles[ii].tc[count].min_timestamp,profiles[ii].tc[count+PartialCountMatch2].min_timestamp);
                  strcpy(profiles[ii].tc[count].max_timestamp,profiles[ii].tc[count+PartialCountMatch2].max_timestamp);
                }


                //register the profile_sequences
                for(int count_i=0;count_i<MAX_NUM_PROFILE_SEQUENCES-1;count_i++)
                {
                  if(profile_sequences[count_i].transaction_name==profiles[ii].name)
                  {
                    for(int count_j=MAX_NUM_PROFILE_SEQUENCES-1;count_j>count_i;count_j--)
                    {
                      profile_sequences[count_j].session_ID=profile_sequences[count_j-1].session_ID;
                      profile_sequences[count_j].row_ID=profile_sequences[count_j-1].row_ID+1;
                      profile_sequences[count_j].transaction_name=profile_sequences[count_j-1].transaction_name;
                    }
                    profile_sequences[count_i].transaction_name=MyTransactionName;
                    profile_sequences[count_i].row_ID=profile_sequences[count_i].row_ID+1;
                    profile_sequences[count_i].session_ID=profile_sequences[count_i-1].session_ID;
                    count_i++;
                    assert(count_i<MAX_NUM_PROFILE_SEQUENCES);
                  }
                }
                //	break;
              }
            }
          }

          //delete the profiles[i]
          profiles[i].name=-1;
          profiles[i].count=0;
          profiles[i].num_commands=0;
          //          transactions=profiles[i].tc;
          assert(profiles[i].tc!=NULL);
          if (profiles[i].tc!=NULL)
          {
            free(profiles[i].tc);
            profiles[i].tc=NULL;
          }

          MyTransactionName++;
          assert(MyTransactionName<MAX_NUM_TRANSACTIONS);
        }
      }
    }
  }


  //show the read only profiles on screen
  for(i=count_profiles;i<MyTransactionName;i++)
  {
    if(profiles[i].num_commands!=0)
    {
      printf("Name: %u\n",profiles[i].name);
      printf("Num_commands: %u\n",profiles[i].num_commands);
      transactions=profiles[i].tc;
      for(j=0;j<(int)profiles[i].num_commands;j++)
      {
        printf("\t%i;%i;%u;<",transactions[j].row_ID,transactions[j].command_code,transactions[j].CRC32);

        i_next_command=0;
        while ((transactions[j].next_command[i_next_command]>=0) && (i_next_command<MAX_NUM_NEXT_COMMANDS))
        {
          if (i_next_command>0)
          {
            printf(",");
          }
          printf("%i",transactions[j].next_command[i_next_command]);
          i_next_command++;
          assert(i_next_command<MAX_NUM_NEXT_COMMANDS);
        }
        printf(">;%s;%s\n",transactions[j].min_timestamp,transactions[j].max_timestamp);
      }
    }
  }

  //returns the correct number of profiles
  count_profiles=MyTransactionName;
}

