//generic functions

#include <stdio.h>
#include <string.h>
#include <stdlib.h>	       // For malloc(), free(), exit(), atoi()
#include <assert.h>
#ifdef WIN32
#include <winsock2.h>         // For socket(), connect(), send(), and recv()
#else
#include <sys/time.h>		//for gettimeofday()
#include <time.h>		//for struct tm
#endif

#ifdef WIN32
//#include <TCHAR.H>
#include <direct.h>
#include <io.h>
//#include <dos.h>
#else
#include <dirent.h>             /* readdir(), etc.                    */
#endif

#ifndef NDEBUG
char DEBUG_MESSAGE[1024];
#define ERROR_MESSAGE(x) __ERROR_MESSAGE__(x,__FILE__,__LINE__,__FUNCTION__)
void __ERROR_MESSAGE__(char * msg,const char * file,int line,const char * function)
{
  sprintf(DEBUG_MESSAGE,"FILE: %s LINE: %i FUNCTION: %s\n%s",file,line,function,msg);
  perror(DEBUG_MESSAGE);
  exit(1);
}
#else
#define ERROR_MESSAGE(x) __ERROR_MESSAGE__(x)
void __ERROR_MESSAGE__(char * msg)
{
  perror(msg);
  exit(1);
}
#endif

FILE *debug_file;	//File containing all the packet information
FILE *audit_file;	//File containing the important information from the packet
FILE *session_file;	//File containing the sessions information
FILE *config_file;	//Configuration file
FILE *aud_file;		//File containing the aud information
FILE *profile_file;	//File containing the profiles
FILE *profile_seq_file;	//File containing the profiles execution sequence
FILE *profile_seq2_file;//File containing the profiles, the profiles that where executed next and the count
FILE *profile_time_file;//File containing when the profile was learned 
FILE *delay_debug_file;	//File containing delay debug information in sniffer mode and containing detector delay debug information in detector mode 
FILE *command_file;	//File containing the commands
FILE *command_seq_file;	//File containing the commands execution sequence
FILE *command_seq2_file;//File containing the commands, the commands that where executed next and the count
FILE *command_time_file;//File containing when the command was learned
FILE *detect_debug_file;//File containing detector debug information
//FILE *detect_delay_debug_file;	//File containing detector delay debug information

#define MAX_FILE_NAME 256

char database_release_name[256]={0};

char config_file_name[MAX_FILE_NAME];
unsigned int DB_listener_port=1521;
unsigned char DB_listener_ip[16]="localhost";
unsigned char client_ip[16]="*";
char SHOW_DISPLAY='y';
char SAVE_DEBUG='y';
char detector_option[256];
char kill_option[256];

bool hidden=false;
char mode[256]="sniffer";
char header[256]="-----Header-----";
char footer[256]="-----Footer-----";
char start_session[256]="-----Start_session-----";
char end_session[256]="-----End_session-----";

char remove_files[256]="";
char append_files[256]="all";

//Linux network interface
char linux_interface[32]="eth0";


char* int2string(int val, int base);
int string2int(char* digit, int& result);
int str_find_unsensitive2(unsigned char *main_string, char *search_string);
int str_find_unsensitive(unsigned char *main_string,unsigned int main_length, char *search_string);
int str_find(unsigned char *main_string,unsigned int main_length, char *search_string);
void date_format(char *date,int &year,int &month,int &day,int &hour,int &minute,int &second,int &milisecond);
void time_diff(char *time_result,char *date_final,char *date_initial);
void get_timestamp(char *session_timestamp);
void PrintError(char *);
void FatalPrintError(char *);
int count_file_radical(char *file_name, char * file_extension);
void file_radical(char *file_name, char * file_extension,int file_radical);
void remove_files_created(char *file_name, char * file_extension);
void remove_files_created_by_mode(char *mode);


char* int2string(int val, int base)
{

  static char buf[32] = {0};

  int i = 30;

  if (val==0) return "0";
  for(; val && i ; --i, val /= base)

    buf[i] = "0123456789abcdef"[val % base];

  return &buf[i+1];

}

int string2int(char* digit, int& result)
{
  result = 0;

  //--- Convert each digit char and add into result.
  while (*digit >= '0' && *digit <='9')
  {
    result = (result * 10) + (*digit - '0');
    digit++;
  }

  //--- Check that there were no non-digits at end.
  if (*digit != 0)
  {
    return -1;
  }

  return 0;
}

void substring(char* mainstring, int start, int end, char *resultstring)
{
  int count;
  int aux;

  aux=0;
  for(count=start;count<=end;count++)
  {
    resultstring[aux]=mainstring[count];
    aux++;
  }
  resultstring[aux]='\0';
}

void date_format(char *date,int &year,int &month,int &day,int &hour,int &minute,int &second,int &milisecond)
{
  char aux[32];
  substring(date,0,1,aux);
  string2int(aux,day);
  substring(date,3,4,aux);
  string2int(aux,month);
  substring(date,6,9,aux);
  string2int(aux,year);
  substring(date,11,12,aux);
  string2int(aux,hour);
  substring(date,14,15,aux);
  string2int(aux,minute);
  substring(date,17,18,aux);
  string2int(aux,second);
  substring(date,20,22,aux);
  string2int(aux,milisecond);
}

void  time_diff(char *time_result,char *date_final,char *date_initial)
{
  int year1,year2,year_result;
  int month1,month2,month_result;
  int day1,day2,day_result;
  int hour1,hour2,hour_result;
  int minute1,minute2,minute_result;
  int second1,second2,second_result;
  int milisecond1,milisecond2,milisecond_result;

  date_format(date_initial,year1,month1,day1,hour1,minute1,second1,milisecond1);
  date_format(date_final,year2,month2,day2,hour2,minute2,second2,milisecond2);
  milisecond_result=milisecond2-milisecond1;
  if(milisecond_result<0)
  {
    milisecond_result+=1000;
    second2--;
  }
  second_result=second2-second1;
  if(second_result<0)
  {
    second_result+=60;
    minute2--;
  }
  minute_result=minute2-minute1;
  if(minute_result<0)
  {
    minute_result+=60;
    hour2--;
  }
  hour_result=hour2-hour1;
  if(hour_result<0)
  {
    hour_result+=24;
    day2--;
  }
  day_result=day2-day1;
  if(day_result<0)
  {
    day_result+=30; //i know this is not correct, but is unlikelly two commands being distant one monyh
    month2--;
  }
  month_result=month2-month1;
  if(month_result<0)
  {
    month_result+=12;
    year2--;
  }
  year_result=year2-year1;

  //  printf("%i/%i/%i %i:%i:%i.%i\n",year1,month1,day1,hour1,minute1,second1,milisecond1);

#ifdef WIN32
  sprintf(time_result,"%0.2d:%0.2d:%0.2d.%0.3d" ,hour_result,minute_result,second_result,milisecond_result);
#else
  sprintf(time_result,"%02d:%02d:%02d.%03d" ,hour_result,minute_result,second_result,milisecond_result);
#endif
}

int str_find_unsensitive2(unsigned char *main_string, char *search_string)
{
  unsigned int i;
  unsigned int j;
  unsigned int match;
  unsigned int main_length;
  unsigned int search_length;

  main_length=0;
  while (*(main_string+main_length)!=0)
  {
    main_length++;
  }

  search_length=0;
  while (*(search_string+search_length)!=0)
  {
    search_length++;
  }

  if (main_length>1 && search_length>1 && main_length>search_length)
  {
    i=0;
    j=0;
    do
    {
      match=0;
      for(j=0;j<search_length-1;j++)
      {
        if ((*(main_string+j+i)==*(search_string+j))
            || ((*(main_string+j+i)==*(search_string+j)+32) && *(search_string+j)>=65 && *(search_string+j)<=90)
            || (*(main_string+j+i)+32==*(search_string+j) && *(main_string+j+i)>=65 && *(main_string+j+i)<=90))
        {
          match=1;
        }
        else
        {
          match=0;
          break;
        }
      }
      i++;
    }
    while(match==0 && i+search_length<main_length);
    if (match!=0)
      return(--i);
    else
      return(-1);
  }
  else
    return(-1);
}

int str_find_unsensitive(unsigned char *main_string,unsigned int main_length, char *search_string)
{
  unsigned int i;
  unsigned int j;
  unsigned int match;
  unsigned int search_length;

  search_length=0;
  while (*(search_string+search_length)!=0)
  {
    search_length++;
  }

  if (main_length>1 && search_length>1 && main_length>search_length)
  {
    i=0;
    j=0;
    do
    {
      match=0;
      for(j=0;j<=search_length-1;j++)
      {
        if ((*(main_string+j+i)==*(search_string+j))
            || ((*(main_string+j+i)==*(search_string+j)+32) && *(search_string+j)>=65 && *(search_string+j)<=90)
            || (*(main_string+j+i)+32==*(search_string+j) && *(main_string+j+i)>=65 && *(main_string+j+i)<=90))
        {
          match=1;
        }
        else
        {
          match=0;
          break;
        }
      }
      i++;
    }
    while(match==0 && i+search_length<main_length);
    if (match!=0)
      return(--i);
    else
      return(-1);
  }
  else
    return(-1);
}

int str_find(unsigned char *main_string,unsigned int main_length, char *search_string)
{
  unsigned int i;
  unsigned int j;
  unsigned int match;
  unsigned int search_length;

  search_length=0;
  while (*(search_string+search_length)!=0)
  {
    search_length++;
  }

  if (main_length>1 && search_length>1 && main_length>search_length)
  {
    match=0;
    i=0;
    j=0;
    do
    {
      for(j=0;j<search_length;j++)
      {
        if (*(main_string+j+i)!=*(search_string+j))
        {
          match=0;
          break;
        }
        else
          match=1;
      }
      i++;
    }
    while(match==0 && i+search_length<main_length);
    if (match!=0)    	return(--i);
    else
      return(-1);
  }
  else
    return(-1);
}


void get_timestamp(char *session_timestamp)
{
#ifdef WIN32
  SYSTEMTIME st;
#else
#define SIZE 256
  time_t curtime;
  struct tm *st;

  struct timeval tp;
  //The struct timeval structure represents an elapsed time. It is declared in sys/time.h and has the following members:
  //long int tv_sec    This represents the number of whole seconds of elapsed time.
  //long int tv_usec    This is the rest of the elapsed time (a fraction of a second), represented as the number of microseconds. It is always less than one million.
#endif
#ifdef WIN32
  GetSystemTime(&st);
  sprintf(session_timestamp,"%0.2d/%0.2d/%0.4d %0.2d:%0.2d:%0.2d.%0.3d" ,st.wDay,st.wMonth,st.wYear,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds);
#else
  gettimeofday(&tp, NULL);
  curtime=tp.tv_sec;

  // Convert it to local time representation.
  st = localtime (&curtime);
  //	strftime (buffer, SIZE, "%d/%m/%Y %H:%M:%S", st);

  //from http://dotnet.di.unipi.it/content/sscli/docs/doxygen/pal/time_8c-source.html
  int old_seconds;
  int new_seconds;
  long Milliseconds;

  Milliseconds = tp.tv_usec/1000;
  old_seconds = st->tm_sec;
  new_seconds = tp.tv_sec%60;

  /* just in case we reached the next second in the interval between
  time() and gettimeofday() */
  if( old_seconds!=new_seconds )
  {
    Milliseconds = 999;
  }
  //printf("%02d/%02d/%04d %02d:%02d:%02d.%03i %s GMT%+ld\n",st->tm_mday, st->tm_mon + 1, st->tm_year +1900,st->tm_hour, st->tm_min, st->tm_sec, tp.tv_usec/1000,tzname[0], timezone / 3600);
  sprintf(session_timestamp,"%02d/%02d/%04d %02d:%02d:%02d.%03li",
          st->tm_mday, st->tm_mon + 1, st->tm_year +1900,st->tm_hour, st->tm_min, st->tm_sec,Milliseconds);
#endif
}

//error message printing routines.
void PrintError(char *str)
{
  ERROR_MESSAGE(str);
}


void FatalPrintError(char *msg)
{
  PrintError(msg);
  exit(1);
}

int count_file_radical(char *file_name, char * file_extension)
{
#ifdef WIN32

  int dir;
  int count_file_name=-1;
  int count_file_name_aux=-1;
  char debug_file_name[MAX_FILE_NAME]="";
  char debug_file_name_complete[MAX_FILE_NAME]="";
  char debug_file_name_aux[MAX_FILE_NAME]="";
  char max_file_name[MAX_FILE_NAME]="";
  int done;
  int aux;
  _finddata_t blk;

  dir = chdir(".");
  if (dir!=0)
  {
    printf("Cannot read directory\n");
  }
  strcpy(debug_file_name_complete,file_name);
  strcat(debug_file_name_complete,file_extension);
  done=_findfirst(debug_file_name_complete,&blk);
  aux=done;
  if (aux!=-1)
    count_file_name=0;
  //  printf("inicio count_file_name %i\n",count_file_name);

  strcpy(debug_file_name,file_name);
  strcat(debug_file_name,"_");
  strcpy(debug_file_name_complete,debug_file_name);
  strcat(debug_file_name_complete,"*");
  strcat(debug_file_name_complete,file_extension);
  done=_findfirst(debug_file_name_complete,&blk);
  //  printf("debug_file_name_complete %s\n",debug_file_name_complete);
  aux=done;
  while(aux!=-1)
  {
    for(unsigned int count=strlen(debug_file_name);count<strlen(blk.name);count++)
    {
      if(blk.name[count]!='.')
        max_file_name[count-strlen(debug_file_name)]=blk.name[count];
      else
        max_file_name[count-strlen(debug_file_name)]='\0';
    }
    if(strlen(max_file_name)>0)
    {
      count_file_name=atoi(max_file_name);
      if(count_file_name>count_file_name_aux)
      {
        count_file_name_aux=count_file_name;
        strcpy(debug_file_name_aux,blk.name);
      }
    }
    aux=_findnext(done,&blk);
  }
  //  printf("fim count_file_name %i\n",count_file_name);

#else

  DIR* dir;			// pointer to the scanned directory.
  struct dirent* entry;	// pointer to one directory entry.
  int count_file_name=-1;
  int count_file_name_aux=-1;
  char debug_file_name[MAX_FILE_NAME]="";
  char debug_file_name_aux[MAX_FILE_NAME]="";
  char max_file_name[MAX_FILE_NAME]="";

  // open the directory for reading
  dir = opendir(".");

  if (!dir)
  {
    printf("Cannot read directory");
  }

  strcpy(debug_file_name,file_name);
  strcat(debug_file_name,file_extension);
  // scan the directory, traversing each sub-directory, and
  // matching the pattern for each file name.
  while ((entry = readdir(dir)))
  {
    // check if the pattern matchs.
    if (entry->d_name && strcmp(entry->d_name, debug_file_name)==0)
    {
      count_file_name=0;
      break;
    }
  }
  //  printf("inicio count_file_name %i\n",count_file_name);

  rewinddir(dir);
  strcpy(debug_file_name,file_name);
  strcat(debug_file_name,"_");
  //  printf("debug_file_name %s\n",debug_file_name);
  // scan the directory, traversing each sub-directory, and
  // matching the pattern for each file name.
  while ((entry = readdir(dir)))
  {
    // check if the pattern matchs.
    if (entry->d_name && strstr(entry->d_name, debug_file_name))
    {
      for(int count=strlen(debug_file_name);count<strlen(entry->d_name);count++)
      {
        if(entry->d_name[count]!='.')
          max_file_name[count-strlen(debug_file_name)]=entry->d_name[count];
        else
          max_file_name[count-strlen(debug_file_name)]='\0';
      }
      if(strlen(max_file_name)>0)
      {
        count_file_name=atoi(max_file_name);
        if(count_file_name>count_file_name_aux)
        {
          count_file_name_aux=count_file_name;
          strcpy(debug_file_name_aux,entry->d_name);
        }
      }
    }
  }
#endif
  //  printf("count_file_name: %i\n",count_file_name);
  return(count_file_name);
}

void file_radical(char *file_name, char * file_extension, int file_radical)
{
  char * debug_file_count;
  int count_file_name=0;


  if((debug_file_count=(char *)malloc((32)*sizeof(char)))==NULL)
    ERROR_MESSAGE("debug_file_count");

  //  printf("file_radical %i\n",file_radical);
  if(file_radical>0)
  {
    debug_file_count=int2string(file_radical,10);
    strcat(file_name,"_");
    strcat(file_name,debug_file_count);
  }
  strcat(file_name,file_extension);
}

void remove_files_created(char *file_name, char * file_extension)
{
  char file_name_remove[MAX_FILE_NAME]="";
  int count_file_name;
  int count;

  count_file_name=count_file_radical(file_name,file_extension);
  for(count=0;count<=count_file_name;count++)
  {
    strcpy(file_name_remove,file_name);
    file_radical(file_name_remove, file_extension,count);
    if( remove(file_name_remove) == -1 )
        printf( "Error deleting file: %s\n",file_name_remove);
    else
      printf( "File %s successfully deleted\n",file_name_remove);
  }
}
void remove_files_created_by_mode(char *mode)
{
  char file_name[MAX_FILE_NAME]="";
  char file_extension[32]="";

  if((strcmp(mode,"sniffer")==0) || (strcmp(mode,"all")==0))
  {
    strcpy(file_extension,".txt");
    strcpy(file_name,"auditory");
    remove_files_created(file_name, file_extension);
    strcpy(file_name,"delay_debug");
    remove_files_created(file_name, file_extension);
    strcpy(file_name,"debug");
    remove_files_created(file_name, file_extension);
    strcpy(file_name,"session");
    remove_files_created(file_name, file_extension);
  }
  if((strcmp(mode,"justparser")==0) || (strcmp(mode,"learner")==0) || (strcmp(mode,"all")==0))
  {
    strcpy(file_extension,".txt");
    strcpy(file_name,"aud");
    remove_files_created(file_name, file_extension);
  }
  if((strcmp(mode,"justlearner")==0) || (strcmp(mode,"learner")==0) || (strcmp(mode,"all")==0))
  {
    strcpy(file_extension,".txt");
    strcpy(file_name,"profile");
    remove_files_created(file_name, file_extension);
    strcpy(file_name,"prof_seq");
    remove_files_created(file_name, file_extension);
    strcpy(file_name,"prof_time");
    remove_files_created(file_name, file_extension);
    strcpy(file_name,"prof_seq2");
    remove_files_created(file_name, file_extension);
  }
  if((strcmp(mode,"detector")==0) || (strcmp(mode,"all")==0))
  {
    strcpy(file_extension,".txt");
    strcpy(file_name,"detect_debug");
    remove_files_created(file_name, file_extension);
    strcpy(file_name,"delay_debug");
    remove_files_created(file_name, file_extension);
  }
}
