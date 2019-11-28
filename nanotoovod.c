/* -*-C-*-
 *
 * File:         nanoitoovod.c
 * Description:  This program binds to an HP OpenView Operations Message 
 *               Stream Interface where it waits for messages comming from
 *               a trap template, with the application field set to a specific
 *               value and where the obejct field follows a specific format:
 * 
 *               ipaAlarmType~ipaAlarmCauseType
 * 
 *               The values are parsed from the object field, integers are
 *               converted into text if possible and a new message is generated onto
 *               the stream.
 * 
 * Revisions
 * 
 * 2007-10-31 (1.2): Made the logging function variadic.
 *  
 * 2007-10-30 (1.1): Made into daemon. Incoporated syslog and BSS_ID <-> hostname
 *                   lookup. 
 * 
 * 2007-10-20 (1.0): Initial version
 * 
 * (c) Copyright Thomas S. Iversen, 2007, while being employed by TeliaSonera
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <opcapi.h>
#include <locale.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>

/* Global definitions */

#define DAEMON_NAME "nanotoovod"
#define RUNNING_DIR "/var/lib/nano-integration/"
#define LOCK_FILE   DAEMON_NAME ".lock"
#define LOG_FILE    DAEMON_NAME ".log"
#define BSC_LIST_FILE DAEMON_NAME "-bscs.lst"
#define BSC_FETCH_CMD "/etc/init.d/ipaccess-bss-manager list | /bin/grep -i connected | /usr/bin/awk '{ print $1 \" \" $2 }' > " BSC_LIST_FILE
#define CONFIG_FILE "/usr/local/etc/" DAEMON_NAME ".conf"
#define DEFAULT_BSC_LIST_AGE_TRESHOLD 1800 /* refetch list every 30 minutes */
#define DEFAULT_LOG_LEVEL LOG_WARNING /* log warnings and more criitcal stuff */
#define USE_SYSLOG  1 /* 1 for logging through syslog, 0 for logging to logfile */
#define MAX_LENGTH 256 /* maxlength of the strings read from the bsc list, could be a problem */
#define BUF_SIZE   512 /* Length of buffer we use when concatenating strings */
#define DNS_SUFFIX ".prod.telia.dk"

#define FALSE (0)
#define TRUE (1)

/* 
 * Structures
 */

struct bsc
{ 
   char *id;
   char *name;
   struct bsc *next;
};

/* Global variables */

struct bsc *bsc_list=NULL;
int bsc_list_age_threshold = DEFAULT_BSC_LIST_AGE_TRESHOLD;
int log_level = DEFAULT_LOG_LEVEL;

/* 
 * Logs message to filename
 * 
 * Variadic simelar to syslog. This is a wrapper
 * for being able to do multiple things and still
 * look a lot like a syslog function in the code.
 */

void log_message(int priority, const char *format, ...)
{
   va_list arg_list;
   char buffer[1024];

   if(log_level < priority)
     return;
   
   va_start(arg_list, format);
   vsnprintf(buffer,1023, format, arg_list);
   va_end(arg_list);
   
   buffer[1023]= '\0';
   
   if(USE_SYSLOG) 
     {
	openlog(DAEMON_NAME, LOG_PID, LOG_DAEMON);
	syslog(priority, buffer);
	closelog();
		
     }
    else 
     {
	FILE *logfile;
	logfile=fopen(LOG_FILE,"a");
	if(!logfile) return;
	fprintf(logfile, "%s\n", buffer);
	fclose(logfile);
     }
   
}

/*
 * Lookup pointer to char * with name of bsc
 * if it exists. If it doesn't return NULL
 */
char * get_bsc_name (char *bsc_id) 
{
   char * bsc_name = NULL;
   struct bsc *list_ptr=bsc_list;
   if(bsc_id != NULL) {
      while(list_ptr != NULL && bsc_name == NULL) 
	{
	   if(strcmp(list_ptr->id, bsc_id) == 0) 
	     bsc_name=list_ptr->name;
	   else 
	     list_ptr=list_ptr->next;
	}
   }
   return bsc_name;
}



/* 
 * Signal handler for unix signals 
 */

void signal_handler(sig)
  int sig;
{
   switch(sig) 
     {
	
      case SIGHUP:
	log_message(LOG_INFO,"Hangup signal catched. Reconfiguring.");
	char id[] = "08A4110A470CB41F";
	char *name = get_bsc_name(id);
	log_message(LOG_DEBUG, "id: %s corresponds to name %s", "08A4110A470CB41F", name);
	break;
      case SIGTERM:
	log_message(LOG_INFO,"Terminate signal catched. Exiting.");
	exit(0);
	break;
     }
   
}

/* 
 * procedure for turning into a daemon
 */

void daemonize()
{
   int i,lfp;
   char str[10];
   if(getppid()==1) return; /* already a daemon */
   i=fork();
   if (i<0) {log_message(LOG_CRIT, "Could not fork, exiting."); exit(1); } /* fork error */
   if (i>0) exit(0); /* parent exits */
   /* child (daemon) continues */
   setsid(); /* obtain a new process group */
   for (i=getdtablesize();i>=0;--i) close(i); /* close all descriptors */
   i=open("/dev/null",O_RDWR); dup(i); dup(i); /* handle standart I/O */
   umask(027); /* set newly created file permissions */
   chdir(RUNNING_DIR); /* change running directory */
   lfp=open(LOCK_FILE,O_RDWR|O_CREAT,0640);
   if (lfp<0) {log_message(LOG_CRIT, "Could not open lockfile, exiting."); exit(1); } /* can not open */
   if (lockf(lfp,F_TLOCK,0)<0) { log_message(LOG_CRIT, "Could not obtain exclusive rights to lock, other instance running, exiting..."); exit(0); } /* can not lock */
   /* first instance continues */
   log_message(LOG_DEBUG,"Pid: %d\n",getpid());
   write(lfp,str,strlen(str)); /* record pid to lockfile */
   signal(SIGCHLD,SIG_IGN); /* ignore child */
   signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
   signal(SIGTTOU,SIG_IGN);
   signal(SIGTTIN,SIG_IGN);
   signal(SIGHUP,signal_handler); /* catch hangup signal */
   signal(SIGTERM,signal_handler); /* catch kill signal */
}

/* 
 * Getting the BSC list through a system call 
 */

int get_bsc_list () 
{
   log_message(LOG_DEBUG, "Fetching bsc list");
   return system(BSC_FETCH_CMD);
}

/* 
 * Freeing a bsc item
 * 
 * input ptr to item
 */

void free_item (struct bsc *item) 
{
   if(item != NULL) 
     {
	if(item->id != NULL) { free(item->id); } 
	if(item->name != NULL) { free(item->name); }
	free(item);
     }
}

/*
 * Freeing a whole bsc list
 * 
 * input ptr to list
 */

void free_list (struct bsc *list)
{
   struct bsc *ptr=list;
   struct bsc *tmp_ptr;
   int i=0;
   while(ptr != NULL) 
     {
	tmp_ptr=ptr;
	ptr=ptr->next;
	free_item(tmp_ptr);
	i++;
     }
   if(i != 0) 
     log_message(LOG_DEBUG, "Freeing BSC list. Freed %d items", i);
}

/*
 * Printing a bsc list 
 * 
 * input ptr to list
 */

void print_bsc_list (struct bsc *list) 
{
   int i=1;
   log_message(LOG_DEBUG, "Printing BSC list");
   while(list != NULL)
     {
	log_message(LOG_DEBUG, "BSC[%d]: id=%s, name=%s", i, list->id, list->name);
	list=list->next;
	i++;
     }
}


/* 
 * (Re)fetches the bsc list if it is to old
 */

int fetch_bsc_list ()
{
   int age;
   struct stat* buf;
   char id[MAX_LENGTH];
   char name[MAX_LENGTH];

   /* Does file exist? If not fetch bsc_list */
   
   FILE *fp = fopen(BSC_LIST_FILE,"r");
   if(!fp) 
     {
	get_bsc_list();
     } 
   else 
     {
	fclose(fp);
     }
   
   /* File do exist, but is it too old, should we refetch it? */
   buf=(struct stat *)malloc(sizeof (struct stat));
   if(buf == NULL) 
     {
	log_message(LOG_ERR, "Could not obtain stat struct for time age");
     }

   
   if (stat(BSC_LIST_FILE,buf) != 0) 
     {
       	log_message(LOG_ERR, "Could not obtain stat data for file");
	return 1;
     }
   
   age=(int) difftime(time(NULL),buf->st_mtime);
   
   if(age > bsc_list_age_threshold) 
     {
	log_message(LOG_DEBUG, BSC_LIST_FILE " is older than %d seconds. Refetching BSC list", bsc_list_age_threshold);
	get_bsc_list();
     }

   /* Now we now that the file exists and is up to date, then read it */
   int error=0; /* keep track of wether or not we have discovered any errors trying to fetch the list */
   
   FILE *fp1 = fopen(BSC_LIST_FILE, "r");
   if(!fp1) 
     {
	log_message(LOG_ERR, BSC_LIST_FILE " could not be opened, not possible to distingish alarms between bsc's");
     }
    else 
     {
	struct bsc *new_list=NULL;
	struct bsc *new_item=NULL;
	while(!error && (fscanf(fp1,"%s %s",&id,&name)!=EOF))
	  {
	     /* show what we parsed */
	     log_message(LOG_DEBUG, "Parsing BSC info. id=%s, name=%s", id, name);
	     
	     /* Obtain memory for holding this info */
	     new_item=(struct bsc *)malloc(sizeof (struct bsc));
	     
	     if(new_item != NULL) 
	       { 
		  /* Initialize memory to a known good state */
		  new_item->id = NULL;
		  new_item->name = NULL;

		  new_item->id = strdup(id);
		  new_item->name = strdup(name);

		  if(new_item->id != NULL && new_item->name != NULL) 
		    {
		       /* now we have the structure in place, link it into list */
		       new_item->next=new_list;
		       new_list=new_item;
		       new_item=NULL;
		    } 
		  else
		    {
		       error=1;
		    }
	       } 
	     else
	       {
		  error=1;
	       }

	     if(error) 
		  free_item(new_item);
	     
	  }
	if(error) 
	  {
	     
	     log_message(LOG_ERR, "Error during fetch of updated BSC list. List not updated");
	     free_list(new_list);
	  }
	
	fclose(fp1);
	free_list(bsc_list);
	bsc_list=new_list;
	print_bsc_list(bsc_list);
     }
}





/*
 * Main
 * 
 * Connects to an MSI, scanning for messages where the appfield 
 * contains keyword. If it doesn't, put message back onto stream
 * 
 * If it does, see if we can parse object field. If we can not
 * put message back onto stream.
 * 
 * If we can parse object field, convert values if possible. 
 * and put message back onto stream.
 *
 * Do this until the end of the program.
 * 
 */
 
int main ()
{
   opcdata    msg;
   opcregcond reg_cond;
   char       buf[BUF_SIZE];
   int 	      interface_type;
   char       *instance="NANO";
   char       *opcreg_app="Nano-BSS";
   int 	      mode;
   int 	      max_entries;
   int 	      interface_id;
   long       cond_id;
   int 	      ret;
   char       *obj = NULL, *obj_dup = NULL;
   int 		ipaAlarmType, ipaAlarmCauseType;
   char       ipaAlarmSource[BUF_SIZE];
   
   enum       exit_values { exit_opcif_open = 1, exit_cant_create_reg_cond = 2 };
   
   char       *ipaAlarmTypes[] = 
     {
	"Communications",
	  "Environment",
	  "Equipment",
	  "Processing",
	  "Quality Of Service",
     };
   
   char       *ipaAlarmCauseTypes[] =
     {
	"",
	  "x721",
	  "gsm",
	  "bts",
	  "bsc",
	  "frip",
	  "gnat",
	  "smgw",
	  "omcr",
	  "platmon",

     };
   
   const char delimiters[] = "~";
   char *token = NULL, *cp = NULL;

   daemonize();

   log_message(LOG_INFO, "Became daemon nicely");

   setlocale(LC_ALL,"");

   /* Open interface to stream in r/w mode */
   interface_type = OPCAGTIF_EXTMSGPROC_READWRITE;   

   /* In what mode should we use the MSI? */
   mode = 0;   
   mode |= OPCIF_ALWAYS;
   mode |= OPCIF_READ_WAIT;
   mode |= OPCIF_CLOSE_FORWARD;
   mode |= OPCIF_IGNORE_MSI_ALREADY_EXISTS; /* If we shut down, uncleanly,
					     * sure we can start up again */ 
   max_entries = 512;
   
   /* Open the MSI interface */
   if ((ret = opcif_open(interface_type, instance, mode, max_entries,
			 &interface_id)) == OPC_ERR_OK)
     {
	log_message(LOG_DEBUG, "returned interface_id: %d\n", interface_id);
     }
   else
     {
	log_message(LOG_CRIT, "Error: opcif_open() = %s. Exiting.", opcdata_report_error (ret));
	exit(exit_opcif_open);
     }
   

   /* Register with registration condition */
   if (opcreg_create(&reg_cond) != OPC_ERR_OK)
     {
	log_message(LOG_CRIT, "Can't create reg_cond. Exiting.");
	exit(exit_cant_create_reg_cond);
     }

   /* Scan for messages where app field is set to the value of opcreg_app */
   opcreg_set_str(reg_cond, OPCREG_APPLICATION, opcreg_app);

   /* register condition */
   if ((ret = opcif_register(interface_id, reg_cond, &cond_id))
       == OPC_ERR_OK)
     {
	log_message(LOG_DEBUG, "returned cond_id: %ld\n", cond_id);
     }
   else
     {
	log_message(LOG_CRIT, "ERROR: opcif_register() = %s. Exiting.", opcdata_report_error (ret));
	exit(1);
     }
   
   opcreg_free(&reg_cond);
   
   fetch_bsc_list();
   

   log_message(LOG_INFO, "Ready to start working in while loop");
   
   while(TRUE) 
     {
	/* Read, modify and write message from MSI instance */
	if (opcdata_create(OPCDATA_EMPTY, &msg) != OPC_ERR_OK)
	  {

	     log_message(LOG_CRIT, "Can't create opcdata structure. Exiting");
	     exit(1);
	  }
	
	if ((ret = opcif_read(interface_id, msg)) == OPC_ERR_OK)
	  {
	     /* Got new message, check the age of the bsc-lookup list */
	     fetch_bsc_list();
	     
	     
	     obj = opcdata_get_str(msg, OPCDATA_OBJECT);
	     
	     /* make dup of obj, we are not allowed to touch stuff
	      * comming from opcdata_get_str as this is internal
	      * to the opcdata structure 
	      */
	     
	     if((obj_dup = strdup(obj)) == NULL)
	       {
		 
		  log_message(LOG_CRIT, "Could not duplicate object string. Out of memory. Exiting");
		  exit(1);
	       }
	     
	     int i = 0;
	     int value;
	     token = strtok(obj_dup, delimiters);
	     while(token != NULL) 
	       {
		  i++;
		  
		  switch(i) 
		    {
		     case 1:
		       value = atoi(token);
		       ipaAlarmType=value;
		       break;
		     case 2:
		       value = atoi(token);
		       ipaAlarmCauseType=value;
		       break;
		     case 3:
		       strncpy(ipaAlarmSource, token, BUF_SIZE-1);
		       break;
		     default:
		       log_message(LOG_DEBUG, "Wrong number of tokens in string");
		       break;
		    }
		  token=strtok(NULL,delimiters);
	       }
	     free(obj_dup);
	     if(i != 3) 
	       {
		  /* Wrong number of tokens, push message back onto stream untouched */
		  log_message(LOG_INFO, "Object field contains a nonsupported number of tokes. Expected 3 got %d",i);
		  
	       } 
	     else 
	       {
		  int nIpaAlarmType= sizeof ipaAlarmTypes / sizeof ipaAlarmTypes[0];
		  int nIpaAlarmCauseType= sizeof ipaAlarmCauseTypes / sizeof ipaAlarmCauseTypes[0];
		    
/*		  if(ipaAlarmType >= 0 && ipaAlarmType < nIpaAlarmType)
		    {
		       printf("ipaAlarmType: %s\n", ipaAlarmTypes[ipaAlarmType]);
		       
		    }
*/
		  if(ipaAlarmCauseType >= 0 && ipaAlarmCauseType < nIpaAlarmCauseType)
		    {
		       (void) strncpy(buf, ipaAlarmCauseTypes[ipaAlarmCauseType], BUF_SIZE-1); 
		       if (opcdata_set_str(msg, OPCDATA_OBJECT, buf)
			   != OPC_ERR_OK)
			 {
			    log_message(LOG_ERR, "Can't set attribute OPCDATA_OBJECT");
			 }
		    }
		  
		  char *bsc_name = get_bsc_name(ipaAlarmSource);
		  int n=strlen(bsc_name);
		  if(BUF_SIZE-1>sizeof(DNS_SUFFIX)+n) 
		    {
		       strncpy(buf, bsc_name, BUF_SIZE-1);
		       strncpy(buf+n,DNS_SUFFIX, BUF_SIZE-1-n);
		       if(opcdata_set_str(msg, OPCDATA_NODENAME, buf)
			  != OPC_ERR_OK) 
			 log_message(LOG_ERR, "Can't set attribute OPCDATA_NODENAME");
		    }
		  
	       }
	     
	     
	     ret = opcif_write (interface_id, msg);
	  }
	else
	  {
	     log_message(LOG_ERR, "ERROR: opcif_read() = %s\n", opcdata_report_error (ret));
	  }
	
	opcdata_free(&msg);
     }
   
}

