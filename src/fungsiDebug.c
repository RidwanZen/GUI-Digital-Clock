#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include "../inc/fungsiDebug.h"

int debug(const char *function_name, char *debug_type, char *debug_msg, ...){
    
	time_t debug_time;
	time(&debug_time);
	
	struct tm *d_tm;
	d_tm = localtime(&debug_time);
	
	char time_str[25];
	memset(time_str, 0x00, 25*sizeof(char));
	sprintf(time_str, "%02d-%02d-%02d %02d:%02d:%02d", d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec);
	
	char tmp_debug_msg[100];
	memset(tmp_debug_msg,0,100*sizeof(char));
	va_list aptr;
	va_start(aptr, debug_msg);
	vsprintf(tmp_debug_msg, debug_msg, aptr);
	va_end(aptr);
	
	if(strcmp(debug_type,"INFO:")==0)
	{
		printf("%s%s %s %s:%s %s\n", KGRN, time_str, debug_type, function_name, KWHT,tmp_debug_msg);
	}
	else if (strcmp(debug_type,"ERROR:")==0)
	{
		printf("%s%s %s %s:%s %s\n", KRED, time_str, debug_type, function_name, KWHT,tmp_debug_msg);
	}
	else if (strcmp(debug_type,"WARNING:")==0)
	{
		printf("%s%s %s %s:%s %s\n", KYEL, time_str, debug_type, function_name, KWHT,tmp_debug_msg);
	} 
    return 0;
}
