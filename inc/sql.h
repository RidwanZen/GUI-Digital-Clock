#ifndef SQL_H
#define SQL_H

#include <sqlite3.h>


const unsigned char *alarm_time, *alarm_mesg, *alarm_ringtones;
int count;

void enco_sql_destroy(void* d);
int enco_sql_open_buffer();
int sql_insert_alarm_list(const char *_alarm_time, char *_ringtone, char *_mesg, ...);
void sql_GetValue_alarm();
void sql_select_table ();
void cek_quary();

#endif