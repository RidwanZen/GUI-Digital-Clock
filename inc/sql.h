#ifndef SQL_H
#define SQL_H

#include <sqlite3.h>

void enco_sql_destroy(void* d);
int enco_sql_open_buffer();
int sql_insert_alarm_list(const char *_alarm_time, char *_ringtone, char *_mesg, ...);
void sql_GetValue_alarm();
int sql_select_table ();
void cek_quary();

#endif