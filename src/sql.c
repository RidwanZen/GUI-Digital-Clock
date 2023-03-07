#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <time.h>
#include <unistd.h>

#include "../inc/main.h"
#include "../inc/sql.h"

#define ALARM_FILE     "log/alarm_list.db"

#define TBLALARM   	"alarm"

#define LOGTIME			"strftime(\"%%Y-%%m-%%d %%H:%%M:%%f\", \"now\", \"localtime\")"

static sqlite3 *alarm_list = NULL;

static sqlite3_stmt *select_alarm = NULL;

void enco_sql_destroy(void* d){
	if(d){
		free(d);
		d = NULL;
	}
}

void enco_sql_add_column(sqlite3 *__db__,char*__table_name,char *__col){
	const char *alter_table = "ALTER TABLE %s ADD COLUMN %s;";
	int len = strlen(alter_table)+strlen(__table_name) + strlen(__col)+1;
	char cmd[len];
	memset(cmd,0,len*sizeof(char));
	sprintf(cmd,alter_table,__table_name,__col);
	printf("%s ",cmd);
	int ret = 0;
	char *errmsg;
	ret = sqlite3_exec(__db__, cmd, 0, 0, &errmsg);
	if (ret == SQLITE_OK){
		printf("[SUCCESS]\n\n");
	}
	else{
		//printf("[%d] %s\n",ret,sqlite3_errstr(ret));
		if(strstr(errmsg,"duplicate column name")){
			printf("[SUCCESS]\n");
		}
		else{
			printf("[FAILED]\n");
			printf("[%d] %s\n\n",ret,errmsg);
		}
	}
	sqlite3_free(errmsg);
}

int enco_sql_open_buffer()
{
	char *cmd;
	char *errmsg;
	int8_t cnt_open = 0;
	int8_t ret =0;

alarmlist_open:
	ret = sqlite3_open (ALARM_FILE, &alarm_list);
	if (ret != SQLITE_OK)
	{
	  debug(__func__, "WARNING:", "Open %s failed", ALARM_FILE);
	  cnt_open++;
	  if(cnt_open > 3 ){
		debug(__func__, "WARNING:", "Open and create file failed");
		return 1;
	  }
	  char tmp[28];
	  memset(tmp,0,28*sizeof(char));
	  sprintf(tmp,"sudo touch log/alarm_list.db");
	  system(tmp);
	  sleep(1);
	  goto alarmlist_open;
	}
	else debug(__func__, "INFO:", "Open %s OK", ALARM_FILE);
	
	cmd = sqlite3_mprintf("CREATE TABLE IF NOT EXISTS %s("
							"alarm_time TEXT,"
							"ringtone TEXT,"
							"message TEXT)",
							TBLALARM);
	ret = sqlite3_exec(alarm_list, cmd, 0, 0, &errmsg);
	if (ret == SQLITE_OK){
		debug(__func__, "INFO:", "Create table %s if not exists OK",TBLALARM);
	}
	else{
		debug(__func__, "ERROR:", "GAGAL CREATE TABLE");
		printf("%s",errmsg);
	}
	sqlite3_close(alarm_list);
	sqlite3_free(errmsg);
	sqlite3_free(cmd);
	return 0;
}

int sql_insert_alarm_list(const char *_alarm_time, char *_ringtone, char *_mesg, ...){
	sqlite3 *db;
	
	// cek open db nya 
	if(sqlite3_open(ALARM_FILE, &db) != SQLITE_OK){
		debug(__func__, "ERROR", "can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	char *cmd;
	int ret = 0;

	// insert data
	cmd = sqlite3_mprintf("INSERT INTO "TBLALARM" (alarm_time,ringtone,message) VALUES ('%s','%s','%s')",_alarm_time,_ringtone,_mesg);
	
	printf("%s\n",cmd);
	ret = sqlite3_exec (db, cmd, NULL, NULL, NULL);
	sqlite3_free(cmd);
	if (ret == SQLITE_OK){
		debug(__func__, "INFO:", "Insert to %s success\n",TBLALARM);
		ret = 0;
	}
	else{
		debug(__func__, "ERROR:", "Failed insert to %s\n",TBLALARM);
		printf("[%s]\n",sqlite3_errmsg(db));
	}
	sqlite3_close(db);
	return ret;
}

// function select table database
int sql_select_table ()
{
	sqlite3 *db;
	sqlite3_finalize(select_alarm);
	// cek open db nya 
	if(sqlite3_open(ALARM_FILE, &db) != SQLITE_OK){
		debug(__func__, "ERROR", "can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}
	sqlite3_prepare_v2(db, "SELECT * FROM alarm", -1, &select_alarm, NULL);
	
	// cek_quary();
	// sql_GetValue_alarm();
	printf("sukses select table\n");
	sqlite3_close(db);
	return 0;
}

void cek_quary(){
	count = 0;

	while (sqlite3_step(select_alarm) == SQLITE_ROW)
	{
    	count++;
	}
	sqlite3_reset(select_alarm);  // reset the stmt for use it again
}

// function get data table to buffer
void sql_GetValue_alarm()
{		

		// select table alarm
		if (sqlite3_step(select_alarm) == SQLITE_ROW) {
			alarm_time = sqlite3_column_text(select_alarm, 0);
			alarm_mesg = sqlite3_column_text(select_alarm, 2);
			alarm_ringtones = sqlite3_column_text(select_alarm, 1);

			// count++;
		}
		// printf("asu %d\n",count);
		// printf("%s .. %s .. %s\n",alarm_time,alarm_mesg,alarm_ringtones);
}
