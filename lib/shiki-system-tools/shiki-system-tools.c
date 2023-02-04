#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <linux/input.h>
#include <openssl/md5.h>
#include "shiki-system-tools.h"

int8_t ssys_debug_mode_status = 1;

static void ssys_debug(const char *function_name, char *debug_type, char *debug_msg, ...);
static int *ssys_keyboard_thread(void *ptr);
static char *ssys_list_dir_by_name(char *_dir_path, char *_keyword, uint8_t _type);
static char *ssys_list_dir(char *_dir_path, uint8_t _type);

static void ssys_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	if (ssys_debug_mode_status == 1){
        time_t debug_time;
	    struct tm *d_tm;
	    va_list aptr;
		
	    time(&debug_time);
	    d_tm = localtime(&debug_time);
	    char tmp_debug_msg[100];
	    va_start(aptr, debug_msg);
	    vsprintf(tmp_debug_msg, debug_msg, aptr);
	    va_end(aptr);
	
	    if (strcmp(debug_type, "INFO")==0) printf("\033[1;32m%02d-%02d-%04d %02d:%02d:%02d\033[1;34m S_SYS\033[1;32m %s: %s: %s\033[0m",
         d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, debug_type, function_name, tmp_debug_msg);
	    else if (strcmp(debug_type, "WARNING")==0) printf("\033[1;33m%02d-%02d-%04d %02d:%02d:%02d\033[1;34m S_SYS\033[1;33m %s: %s: %s\033[0m",
         d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, debug_type, function_name, tmp_debug_msg);
	    else if (strcmp(debug_type, "ERROR")==0) printf("\033[1;31m%02d-%02d-%04d %02d:%02d:%02d\033[1;34m S_SYS\033[1;31m %s: %s: %s\033[0m",
         d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, debug_type, function_name, tmp_debug_msg);
    }
}

// keyboard
int8_t ssys_get_keyboard_file(char *_file_name){
    DIR *d_fd;
    struct dirent *d_st;
    if ((d_fd = opendir("/dev/input/by-path")) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"/dev/input/by-path\"\n");
        return -1;
    }
    while((d_st = readdir(d_fd)) != NULL){
        if (d_st->d_name[strlen(d_st->d_name)-3] == 'k' &&
         d_st->d_name[strlen(d_st->d_name)-2] == 'b' &&
         d_st->d_name[strlen(d_st->d_name)-1] == 'd'
        ){
            strcpy(_file_name, d_st->d_name);
            closedir(d_fd);
            return 0;
        }
    }
    closedir(d_fd);
    ssys_debug(__func__, "ERROR", "can't found keyboard input file\n");
    return -1;
}

int16_t ssys_get_keyboard_input(char *_file_name, char *_key_name){
    if (strlen(_file_name) == 0){
        ssys_debug(__func__, "ERROR", "file name is missing\n");
        return -1;
    }
    FILE *f_key;
    char f_path[20 + strlen(_file_name)];
    memset(f_path, 0x00, (20 + strlen(_file_name))*sizeof(char));
    sprintf(f_path, "/dev/input/by-path/%s", _file_name);
    if ((f_key = fopen(f_path, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to open %s\n", f_path);
        return -2;
    }
    struct input_event kb_input;
    // wait until input is aviable
    while(fread(&kb_input, sizeof(kb_input), 1, f_key) == 0) usleep(100);
    int16_t key_num = (int16_t) kb_input.value;
    fclose(f_key);
    switch(key_num){
        case 1 :
            strcpy(_key_name, "[ESC]");
        break;
        case 2 :
            strcpy(_key_name, "1");
        break;
        case 3 :
            strcpy(_key_name, "2");
        break;
        case 4 :
            strcpy(_key_name, "3");
        break;
        case 5 :
            strcpy(_key_name, "4");
        break;
        case 6 :
            strcpy(_key_name, "5");
        break;
        case 7 :
            strcpy(_key_name, "6");
        break;
        case 8 :
            strcpy(_key_name, "7");
        break;
        case 9 :
            strcpy(_key_name, "8");
        break;
        case 10 :
            strcpy(_key_name, "9");
        break;
        case 11 :
            strcpy(_key_name, "0");
        break;
        case 12 :
            strcpy(_key_name, "-");
        break;
        case 13 :
            strcpy(_key_name, "=");
        break;
        case 14 :
            strcpy(_key_name, "[BACKSPACE]");
        break;
        case 15 :
            strcpy(_key_name, "[TAB]");
        break;
        case 16 :
            strcpy(_key_name, "q");
        break;
        case 17 :
            strcpy(_key_name, "w");
        break;
        case 18 :
            strcpy(_key_name, "e");
        break;
        case 19 :
            strcpy(_key_name, "r");
        break;
        case 20 :
            strcpy(_key_name, "t");
        break;
        case 21 :
            strcpy(_key_name, "y");
        break;
        case 22 :
            strcpy(_key_name, "u");
        break;
        case 23 :
            strcpy(_key_name, "i");
        break;
        case 24 :
            strcpy(_key_name, "o");
        break;
        case 25 :
            strcpy(_key_name, "p");
        break;
        case 26 :
            strcpy(_key_name, "[");
        break;
        case 27 :
            strcpy(_key_name, "]");
        break;
        case 28 :
            strcpy(_key_name, "[ENTER]");
        break;
        case 29 :
            strcpy(_key_name, "L_CTRL");
        break;
        case 30 :
            strcpy(_key_name, "a");
        break;
        case 31 :
            strcpy(_key_name, "s");
        break;
        case 32 :
            strcpy(_key_name, "d");
        break;
        case 33 :
            strcpy(_key_name, "f");
        break;
        case 34 :
            strcpy(_key_name, "g");
        break;
        case 35 :
            strcpy(_key_name, "h");
        break;
        case 36 :
            strcpy(_key_name, "j");
        break;
        case 37 :
            strcpy(_key_name, "k");
        break;
        case 38 :
            strcpy(_key_name, "l");
        break;
        case 39 :
            strcpy(_key_name, ";");
        break;
        case 40 :
            strcpy(_key_name, "'");
        break;
        case 41 :
            strcpy(_key_name, "`");
        break;
        case 42 :
            strcpy(_key_name, "L_SHIFT");
        break;
        case 43 :
            strcpy(_key_name, "\\");
        break;
        case 44 :
            strcpy(_key_name, "z");
        break;
        case 45 :
            strcpy(_key_name, "x");
        break;
        case 46 :
            strcpy(_key_name, "c");
        break;
        case 47 :
            strcpy(_key_name, "v");
        break;
        case 48 :
            strcpy(_key_name, "b");
        break;
        case 49 :
            strcpy(_key_name, "n");
        break;
        case 50 :
            strcpy(_key_name, "m");
        break;
        case 51 :
            strcpy(_key_name, ",");
        break;
        case 52 :
            strcpy(_key_name, ".");
        break;
        case 53 :
            strcpy(_key_name, "/");
        break;
        case 54 :
            strcpy(_key_name, "R_SHIFT");
        break;
        case 55 :
            strcpy(_key_name, "m");
        break;
        case 56 :
            strcpy(_key_name, "L_ALT");
        break;
        case 57 :
            strcpy(_key_name, " ");
        break;
        case 58 :
            strcpy(_key_name, "[CAPSLOCK]");
        break;
        case 59 :
            strcpy(_key_name, "[F1]");
        break;
        case 60 :
            strcpy(_key_name, "[F2]");
        break;
        case 61 :
            strcpy(_key_name, "[F3]");
        break;
        case 62 :
            strcpy(_key_name, "[F4]");
        break;
        case 63 :
            strcpy(_key_name, "[F5]");
        break;
        case 64 :
            strcpy(_key_name, "[F6]");
        break;
        case 65 :
            strcpy(_key_name, "[F7]");
        break;
        case 66 :
            strcpy(_key_name, "[F8]");
        break;
        case 67 :
            strcpy(_key_name, "[F9]");
        break;
        case 68 :
            strcpy(_key_name, "[F10]");
        break;
        case 69 :
            strcpy(_key_name, "[F9]");
        break;
        case 70 :
        break;
        case 71 :
        break;
        case 72 :
        break;
        case 73 :
        break;
        case 74 :
        break;
        case 75 :
        break;
        case 76 :
        break;
        case 77 :
        break;
        case 78 :
        break;
        case 79 :
        break;
        case 80 :
        break;
        case 81 :
        break;
        case 82 :
        break;
        case 83 :
        break;
        case 84 :
        break;
        case 85 :
        break;
        case 86 :
        break;
        case 87 :
            strcpy(_key_name, "[F11]");
        break;
        case 88 :
            strcpy(_key_name, "[F12]");
        break;
        case 89 :
        break;
        case 90 :
        break;
        case 157 :
            strcpy(_key_name, "[R_CTRL]");
        break;
        case 183 :
            strcpy(_key_name, "[PRTSCR]");
        break;
        case 184 :
            strcpy(_key_name, "[R_ALT]");
        break;
        case 200 :
            strcpy(_key_name, "[KEY_UP]");
        break;
        case 203 :
            strcpy(_key_name, "[KEY_LEFT]");
        break;
        case 205 :
            strcpy(_key_name, "[KEY_RIGHT]");
        break;
        case 208 :
            strcpy(_key_name, "[KEY_DOWN]");
        break;
        case 210 :
            strcpy(_key_name, "[WINDOW]");
        break;
    }
    return (int16_t) kb_input.value;
}

int8_t ssys_get_keyboard_plug_status(){
    char *list_event = ssys_list_directory_by_name("/sys/class/input", "event");
    if (list_event == NULL) {
        return -1;
    }
    int8_t num_of_event = 0;
    char dir_name[256];
    memset(dir_name, 0x00, 256*sizeof(char));
    uint16_t i = 0;
    uint8_t idx_char = 0;
    for (i=0; i<strlen(list_event); i++){
        if (list_event[i] == '\n'){
            char file_full_path[256];
            memset(file_full_path, 0x00, 256*sizeof(char));
            sprintf(file_full_path, "/sys/class/input/%s/device/uevent", dir_name);
            if(ssys_check_text_in_file(file_full_path, "keyboard") == 0 ||
             ssys_check_text_in_file(file_full_path, "Keyboard") == 0 ||
             ssys_check_text_in_file(file_full_path, "KEYBOARD") == 0
            ){
                ssys_debug(__func__, "INFO", "keyboard detected\n");
                num_of_event++;
            }
            memset(dir_name, 0x00, 256*sizeof(char));
            idx_char = 0;
        }
        else {
            dir_name[idx_char] = list_event[i];
            idx_char++;
        }
    }
    free(list_event);
    if (num_of_event == 0){
        return -1;
    }
    return num_of_event;
}

static int *ssys_keyboard_thread(void *ptr){
    char file_name[100];
    int8_t retval = 0;
    retval = ssys_get_keyboard_file(file_name);
    if (retval == 0){
        ssys_debug(__func__, "INFO", "%s\n", file_name);
    }
    while(1) {
        ssys_debug(__func__, "INFO", "wait input\n");
        skey_data.key_value = ssys_get_keyboard_input(file_name, skey_data.key_name);

        ssys_debug(__func__, "INFO", "keyboard input : %d - %s\n", skey_data.key_value, skey_data.key_name);
        usleep(1000);
        if (skey_data.key_value == -2){
            ssys_get_keyboard_file(file_name);
            sleep(1);
        }
    }
    return 0;
}

int8_t ssys_keyboard_thread_start(){
	pthread_t qr_thread;
	if(pthread_create(&qr_thread, NULL, (void*) ssys_keyboard_thread, NULL) == 0) {
		ssys_debug(__func__, "INFO", "thread started successfully\n");
		return 0;
	}
	else ssys_debug(__func__, "ERROR", "thread start failed\n");
	return -1;
}

// temperature
float ssys_get_temperature(){
    FILE *f_temp;
    if ((f_temp = fopen("/sys/class/thermal/thermal_zone0/temp", "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to read temperature\n");
        return -1;
    }

    char buff[6];
    memset(buff, 0x00, 6*sizeof(char));
    if(fread(&buff, 5, 1, f_temp) > 0){
        float temp;
        temp = atof(buff)/1000;
        fclose(f_temp);
        return temp;
    }
    fclose(f_temp);
    return -99.0;
}

// file and directory
static char *ssys_list_dir(char *_dir_path, uint8_t _type){
    DIR *d_fd;
    struct dirent *d_st;
    if ((d_fd = opendir(_dir_path)) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"%s\"\n", _dir_path);
        return NULL;
    }
    uint16_t dir_count = 0;
    uint16_t str_length = 0;
    char *dir_list;
    dir_list = (char *) malloc(3*sizeof(char));
    if (dir_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    memset(dir_list, 0x00, 3*sizeof(char));
    while((d_st = readdir(d_fd)) != NULL){
        if (d_st->d_type == _type || (_type == 4 && d_st->d_type == 10)){
            str_length = str_length + strlen(d_st->d_name) + 1;
            dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
            strcat(dir_list, d_st->d_name);
            dir_list[str_length - 1] = '\n';
            dir_list[str_length] = 0x00;
            dir_count++;
        }
    }
    closedir(d_fd);
    if (dir_count > 0){
        if (_type == 4){
            ssys_debug(__func__, "INFO", "found %d directories\n", dir_count);
        }
        if (_type == 8){
            ssys_debug(__func__, "INFO", "found %d files\n", dir_count);
        }
    }
    else {
        if (_type == 4){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else if (_type == 8){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else {
            ssys_debug(__func__, "ERROR", "wrong type\n");
        }
        free(dir_list);
        return NULL;
    }
    return dir_list;
}

static char *ssys_list_dir_by_name(char *_dir_path, char *_keyword, uint8_t _type){
    DIR *d_fd;
    struct dirent *d_st;
    if ((d_fd = opendir(_dir_path)) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"%s\"\n", _dir_path);
        return NULL;
    }
    uint16_t dir_count = 0;
    uint16_t str_length = 0;
    char *dir_list;
    dir_list = (char *) malloc(3*sizeof(char));
    if (dir_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    memset(dir_list, 0x00, 3*sizeof(char));
    while((d_st = readdir(d_fd)) != NULL){
        if ((d_st->d_type == _type || (_type == 4 && d_st->d_type == 10)) && strlen(d_st->d_name) >= strlen(_keyword)){
            char buff[strlen(_keyword) + 1];;
            memset(buff, 0x00, (strlen(_keyword) + 1)*sizeof(char));
            strncpy(buff, d_st->d_name, strlen(_keyword));
            if (_keyword[0]=='*' && _keyword[1]=='.'){
                char keyword_tmp[strlen(_keyword)-1];
                memset(buff, 0x00, (strlen(_keyword) + 1)*sizeof(char));
                memset(keyword_tmp, 0x00, strlen(_keyword)-1);
                memcpy(keyword_tmp, _keyword + 2, strlen(_keyword)-2);
                uint8_t i = 0;
                for (i=0; i<strlen(keyword_tmp); i++){
                    if (d_st->d_name[strlen(d_st->d_name) - i - 1] == '.'){
                        break;
                    }
                    buff[i] = d_st->d_name[strlen(d_st->d_name) - i - 1];
                }
                char buff_tmp[strlen(buff) + 1];
                memset(buff_tmp, 0x00, (strlen(buff) + 1)*sizeof(char));
                for (i=0; i<strlen(buff); i++){
                    buff_tmp[i] = buff[strlen(buff) - i - 1];
                }
                strcpy(buff, buff_tmp);
                if (strcmp(buff, keyword_tmp) == 0){
                    str_length = str_length + strlen(d_st->d_name) + 1;
                    dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
                    strcat(dir_list, d_st->d_name);
                    dir_list[str_length - 1] = '\n';
                    dir_list[str_length] = 0x00;
                    dir_count++;
                }
            }
            else if (strcmp(buff, _keyword) == 0){
                str_length = str_length + strlen(d_st->d_name) + 1;
                dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
                strcat(dir_list, d_st->d_name);
                dir_list[str_length - 1] = '\n';
                dir_list[str_length] = 0x00;
                dir_count++;
            }
            else {
                uint8_t i = 0;
                for(i=strlen(_keyword); i<strlen(d_st->d_name); i++){
                    uint8_t j = 0;
                    for(j=0; j<strlen(_keyword)-1; j++){
                        buff[j] = buff[j+1];
                    }
                    buff[strlen(_keyword)-1] = d_st->d_name[i];
                    if (strcmp(buff, _keyword) == 0){
                        str_length = str_length + strlen(d_st->d_name) + 1;
                        dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
                        strcat(dir_list, d_st->d_name);
                        dir_list[str_length - 1] = '\n';
                        dir_list[str_length] = 0x00;
                        dir_count++;
                    }
                }
            }
        }
    }
    closedir(d_fd);
    if (dir_count == 0) {
        if (_type == 4){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else if (_type == 8){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else {
            ssys_debug(__func__, "ERROR", "wrong type\n");
        }
        free(dir_list);
        return NULL;
    }
    return dir_list;
}

char *ssys_list_directory(char *_dir_path){
    return ssys_list_dir(_dir_path, 4);
}

char *ssys_list_file(char *_dir_path){
    return ssys_list_dir(_dir_path, 8);
}

char *ssys_list_directory_by_name(char *_dir_path, char *_keyword){
    return ssys_list_dir_by_name(_dir_path, _keyword, 4);
}

char *ssys_list_file_by_name(char *_dir_path, char *_keyword){
    return ssys_list_dir_by_name(_dir_path, _keyword, 8);
}

char *ssys_list_file_by_content(char *_dir_path, char *_keyword){
    DIR *d_fd;
    struct dirent *d_st;
    if ((d_fd = opendir(_dir_path)) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"%s\"\n", _dir_path);
        return NULL;
    }
    uint16_t dir_count = 0;
    uint16_t str_length = 0;
    uint8_t _type = 8;
    char *dir_list;
    dir_list = (char *) malloc(3*sizeof(char));
    if (dir_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    memset(dir_list, 0x00, 3*sizeof(char));
    while((d_st = readdir(d_fd)) != NULL){
        if (d_st->d_type == _type){
            char file_full_path[strlen(_dir_path) + strlen(d_st->d_name) + 2];
            memset(file_full_path, 0x00, (strlen(_dir_path) + strlen(d_st->d_name) + 2)*sizeof(char));
            sprintf(file_full_path, "%s/%s", _dir_path, d_st->d_name);
            if (ssys_check_text_in_file(file_full_path, _keyword) == 0){
                str_length = str_length + strlen(d_st->d_name) + 1;
                dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
                strcat(dir_list, d_st->d_name);
                dir_list[str_length - 1] = '\n';
                dir_list[str_length] = 0x00;
                dir_count++;
            }
        }
    }
    closedir(d_fd);
    if (dir_count > 0){
        if (_type == 4){
            ssys_debug(__func__, "INFO", "found %d directories\n", dir_count);
        }
        if (_type == 8){
            ssys_debug(__func__, "INFO", "found %d files\n", dir_count);
        }
    }
    else {
        if (_type == 4){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else if (_type == 8){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else {
            ssys_debug(__func__, "ERROR", "wrong type\n");
        }
        free(dir_list);
        return NULL;
    }
    return dir_list;
}

int8_t ssys_check_text_in_file(char *_file, char *_keyword){
    FILE *f_check;
    if ((f_check = fopen(_file, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to read \"%s\"\n", _file);
        return -1;
    }

    char buff[strlen(_keyword) + 1];
    char character = 0;
    memset(buff, 0x00, (strlen(_keyword) + 1)*sizeof(char));
    uint8_t i = 0;
    for (i=0; i< strlen(_keyword); i++){
        character = fgetc(f_check);
        if (character == EOF){
            break;
        }
        buff[i] = character;
    }
    if (strlen(buff) < strlen(_keyword)){
        fclose(f_check);
        return -1;
    }
    if (strcmp(buff, _keyword) == 0){
        fclose(f_check);
        return 0;
    }
    else if (character == EOF){
        fclose(f_check);
        return -1;
    }

    while ((character = fgetc(f_check)) != EOF){
        if (character < 1 || character > 127) break;
        for (i=0; i<strlen(_keyword) - 1; i++){
            buff[i] = buff[i + 1];
        }
        buff[strlen(_keyword) - 1] = character;
        if (strcmp(buff, _keyword) == 0){
            fclose(f_check);
            return 0;
        }
    }
    fclose(f_check);
    return -1;
}

unsigned long ssys_get_file_size(char *_file){
    FILE *f_check;
    if ((f_check = fopen(_file, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to read \"%s\"\n", _file);
        return 0;
    }

    fseek(f_check, 0L, SEEK_END);
    unsigned long file_size = ftell(f_check);
    fclose(f_check);

    return file_size;
}

int8_t ssys_get_checksum_of_file(char *_file_name, unsigned char *_checksum_output){
	FILE *fd_sum = fopen(_file_name, "rb");
	if (fd_sum == NULL){
		ssys_debug(__func__, "ERROR", "fail to open file");
		return -1;
	}

	MD5_CTX context;
	MD5_Init(&context);

	int bytes = 0;
	unsigned char *data;
	unsigned char *sum;
	unsigned char *md5_sum;

	data = (unsigned char *) malloc(1024*sizeof(char));
	if (data == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate data memory\n");
		return -1;
	}
	sum = (unsigned char *) malloc(MD5_DIGEST_LENGTH*sizeof(char));
	if (sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate sum memory\n");
		free(data);
		return -1;
	}
	md5_sum = (unsigned char *) malloc(33*sizeof(char));
	if (md5_sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate md5_sum memory\n");
		free(data);
		free(sum);
		return -1;
	}

	while ((bytes = fread(data, 1, 1024, fd_sum)) != 0){
		MD5_Update(&context, data, bytes);
		MD5_Final(sum, &context);
	}

	memset(md5_sum, 0x00, 33*sizeof(char));
	for (int i=0; i< MD5_DIGEST_LENGTH; i++){
		sprintf((char *) &md5_sum[i*2], "%02x", (unsigned int)sum[i]);
	}
	fclose(fd_sum);
	strcpy((char *)_checksum_output, (char *)md5_sum);
	ssys_debug(__func__, "INFO", "checksum of \"%s\" is %s\n", _file_name, md5_sum);
	free(data);
	free(sum);
	free(md5_sum);
	return 0;
}

int8_t ssys_get_checksum(unsigned char *_input, unsigned char *_checksum_output){
	MD5_CTX context;
	MD5_Init(&context);

	unsigned char *sum;
	unsigned char *md5_sum;

	sum = (unsigned char *) malloc(MD5_DIGEST_LENGTH*sizeof(char));
	if (sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate sum memory\n");
		return -1;
	}
	md5_sum = (unsigned char *) malloc(33*sizeof(char));
	if (md5_sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate md5_sum memory\n");
		free(sum);
		return -1;
	}

	MD5_Update(&context, _input, strlen((char *)_input));
	MD5_Final(sum, &context);

	memset(md5_sum, 0x00, 33*sizeof(char));
	for (int i=0; i< MD5_DIGEST_LENGTH; i++){
		sprintf((char *) &md5_sum[i*2], "%02x", (unsigned int)sum[i]);
	}

	strcpy((char *)_checksum_output, (char *)md5_sum);
	ssys_debug(__func__, "INFO", "checksum of \"%s\" is %s\n", _input, md5_sum);
	free(sum);
	free(md5_sum);
	return 0;
}

// mac address
int8_t ssys_get_mac_address(char* _mac_address, char* _interface){
    FILE *mac_file;
    char *file_name;
    char *mac_address;

	file_name = (char *) malloc(35*sizeof(char));
	if (file_name == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate file_name memory\n");
		return -1;
	}
	mac_address = (char *) malloc(18*sizeof(char));
	if (file_name == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate mac_address memory\n");
		free(file_name);
		return -1;
	}

    memset(file_name, 0x00, 35*sizeof(char));
    memset(mac_address, 0x00, 18*sizeof(char));
    sprintf(file_name, "/sys/class/net/%s/address", _interface);
    if ((mac_file=fopen(file_name, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to open %s\n", file_name);
		free(file_name);
		free(mac_address);
        return -2;
    }
    if(fgets(mac_address, 18, mac_file)!=NULL){
		mac_address[17] = 0x00;
        strncpy(_mac_address, mac_address, 18);
        ssys_debug(__func__, "INFO", "your mac address is %s\n", mac_address);
    }
    else{
        ssys_debug(__func__, "INFO", "failed to read mac address\n");
        fclose(mac_file);
		free(file_name);
		free(mac_address);
        return -3;
    }
	free(mac_address);
    fclose(mac_file);
    return 0;
}
//#define aaa
#ifdef aaa 
int main(int arg, char ** argv[]){
	int hasil=0;
	char fileS[100] = {"/home/yuharsenergi/Downloads/postgresql-10.11-3-linux-x64.run"};
	
	hasil = ssys_get_file_size(fileS);
	printf("Hasil file : %s\n",fileS);
	printf("Size File : %d bytes\n",hasil);
	
	return 0;
}
#endif
