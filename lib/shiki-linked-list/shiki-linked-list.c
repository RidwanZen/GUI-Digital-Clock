/*
    lib info    : SHIKI_LIB_GROUP - LINKED_LIST
    ver         : 1.04.20.10.01
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2020 HANA,. Jaya Wikrama
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "shiki-linked-list.h"

#define var_name(var) #var

#define SHILINK_VER "1.04.20.10.01"

int8_t debug_mode_status = 1;

typedef enum {
  SHILINK_DEBUG_INFO = 0x00,
  SHILINK_DEBUG_VERSION = 0x01,
  SHILINK_DEBUG_WARNING = 0x02,
  SHILINK_DEBUG_ERROR = 0x03,
  SHILINK_DEBUG_CRITICAL = 0x04
} shilink_debug_type;

static void shilink_debug(const char *_function_name, shilink_debug_type _debug_type, const char *_debug_msg, ...){
	if (debug_mode_status == 1 || _debug_type != SHILINK_DEBUG_INFO){
        struct tm *d_tm = NULL;
        struct timeval tm_debug;
        uint16_t msec = 0;
		
	    gettimeofday(&tm_debug, NULL);
	    d_tm = localtime(&tm_debug.tv_sec);
        msec = tm_debug.tv_usec/1000;

        #ifdef __linux__
            if (_debug_type == SHILINK_DEBUG_INFO)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SHILINK\033[1;32m INFO\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == SHILINK_DEBUG_VERSION)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SHILINK\033[1;32m VERSION\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
    	    else if (_debug_type == SHILINK_DEBUG_WARNING)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SHILINK\033[1;33m WARNING\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
    	    else if (_debug_type == SHILINK_DEBUG_ERROR)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SHILINK\033[1;31m ERROR\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == SHILINK_DEBUG_CRITICAL)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SHILINK\033[1;31m CRITICAL\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
	    #else
            printf("%02d-%02d-%04d %02d:%02d:%02d.%03d [%02x]: %s: ",
             d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
             msec, _debug_type, _function_name
            );
        #endif

        va_list aptr;
        va_start(aptr, _debug_msg);
	    vfprintf(stdout, _debug_msg, aptr);
	    va_end(aptr);
    }
}

long shilink_get_version(char *_version){
    strcpy(_version, SHILINK_VER);
    long version_in_long = 0;
    uint8_t idx_ver = 0;
    uint8_t multiplier = 10;
    while(idx_ver < 13){
        if(SHILINK_VER[idx_ver] != '.' && SHILINK_VER[idx_ver] != 0x00){
            if (version_in_long == 0){
                version_in_long = SHILINK_VER[idx_ver] - '0';
            }
            else{
                version_in_long = (version_in_long*multiplier) + (SHILINK_VER[idx_ver] - '0');
            }
        }
        else if (SHILINK_VER[idx_ver] == 0x00){
            break;
        }
        idx_ver++;
    }
    return version_in_long;
}

void shilink_view_version(){
    shilink_debug(__func__, SHILINK_DEBUG_VERSION, "%s\n", SHILINK_VER);
}

/* USER MODIFICATION PURPOSE START HERE */
void shilink_fill_data(SHLink *_target, SHLinkCustomData _data){
    (*_target)->sl_data.sl_key = _data.sl_key;
    (*_target)->sl_data.sl_value = _data.sl_value;
    (*_target)->sl_data.sl_keysize = _data.sl_keysize;
    (*_target)->sl_data.sl_valsize = _data.sl_valsize;
    (*_target)->sl_data.sl_data_types = _data.sl_data_types;
}

static void shilink_print_data(const SHLink _data){
    char sldata_type[8];
    if (_data->sl_data.sl_data_types == SL_BOOLEAN){
        strcpy(sldata_type, "BOOLEAN");
    }
    else if (_data->sl_data.sl_data_types == SL_POINTER){
        strcpy(sldata_type, "POINTER");
    }
    else if (_data->sl_data.sl_data_types == SL_TEXT){
        strcpy(sldata_type, "STRING");
    }
    else if (_data->sl_data.sl_data_types == SL_NUMERIC){
        strcpy(sldata_type, "NUMERIC");
    }
    else if (_data->sl_data.sl_data_types == SL_FLOAT){
        strcpy(sldata_type, "FLOAT");
    }
    printf("key = %s; value = %s; type = %s\n",
     (unsigned char *) _data->sl_data.sl_key,
     (unsigned char *) _data->sl_data.sl_value,
     sldata_type
    );
}

static int8_t shilink_check_custom_data(SHLinkCustomData _data){
    if (_data.sl_value == NULL && _data.sl_key == NULL){
        return -1;
    }
    return 0;
}

static int8_t shilink_compare_custom_data(SHLinkCustomData _data_main, SHLinkCustomData _data_child){
    if(_data_child.sl_key != NULL && _data_child.sl_value != NULL){
        if (_data_main.sl_keysize == _data_child.sl_keysize &&
         _data_main.sl_valsize == _data_child.sl_valsize
        ){
            if (memcmp(_data_main.sl_key, _data_child.sl_key, _data_main.sl_keysize) == 0 &&
             memcmp(_data_main.sl_value, _data_child.sl_value, _data_main.sl_valsize) == 0
            ){
                return 0;
            }
        }
    }
    else if (_data_child.sl_key != NULL){
        if (_data_main.sl_keysize == _data_child.sl_keysize){
            if (memcmp(_data_main.sl_key, _data_child.sl_key, _data_main.sl_keysize) == 0){
                return 0;
            }
        }
    }
    else if (_data_main.sl_valsize == _data_child.sl_valsize){
        if (memcmp(_data_main.sl_value, _data_child.sl_value, _data_main.sl_valsize) == 0){
            return 0;
        }
    }
    return -1;
}

int8_t shilink_fill_custom_data(
 SHLinkCustomData *_data,
 const void *_key,
 uint16_t _sizeof_key,
 const void *_value,
 uint16_t _sizeof_value,
 SHLDataTypes _data_types
){
    _data->sl_key = NULL;
    _data->sl_value = NULL;
    _data->sl_keysize = _sizeof_key;
    _data->sl_valsize = _sizeof_value;
    
    if (_key != NULL){
        _data->sl_key = (char *) malloc(_sizeof_key + 1);
        if (_data->sl_key == NULL){
            shilink_debug(__func__, SHILINK_DEBUG_ERROR, "failed to allocate memory. process aborted!\n");
            return -1;
        }
    }
    if (_value != NULL){
        _data->sl_value = (char *) malloc(_sizeof_value + 1);
        if (_data->sl_value == NULL){
            shilink_debug(__func__, SHILINK_DEBUG_ERROR, "failed to allocate memory. process aborted!\n");
            if (_key != NULL){
                free(_data->sl_key);
                _data->sl_key = NULL;
            }
            return -1;
        }
    }

    if (_key != NULL){
        memset(_data->sl_key, 0x00, _sizeof_key + 1);
        memcpy(_data->sl_key, _key, _sizeof_key);
    }
    if (_value != NULL){
        memset(_data->sl_value, 0x00, _sizeof_value + 1);
        memcpy(_data->sl_value, _value, _sizeof_value);
    }
    _data->sl_data_types = _data_types;
    return 0;
}

void shilink_free_custom_data(SHLinkCustomData *_data){
    free(_data->sl_key);
    if (_data->sl_value != NULL){
        free(_data->sl_value);
    }

    _data->sl_keysize = 0;
    _data->sl_valsize = 0;
    _data->sl_key = NULL;
    _data->sl_value = NULL;
    _data->sl_data_types = SL_TEXT;
}

uint16_t shilink_count_data_by_key(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key
){
    uint16_t idx_pos = 0;
    while (_target != NULL){
        if (_sizeof_key == _target->sl_data.sl_keysize){
            if(memcmp(_target->sl_data.sl_key, _key, _sizeof_key) == 0){
                idx_pos++;
                _target = _target->sh_next;
            }
        }
        _target = _target->sh_next;
    }
    return idx_pos;
}

uint16_t shilink_count_data_by_key_val(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 const void *_value,
 uint16_t _sizeof_val
){
    uint16_t idx_pos = 0;
    while (_target != NULL){
        if (_sizeof_key == _target->sl_data.sl_keysize && _sizeof_val == _target->sl_data.sl_valsize){
            if(memcmp(_target->sl_data.sl_key, _key, _sizeof_key) == 0 &&
             memcmp(_target->sl_data.sl_value, _value, _sizeof_val) == 0
            ){
                idx_pos++;
                _target = _target->sh_next;
            }
        }
        _target = _target->sh_next;
    }
    return idx_pos;
}

int8_t shilink_get_data_by_position(SHLink _target, int16_t _pos, SHLinkCustomData *_data){
    int16_t idx_pos = -1;
    while (idx_pos < _pos){
        if (_target == NULL){
            break;
        }
        if (idx_pos < _pos - 1){
            _target = _target->sh_next;
        }
        idx_pos++;
    }
    if (_target != NULL){
        _data->sl_key = _target->sl_data.sl_key;
        _data->sl_value = _target->sl_data.sl_value;
        _data->sl_keysize = _target->sl_data.sl_keysize;
        _data->sl_valsize = _target->sl_data.sl_valsize;
        _data->sl_data_types = _target->sl_data.sl_data_types;
    }
    else if (idx_pos < _pos){
        return -1;
    }
    return 0;
}

int8_t shilink_search_data_by_position(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 int16_t _pos,
 SHLinkCustomData *_data
){
    int16_t idx_pos = -1;
    while (idx_pos < _pos){
        while (_target != NULL){
            if (_sizeof_key == _target->sl_data.sl_keysize){
                if(memcmp(_target->sl_data.sl_key, _key, _sizeof_key) == 0){
                    _data->sl_key = _target->sl_data.sl_key;
                    _data->sl_value = _target->sl_data.sl_value;
                    _data->sl_keysize = _target->sl_data.sl_keysize;
                    _data->sl_valsize = _target->sl_data.sl_valsize;
                    idx_pos++;
                    _target = _target->sh_next;
                    if (idx_pos == _pos){
                        break;
                    }
                }
            }
            _target = _target->sh_next;
        }
        if (idx_pos == _pos){
            return 0;
        }
        if (_target == NULL){
            break;
        }
    }
    if (idx_pos == -1){
        return -1;
    }
    return 1;
}

int8_t shilink_search_data_by_prev_cond(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 SHLinkCustomData *_prev_cond_data,
 SHLinkCustomData *_data
){
    if (_target == NULL){
        shilink_free_custom_data(_prev_cond_data);
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_target is NULL pointer\n");
        return -1;
    }
    while (_target != NULL){
        while (_target != NULL){
            if (_prev_cond_data->sl_keysize == _target->sl_data.sl_keysize &&
             _prev_cond_data->sl_valsize == _target->sl_data.sl_valsize
            ){
                if(memcmp(_target->sl_data.sl_key, _prev_cond_data->sl_key, _prev_cond_data->sl_keysize) == 0 &&
                 memcmp(_target->sl_data.sl_value, _prev_cond_data->sl_value, _prev_cond_data->sl_valsize) == 0
                ){
                    _target = _target->sh_next;
                    break;
                }
            }
            _target = _target->sh_next;
        }
        shilink_free_custom_data(_prev_cond_data);
        if (_target == NULL){
            shilink_debug(__func__, SHILINK_DEBUG_ERROR, "condition not found\n");
            return -1;
            break;
        }
        while (_target != NULL){
            if (_sizeof_key == _target->sl_data.sl_keysize){
                if(memcmp(_target->sl_data.sl_key, _key, _sizeof_key) == 0){
                    _data->sl_key = _target->sl_data.sl_key;
                    _data->sl_value = _target->sl_data.sl_value;
                    _data->sl_keysize = _target->sl_data.sl_keysize;
                    _data->sl_valsize = _target->sl_data.sl_valsize;
                    return 0;
                }
            }
            _target = _target->sh_next;
        }
    }
    shilink_debug(__func__, SHILINK_DEBUG_WARNING, "data not found\n");
    return -1;
}

int8_t shilink_search_data_by_pos_and_prev_cond(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 int16_t _pos,
 SHLinkCustomData *_prev_cond_data,
 SHLinkCustomData *_data
){
    int16_t idx_pos = -1;
    if (_target == NULL){
        shilink_free_custom_data(_prev_cond_data);
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_target is NULL pointer\n");
        return -1;
    }
    while (_target != NULL){
        while (_target != NULL){
            if (_prev_cond_data->sl_keysize == _target->sl_data.sl_keysize &&
             _prev_cond_data->sl_valsize == _target->sl_data.sl_valsize
            ){
                if(memcmp(_target->sl_data.sl_key, _prev_cond_data->sl_key, _prev_cond_data->sl_keysize) == 0 &&
                 memcmp(_target->sl_data.sl_value, _prev_cond_data->sl_value, _prev_cond_data->sl_valsize) == 0
                ){
                    _target = _target->sh_next;
                    idx_pos++;
                    if (idx_pos == _pos){
                        break;
                    }
                }
            }
            _target = _target->sh_next;
        }
        shilink_free_custom_data(_prev_cond_data);
        if (_target == NULL){
            shilink_debug(__func__, SHILINK_DEBUG_ERROR, "condition not found\n");
            return -1;
        }
        else if (_pos != idx_pos){
            shilink_debug(__func__, SHILINK_DEBUG_ERROR, "position not found\n");
            return -2;
        }
        while (_target != NULL){
            if (_sizeof_key == _target->sl_data.sl_keysize){
                if(memcmp(_target->sl_data.sl_key, _key, _sizeof_key) == 0){
                    _data->sl_key = _target->sl_data.sl_key;
                    _data->sl_value = _target->sl_data.sl_value;
                    _data->sl_keysize = _target->sl_data.sl_keysize;
                    _data->sl_valsize = _target->sl_data.sl_valsize;
                    return 0;
                }
            }
            _target = _target->sh_next;
        }
    }
    shilink_debug(__func__, SHILINK_DEBUG_WARNING, "data not found\n");
    return -1;
}
/* USER MODIFICATION PURPOSE END HERE */

int8_t shilink_push(SHLink *_target, SHLinkCustomData _data){
    SHLink new_data = NULL;
    new_data = (SHLink) malloc(sizeof(struct shilink_var));
    if (new_data == NULL){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "failed to allocate memory\n");
        return -1;
    }
    shilink_fill_data(&new_data, _data);
    new_data->sh_next = (*_target);
    (*_target) = new_data;
    return 0;
}

int8_t shilink_append(SHLink *_target, SHLinkCustomData _data){
    SHLink new_data = NULL;
    new_data = (SHLink) malloc(sizeof(struct shilink_var));
    if (new_data == NULL){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "failed to allocate memory\n");
        return -1;
    }
    shilink_fill_data(&new_data, _data);
    new_data->sh_next = NULL;

    if ((*_target) == NULL){
        (*_target) = new_data;
        return 0;
    }

    SHLink end_of_target = (*_target);

    while (end_of_target->sh_next != NULL){
        end_of_target = end_of_target->sh_next;
    }

    end_of_target->sh_next = new_data;
    return 0;
}

static int8_t shilink_insert(SHLink *_target, SHLinkCustomData _data_cond, SHLinkCustomData _data, int8_t _mode){
    if (shilink_check_custom_data(_data) != 0){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_data_new is not set. process aborted\n");
        return -1;
    }

    if (*_target == NULL){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_target (null). process aborted\n");
        return -1;
    }

    SHLink tmp = NULL;
    SHLink prev = NULL;

    tmp = *_target;

    while(tmp != NULL){
        if (shilink_compare_custom_data(tmp->sl_data, _data_cond) == 0){
            break;
        }
        prev = tmp;
        tmp = tmp->sh_next;
    }

    if (tmp == NULL){
        shilink_debug(__func__, SHILINK_DEBUG_WARNING, "cond_data not found. process aborted\n");
        return -2;
    }
    
    if (_mode == 0){
        prev = tmp;
        tmp = tmp->sh_next;
    }

    SHLink new_data = NULL;
    new_data = (SHLink) malloc(sizeof(struct shilink_var));
    if (new_data == NULL){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "failed to allocate memory\n");
        return -1;
    }
    shilink_fill_data(&new_data, _data);
    new_data->sh_next = tmp;

    prev->sh_next = new_data;

    return 0;
}

int8_t shilink_insert_after(SHLink *_target, SHLinkCustomData _data_cond, SHLinkCustomData _data){
    return shilink_insert(_target, _data_cond, _data, 0);
}

int8_t shilink_insert_before(SHLink *_target, SHLinkCustomData _data_cond, SHLinkCustomData _data){
    return shilink_insert(_target, _data_cond, _data, 1);
}

int8_t shilink_delete(SHLink *_target, SHLinkCustomData _data){
    if (shilink_check_custom_data(_data) != 0){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_data is not set. process aborted\n");
        return -1;
    }

    if (*_target == NULL){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_target (null). process aborted\n");
        return -1;
    }

    SHLink tmp = NULL;
    SHLink prev = NULL;

    tmp = *_target;
    prev = tmp;

    if (shilink_compare_custom_data(tmp->sl_data, _data)){
        while(tmp != NULL){
            if (!shilink_compare_custom_data(tmp->sl_data, _data)){
                break;
            }
            prev = tmp;
            tmp = tmp->sh_next;
        }
        if (tmp == NULL){
            return -2;
        }
        prev->sh_next = tmp->sh_next;
    }
    else {
        *_target = (*_target)->sh_next;
    }

    shilink_free_custom_data(&tmp->sl_data);
    free(tmp);
    tmp = NULL;

    return 0;
}

int8_t shilink_update(SHLink *_target, SHLinkCustomData _data_old, SHLinkCustomData _data_new){
    if (shilink_check_custom_data(_data_old) != 0){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_data_old is not set. process aborted\n");
        return -1;
    }

    if (shilink_check_custom_data(_data_new) != 0){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_data_new is not set. process aborted\n");
        return -1;
    }

    if (*_target == NULL){
        shilink_debug(__func__, SHILINK_DEBUG_ERROR, "_target (null). process aborted\n");
        return -1;
    }

    SHLink tmp = NULL;

    tmp = *_target;

    while(tmp != NULL){
        if (shilink_compare_custom_data(tmp->sl_data, _data_old) == 0){
            break;
        }
        tmp = tmp->sh_next;
    }

    if (tmp == NULL){
        return -2;
    }

    shilink_free_custom_data(&tmp->sl_data);
    shilink_fill_data(&tmp, _data_new);

    return 0;
}

void shilink_print(SHLink _target){
    while (_target != NULL){
        shilink_print_data(_target);
        _target = _target->sh_next;
    }
}

void shilink_free(SHLink *_target){
    SHLink sh_tmp = NULL;
    while ((*_target) != NULL){
        sh_tmp = (*_target);
        *(_target) = (*_target)->sh_next;
        shilink_free_custom_data(&(sh_tmp->sl_data));
        free(sh_tmp);
    }
    *(_target) = NULL;
}