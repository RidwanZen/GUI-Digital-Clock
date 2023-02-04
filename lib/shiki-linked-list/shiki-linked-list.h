#ifndef __SHIKI_LINKED_LIST__
#define __SHIKI_LINKED_LIST__

#include <stdint.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* USER MODIFICATION PURPOSE START HERE */
typedef enum{
    SL_NUMERIC = 0,
    SL_BOOLEAN = 1,
    SL_TEXT = 2,
    SL_POINTER = 3,
    SL_FLOAT = 4
} SHLDataTypes;

struct shilink_custom_data{
    void *sl_key;
    void *sl_value;
    uint16_t sl_keysize;
    uint16_t sl_valsize;
    SHLDataTypes sl_data_types;
};

typedef struct shilink_custom_data SHLinkCustomData;
/* USER MODIFICATION PURPOSE END HERE */

struct shilink_var{
    SHLinkCustomData sl_data;
    struct shilink_var *sh_next;
};

typedef struct shilink_var * SHLink;

long shilink_get_version(char *_version);
void shilink_view_version();

/* USER MODIFICATION PURPOSE START HERE */
void shilink_fill_data(SHLink *_target, SHLinkCustomData _data);
int8_t shilink_fill_custom_data(
 SHLinkCustomData *_data,
 const void *_key,
 uint16_t _sizeof_key,
 const void *_value,
 uint16_t _sizeof_value,
 SHLDataTypes _data_types
);
void shilink_free_custom_data(SHLinkCustomData *_data);
uint16_t shilink_count_data_by_key(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key
);
uint16_t shilink_count_data_by_key_val(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 const void *_value,
 uint16_t _sizeof_val
);
int8_t shilink_get_data_by_position(
 SHLink _target,
 int16_t _pos,
 SHLinkCustomData *_data
);
int8_t shilink_search_data_by_position(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 int16_t _pos,
 SHLinkCustomData *_data
);
int8_t shilink_search_data_by_prev_cond(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 SHLinkCustomData *_prev_cond_data,
 SHLinkCustomData *_data
);
int8_t shilink_search_data_by_pos_and_prev_cond(
 SHLink _target,
 const void *_key,
 uint16_t _sizeof_key,
 int16_t _pos,
 SHLinkCustomData *_prev_cond_data,
 SHLinkCustomData *_data
);
/* USER MODIFICATION PURPOSE END HERE */

int8_t shilink_push(SHLink *_target, SHLinkCustomData _data);
int8_t shilink_append(SHLink *_target, SHLinkCustomData _data);
int8_t shilink_insert_after(SHLink *_target, SHLinkCustomData _data_cond, SHLinkCustomData _data);
int8_t shilink_insert_before(SHLink *_target, SHLinkCustomData _data_cond, SHLinkCustomData _data);
int8_t shilink_delete(SHLink *_target, SHLinkCustomData _data);
int8_t shilink_update(SHLink *_target, SHLinkCustomData _data_old, SHLinkCustomData _data_new);
void shilink_print(SHLink _target);
void shilink_free(SHLink *_target);

#ifdef __cplusplus
    }
#endif

#endif