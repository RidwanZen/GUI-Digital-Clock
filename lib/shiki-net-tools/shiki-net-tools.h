#ifndef SHIKI_NET_TOOLS_H
#define SHIKI_NET_TOOLS_H

struct snet_speed_test{
  int total_download;
  float download_speed, total_time;
};

//Global Function
//core
void my_net_debug(const char *function_name, char *debug_type, char *debug_msg, ...);
//ping
int snet_ping(char *_address, int _num_of_ping);
//net-speed
int snet_speed_test(char *_snet_speed_test_url, struct snet_speed_test *_snet_speed_data);
//get-data
int snet_get_data_and_save(char *_snet_speed_test_url, struct snet_speed_test *_snet_speed_data, char *_save_to);
int snet_get_data_to_str(char *_snet_data_url, char *_snet_curl_data);
#endif
