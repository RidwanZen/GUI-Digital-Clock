#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include "shiki-net-tools.h"

#define URL_FOR_TEST_DOWNLOAD_SPEED "http://speedtest.ftp.otenet.gr/files/test1Mb.db"
//#define URL_FOR_TEST_DOWNLOAD_SPEED "https://raw.githubusercontent.com/JayaWikrama/STM32-SQLite-Encrypted-Data/master/tct"
//#define URL_FOR_TEST_DOWNLOAD_SPEED "https://raw.githubusercontent.com/JayaWikrama/STM32-SQLite-Encrypted-Data/master/script"
#define INFO "INFO"
#define WARNING "WARNING"
#define CRITICAL "CRITICAL"

static size_t snetCallback(void *curl_data, size_t size, size_t nmemb, void *un_used_data);

static size_t snetCallback(void *curl_data, size_t size, size_t nmemb, void *un_used_data)
{
  
  (void)un_used_data;
  (void)curl_data;
  return (size_t)(size * nmemb);
}

int snet_speed_test(char *_snet_speed_test_url, struct snet_speed_test *_snet_speed_data){
  CURL *curl_handle;
  CURLcode retval;
  struct timespec tm_start, tm_end;
  int time_correction_factor = 800;
  int retval_of_func = 0;

  curl_global_init(CURL_GLOBAL_ALL);
  curl_handle = curl_easy_init();

  //specify URL to get
  curl_easy_setopt(curl_handle, CURLOPT_URL, _snet_speed_test_url);

  //send all data to this function
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, snetCallback);
  
  //execute
  my_net_debug(__func__, INFO, "check speed starting...");
  my_net_debug(__func__, INFO, "test url: %s", _snet_speed_test_url);
  clock_gettime(CLOCK_MONOTONIC, &tm_start);
  retval = curl_easy_perform(curl_handle);
  clock_gettime(CLOCK_MONOTONIC, &tm_end);
  my_net_debug(__func__, INFO, "check speed done...");
  
  //calculate parameters
  if(retval == CURLE_OK) {
    curl_off_t pass_val;
    
    if(curl_easy_getinfo(curl_handle, CURLINFO_SIZE_DOWNLOAD, &pass_val) == CURLE_OK) _snet_speed_data->total_download = (int)pass_val;
    _snet_speed_data->total_time = ((tm_end.tv_sec - tm_start.tv_sec)*1000.0+(tm_end.tv_nsec - tm_start.tv_nsec)/1000000.0) - time_correction_factor;
    _snet_speed_data->download_speed = (_snet_speed_data->total_download/_snet_speed_data->total_time)/1.24;

    if(_snet_speed_data->total_download <=0 || _snet_speed_data->total_time <=0 || _snet_speed_data->download_speed <=0) retval_of_func = -2;
  }
  else {
    fprintf(stderr, "Error while fetching '%s' : %s\n", _snet_speed_test_url, curl_easy_strerror(retval));
    retval_of_func = -1;
  }
  curl_easy_cleanup(curl_handle);
  curl_global_cleanup();

  return retval_of_func;
}