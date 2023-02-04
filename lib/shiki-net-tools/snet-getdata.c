#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include "shiki-net-tools.h"

//#define URL_RESOURCE_FILE "http://speedtest.ftp.otenet.gr/files/test1Mb.db"
//#define URL_RESOURCE_FILE "https://raw.githubusercontent.com/JayaWikrama/STM32-SQLite-Encrypted-Data/master/tct"
//#define URL_RESOURCE_FILE "https://raw.githubusercontent.com/JayaWikrama/STM32-SQLite-Encrypted-Data/master/script"
//#define URL_RESOURCE_FILE "https://www.google.com/search?source=hp&ei=GKpfXeSLA4DFz7sPm7aYiAQ&q=cara+buat+npwp"
//#define CURL_FILE_OUTPUT "curl_data.download"
#define url_server "192.168.10.100:/home/Delameta/update/"
#define SIZE_OF_CURL_DATA 100000
#define INFO "INFO"
#define WARNING "WARNING"
#define CRITICAL "CRITICAL"

static size_t snetCallback_and_save_data(void *curl_data, size_t size, size_t nmemb, void *stream);

char curl_data_tmp[SIZE_OF_CURL_DATA];

static size_t snetCallback_and_save_data(void *curl_data, size_t size, size_t nmemb, void *stream)
{
  size_t retval_write_opt = fwrite(curl_data, size, nmemb, (FILE *)stream);
  return retval_write_opt;
}

static size_t snetCallback(void *curl_data, size_t size, size_t nmemb, void *un_used_data)
{
  (void)un_used_data;
  memset(curl_data_tmp, 0x00, SIZE_OF_CURL_DATA*sizeof(char));
  strcpy(curl_data_tmp, (char *)curl_data);
  return (size_t)(size * nmemb);
}

int snet_get_data_and_save(char *_snet_download_url, struct snet_speed_test *_snet_speed_data, char *_save_to){
  CURL *curl_handle;
  CURLcode retval;
  struct timespec tm_start, tm_end;
  int time_correction_factor = 800;
  int retval_of_func;

  retval_of_func = 0;

  curl_global_init(CURL_GLOBAL_ALL);
  curl_handle = curl_easy_init();

  //specify URL to get
  curl_easy_setopt(curl_handle, CURLOPT_URL, _snet_download_url);

  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, snetCallback_and_save_data);
  
  //execute
  FILE *curl_fd;
  if((curl_fd = fopen(_save_to, "wb")) == NULL){
    my_net_debug(__func__, CRITICAL, "fail to open curl_file_output");
    retval_of_func = -1;
  }
  else{
    my_net_debug(__func__, INFO, "download starting...");
    my_net_debug(__func__, INFO, "download url: %s", _snet_download_url);
        
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, curl_fd);

    clock_gettime(CLOCK_MONOTONIC, &tm_start);
    retval = curl_easy_perform(curl_handle);
    clock_gettime(CLOCK_MONOTONIC, &tm_end);
 
    fclose(curl_fd);
    my_net_debug(__func__, INFO, "download done. check your download file in: %s", _save_to);
  }
  
  //calculate parameters
  if(retval == CURLE_OK) {
    curl_off_t pass_val;
    
    if(curl_easy_getinfo(curl_handle, CURLINFO_SIZE_DOWNLOAD, &pass_val) == CURLE_OK) _snet_speed_data->total_download = (int)pass_val;
    _snet_speed_data->total_time = ((tm_end.tv_sec - tm_start.tv_sec)*1000.0+(tm_end.tv_nsec - tm_start.tv_nsec)/1000000.0) - time_correction_factor;
    _snet_speed_data->download_speed = (_snet_speed_data->total_download/_snet_speed_data->total_time)/1.24;

    //masih perlu diperbaiki
    //if(_snet_speed_data->total_download <=0 || _snet_speed_data->total_time <=0 || _snet_speed_data->download_speed <=0) retval_of_func = -2;
  }
  else {
    fprintf(stderr, "Error while fetching '%s' : %s\n", _snet_download_url, curl_easy_strerror(retval));
    retval_of_func = -1;
  }
  curl_easy_cleanup(curl_handle);
  curl_global_cleanup();
  return retval_of_func;
}

int snet_get_data_to_str(char *_snet_data_url, char *_snet_curl_data){
  CURL *curl_handle;
  CURLcode retval;
  int retval_of_func = 0;

  curl_global_init(CURL_GLOBAL_ALL);
  curl_handle = curl_easy_init();

  //specify URL to get
  curl_easy_setopt(curl_handle, CURLOPT_URL, _snet_data_url);

  //send all data to this function
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, snetCallback);
  //curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intle Mac OS X 10_6_8) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.112 Safari/543.30");
  
  //execute
  my_net_debug(__func__, INFO, "get data starting...");
  my_net_debug(__func__, INFO, "test url: %s", _snet_data_url);
  retval = curl_easy_perform(curl_handle);
  my_net_debug(__func__, INFO, "get data done...");
  
  //calculate parameters
  if(retval == CURLE_OK) {
    strcpy(_snet_curl_data, curl_data_tmp);
    memset(curl_data_tmp, 0x00, SIZE_OF_CURL_DATA*sizeof(char));
  }
  else {
    fprintf(stderr, "Error while fetching '%s' : %s\n", _snet_data_url, curl_easy_strerror(retval));
    retval_of_func = -1;
  }
  curl_easy_cleanup(curl_handle);
  curl_global_cleanup();

  return retval_of_func;
}
