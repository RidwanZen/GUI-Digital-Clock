#ifndef UI_WINDOW_H_  
#define UI_WINDOW_H_

#include <stdio.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <time.h>

typedef struct _window_clock
{
    GtkWidget *window;
    GtkWidget *window_box;
    GtkWidget *box1;
    GtkWidget *box2;
    GtkWidget *box3;
    GtkWidget *box_alarm;
    GtkWidget *box_waktu;
    GtkWidget *box_hari;
    GtkWidget *grid_suhu;
    GtkWidget *icon1;
    GtkWidget *icon2;
    GtkWidget *icon_alarm;
    GtkWidget *label_name;
    GtkWidget *label_tanggal;
    GtkWidget *label_alarm;
    GtkWidget *label_waktu;
    GtkWidget *label_titik;
    GtkWidget *label_suhu;
    GtkWidget *label_temp;
    GtkWidget *label_hari;
    GtkWidget *label_catatan;
    GtkWidget *label_creator;
    GtkWidget *value_alarm;
    GtkWidget *value_waktu;
    GtkWidget *value_detik;
    GtkWidget *value_suhu;
    GtkWidget *button_alarm;

}Window_clock;

extern Window_clock ui_clock;

typedef struct _window_alarm
{
    GtkWidget *window_alarm;
    GtkWidget *w_alarm_box;
    GtkWidget *box4;
    GtkWidget *box5;
    GtkWidget *scroller_window;
    GtkWidget *view_port;
    GtkWidget *grid_alarm;
    GtkWidget *grid_message;
    GtkWidget *grid_edit;
    GtkWidget *grid_delete;
    GtkWidget *button_close;
    GtkWidget *button_add_alarm;
    GtkWidget *label_header_alarm;
    GtkWidget *label_list_alarm;
    GtkWidget *label_list_message;
    GtkWidget *icon_add;

    GtkWidget *label1[50];
    GtkWidget *label2[50];
    GtkWidget *button_edit_alarm[50];
    GtkWidget *button_delete_alarm[50];
    GtkWidget *icon_edit;
    GtkWidget *icon_remove;
    GtkWidget *hbox[50];

}Window_alarm;

extern Window_alarm ui_alarm;

typedef struct _window_set_alarm
{
    GtkWidget *window_set_alarm;
    GtkWidget *box_set_alarm;
    GtkWidget *box_message;
    GtkWidget *box_time_alarm;
    GtkWidget *box_ringtones;
    GtkWidget *box_tombol;
    GtkWidget *combo_box_jam;
    GtkWidget *combo_box_menit;
    GtkWidget *combo_box_ringtones;
    GtkWidget *label_header_set_alarm;
    GtkWidget *label_message;
    GtkWidget *label_ringtone;
    GtkWidget *label_1;
    GtkWidget *entry_message;
    GtkWidget *button_ok;
    GtkWidget *button_cancel;

}Window_set_alarm;

extern Window_set_alarm ui_set_alarm;

// typedef struct _day_name
// {
//     char *sunday = "SUN";
//     char *monday = "MON";
//     char *tuesday = "TUE";
//     char *wednesday = "WED";
//     char *thursday = "THU";
//     char *friday = "FRI";
//     char *saturday = "SAT";
// }Day_name;

// extern Day_name day_name;

extern const char *day_name[7] =
{
  "SUN",
  "MON",
  "TUE",
  "WED",
  "THU",
  "FRI",
  "SAT"
};

void gtk_builder_and_attrib_init();
void ui_gtk_get_object();
void gtk_mainWindow_setAttrib();
void gtk_mainWindow_connect();
static void ui_gtk_widget_signal_connect();

static gboolean ui_load_image_helper(GtkWidget **_widget,int _width,int _height,char *_file);
void ui_gtk_set_image();
static gboolean ui_gtk_set_label_text(GtkWidget **_widget, char *_text);
static gboolean ui_set_label_color(GtkWidget **_widget, char *_color);
gboolean ui_is_gui_running();
gboolean ui_update(gpointer not_used);
static void ui_lbl_dtime();

static void view_windowAlarm();
static void close_windowAlarm();
static void view_window_SetAlarm();
static void close_window_SetAlarm();
char *IntToStr(int x);
void list_alarm();
void set_alarm();
static void add_text(GtkListStore *model, char *text);
static void wrapper2text(GtkCellLayout *cell_layout, GtkCellRenderer *cell,
   			GtkTreeModel *model, GtkTreeIter *iter, gpointer data) ;


void get_list_ringtones(GtkListStore *_gtklist, char *_str);
void alarm_start();
int8_t th_alarm_start();

void Refresh();

#endif
