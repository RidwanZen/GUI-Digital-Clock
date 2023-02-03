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

}Window_clock;

extern Window_clock ui_clock;

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
static void ui_gtk_set_image();
static gboolean ui_gtk_set_label_text(GtkWidget **_widget, char *_text);
static void ui_set_label_color(GtkWidget **_widget, char *_color);
gboolean ui_is_gui_running();
gboolean ui_update(gpointer not_used);

#endif
