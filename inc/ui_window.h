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

void gtk_builder_and_attrib_init();
void ui_gtk_get_object();
void gtk_mainWindow_setAttrib();
void gtk_mainWindow_connect();
gboolean ui_is_gui_running();

#endif
