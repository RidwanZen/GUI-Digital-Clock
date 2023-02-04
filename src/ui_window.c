
#include <errno.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../inc/ui_window.h"
#include "../inc/fungsiDebug.h"
#include "shiki-time-tools/shiki-time-tools.h"

#define GLADE_FILE      "ui_clock.glade"
#define CSS_FILE      	"style.css"
#define VERSION         "V0.1"

Window_clock ui_clock;

const char *day_name[];

GtkBuilder *builder;
GtkCssProvider *cssProvider;



gboolean isGuiRunning = FALSE;

int i=0;

int main(int argc, char **argv)
{
    //start ui
    debug(__func__,"INFO:","GUI START");
	debug(__func__,"INFO:", "GUI VERSION : %s", VERSION);
    gtk_init(&argc, &argv);
	gtk_builder_and_attrib_init();
	ui_gtk_get_object();
	gtk_mainWindow_setAttrib();
	ui_gtk_widget_signal_connect();
	ui_gtk_set_image();
	gtk_builder_connect_signals(builder, NULL);
	g_timeout_add_seconds(1, (GSourceFunc) ui_update, NULL);
    gtk_widget_show(ui_clock.window);
	g_object_unref(builder);
	// gdk_threads_add_idle(ui_update, NULL);
	g_idle_add(ui_update,NULL);
	gtk_main();
	return 0;
}

void gtk_builder_and_attrib_init(){
	GError *err = NULL;
    builder=gtk_builder_new();
	if(!gtk_builder_add_from_file (builder, GLADE_FILE, &err))
	{
		debug(__func__,"ERROR:","FAILED OPEN : %s",GLADE_FILE);
		if(err){
			printf("[%d] %s\n",err->code,err->message);
			g_error_free (err);
			err = NULL;
			exit(1);
		}
	}
	else debug(__func__,"INFO:","BUILDER FROM %s",GLADE_FILE);
	
	cssProvider = gtk_css_provider_new();
	gtk_css_provider_load_from_path(cssProvider, CSS_FILE, NULL);
}

static void gtk_get_object_helper(GtkWidget **widget , char *widget_name){

	*widget = GTK_WIDGET(gtk_builder_get_object(builder, widget_name));
	if(*widget==NULL) debug(__func__,"ERROR:","FAILED GET %s",widget_name);
}

void ui_gtk_get_object(){
	gtk_get_object_helper(&ui_clock.window			, "window");
	gtk_get_object_helper(&ui_clock.window_box		, "window_box");
	gtk_get_object_helper(&ui_clock.box1			, "box1");
	gtk_get_object_helper(&ui_clock.box2			, "box2");
	gtk_get_object_helper(&ui_clock.box3			, "box3");
	gtk_get_object_helper(&ui_clock.box_alarm		, "box_alarm");
	gtk_get_object_helper(&ui_clock.box_waktu		, "box_waktu");
	gtk_get_object_helper(&ui_clock.box_hari		, "box_hari");
	gtk_get_object_helper(&ui_clock.grid_suhu		, "grid_suhu");
	gtk_get_object_helper(&ui_clock.icon1			, "icon1");
	gtk_get_object_helper(&ui_clock.icon2			, "icon2");
	gtk_get_object_helper(&ui_clock.icon_alarm		, "icon_alarm");
	gtk_get_object_helper(&ui_clock.label_name		, "lb_name");
	gtk_get_object_helper(&ui_clock.label_alarm		, "lb_alarm");
	gtk_get_object_helper(&ui_clock.label_tanggal	, "lb_tanggal");
	gtk_get_object_helper(&ui_clock.label_waktu		, "lb_waktu");
	gtk_get_object_helper(&ui_clock.label_titik		, "lb_titik");
	gtk_get_object_helper(&ui_clock.label_suhu		, "lb_suhu");
	gtk_get_object_helper(&ui_clock.label_temp		, "lb_temp");
	gtk_get_object_helper(&ui_clock.label_hari		, "lb_hari");
	gtk_get_object_helper(&ui_clock.label_catatan	, "lb_catatan");
	gtk_get_object_helper(&ui_clock.label_creator	, "lb_creator");
	gtk_get_object_helper(&ui_clock.value_alarm		, "value_alarm");
	gtk_get_object_helper(&ui_clock.value_waktu		, "value_waktu");
	gtk_get_object_helper(&ui_clock.value_detik		, "value_detik");
	gtk_get_object_helper(&ui_clock.value_suhu		, "value_suhu");

gboolean ui_is_gui_running()
	{
    	return isGuiRunning;
	}

}

gboolean ui_is_gui_running(){
    return isGuiRunning;
}

void gtk_mainWindow_setAttrib(){
	// gtk_window_fullscreen(GTK_WINDOW(ui_clock.window));

	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(cssProvider), GTK_STYLE_PROVIDER_PRIORITY_USER);

}

void ui_gtk_set_image(){
	ui_load_image_helper(&ui_clock.icon_alarm,50,50,"asset/img/alarm-icon.png");
	ui_load_image_helper(&ui_clock.icon1,30,30,"asset/img/alarm-icon.png");
	ui_load_image_helper(&ui_clock.icon2,30,30,"asset/img/alarm-icon.png");

	
}

static void ui_gtk_widget_signal_connect(){
	g_signal_connect(ui_clock.window, "destroy", (GCallback) exit, NULL);
}

void gtk_mainWindow_connect(){

}

static gboolean ui_set_label_color(GtkWidget **_widget, char *_color){
	GdkColor color;
	gdk_color_parse(_color, &color);
	gtk_widget_modify_fg(*_widget, GTK_STATE_NORMAL, &color);
	return FALSE;
}

static gboolean ui_load_image_helper(GtkWidget **_widget,int _width,int _height,char *_file){
	GdkPixbuf * img_loader = NULL;
	GdkPixbuf * img = NULL;
	GError * err = NULL;
	img_loader = gdk_pixbuf_new_from_file (_file, &err);
	if(!img_loader){
		if(err){
			if(err->code==2) debug(__func__,"ERROR:","[%d] FAILED TO LOAD IMAGE %s",_file);
			else printf("[%d] %s\n",err->code,err->message);
			g_error_free (err);
		}
		return TRUE;
	}
	img = gdk_pixbuf_scale_simple(img_loader, _width, _height, GDK_INTERP_BILINEAR);
	g_object_unref(img_loader);
	if(!img) return TRUE;
	gtk_image_set_from_pixbuf ((GtkImage *)*_widget, img);
	g_object_unref(img);
	return FALSE;
}

static gboolean ui_gtk_set_label_text(GtkWidget **_widget, char *_text){
	gtk_label_set_text ((GtkLabel *)*_widget, _text);
	return FALSE;
}

gboolean ui_update(gpointer not_used){

	ui_lbl_dtime(NULL);

	return TRUE;
}

static void ui_lbl_dtime(){
	time_t time_now;
    struct tm *mtm;
    time(&time_now);
    mtm = localtime(&time_now);
    char tmp[30];
	char _wday_name[9];
	//set tanggal
    stim_get_date_custom_auto(tmp,date_format_custom1_eng);
    gtk_label_set_text ((GtkLabel *) ui_clock.label_tanggal, tmp);	
    //set waktu (jam & menit)
	stim_get_time_colon_auto(tmp,hhmm);
    gtk_label_set_text ((GtkLabel *) ui_clock.value_waktu, tmp);
	//set detik
	stim_get_time_colon_auto(tmp,ss);
    gtk_label_set_text ((GtkLabel *) ui_clock.value_detik, tmp);
	//set day
	stim_get_wday_eng_short(_wday_name, mtm->tm_wday);
	gtk_label_set_text ((GtkLabel *) ui_clock.label_hari, _wday_name);
	//set maridiem (AM/PM)
	stim_get_maridiem(tmp);
	gtk_label_set_text ((GtkLabel *) ui_clock.label_waktu, tmp);
	while(gtk_events_pending()) gtk_main_iteration();
}