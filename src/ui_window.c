
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

#define GLADE_FILE      "ui_clock.glade"
#define CSS_FILE      	"style.css"
#define VERSION         "V0.1"

Window_clock *ui_clock = NULL;

GtkBuilder *builder;
GtkCssProvider *cssProvider;

gboolean isGuiRunning = FALSE;
GtkWidget *window;
int main(int argc, char **argv)
{
    //start ui
    debug(__func__,"INFO:","GUI START");
    gtk_init(&argc, &argv);
	gtk_builder_and_attrib_init();
	ui_gtk_get_object();
	gtk_mainWindow_setAttrib();
	gtk_builder_connect_signals(builder, NULL);

    gtk_widget_show(&ui_clock->window);
			printf("tes\n");
	g_object_unref(builder);
	gtk_main();
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

static void gtk_get_object_helper(GtkWidget *widget , char *widget_name){

	widget = GTK_WIDGET(gtk_builder_get_object(builder, widget_name));
	if(widget==NULL) debug(__func__,"ERROR:","FAILED GET %s",widget_name);
}

void ui_gtk_get_object(){
	gtk_get_object_helper(&ui_clock->window			, "window");
	gtk_get_object_helper(&ui_clock->window_box		, "window_box");
	gtk_get_object_helper(&ui_clock->box1			, "box1");
	gtk_get_object_helper(&ui_clock->box2			, "box2");
	gtk_get_object_helper(&ui_clock->box3			, "box3");
	gtk_get_object_helper(&ui_clock->box_alarm		, "box_alarm");
	gtk_get_object_helper(&ui_clock->box_waktu		, "box_waktu");
	gtk_get_object_helper(&ui_clock->box_hari		, "box_hari");
	gtk_get_object_helper(&ui_clock->grid_suhu		, "grid_suhu");
	gtk_get_object_helper(&ui_clock->icon1			, "icon1");
	gtk_get_object_helper(&ui_clock->icon2			, "icon2");
	gtk_get_object_helper(&ui_clock->icon_alarm		, "icon_alarm");
	gtk_get_object_helper(&ui_clock->label_name		, "lb_name");
	gtk_get_object_helper(&ui_clock->label_alarm	, "lb_alarm");
	gtk_get_object_helper(&ui_clock->label_tanggal	, "lb_tanggal");
	gtk_get_object_helper(&ui_clock->label_titik	, "lb_titik");
	gtk_get_object_helper(&ui_clock->label_suhu		, "lb_suhu");
	gtk_get_object_helper(&ui_clock->label_temp		, "lb_temp");
	gtk_get_object_helper(&ui_clock->label_hari		, "lb_hari");
	gtk_get_object_helper(&ui_clock->label_catatan	, "lb_catatan");
	gtk_get_object_helper(&ui_clock->label_creator	, "lb_creator");
	gtk_get_object_helper(&ui_clock->value_alarm	, "value_alarm");
	gtk_get_object_helper(&ui_clock->value_waktu	, "value_waktu");
	gtk_get_object_helper(&ui_clock->value_detik	, "value_detik");
	gtk_get_object_helper(&ui_clock->value_suhu		, "value_suhu");
	gboolean ui_is_gui_running(){
		// printf("tes\n");
    return isGuiRunning;
	}

}

gboolean ui_is_gui_running(){
    return isGuiRunning;
}

void gtk_mainWindow_setAttrib(){
	//~ gtk_window_fullscreen(GTK_WINDOW(ui_clock->window));

	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(cssProvider), GTK_STYLE_PROVIDER_PRIORITY_USER);

}

void gtk_mainWindow_connect(){

}
