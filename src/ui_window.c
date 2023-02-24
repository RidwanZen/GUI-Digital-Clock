
#include <errno.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>

#include "../inc/ui_window.h"
#include "../inc/fungsiDebug.h"
#include "../inc/sql.h"
#include "shiki-time-tools/shiki-time-tools.h"

#define GLADE_FILE      "ui_clock.glade"
#define CSS_FILE      	"style.css"
#define RINGTONES_FILE  "asset/Ringtones/"
#define VERSION         "V0.1"

Window_clock ui_clock;
Window_alarm ui_alarm;
Window_set_alarm ui_set_alarm;

const char *day_name[];

GtkBuilder *builder;
GtkCssProvider *cssProvider;

static pthread_mutex_t lockCount = PTHREAD_MUTEX_INITIALIZER;

gboolean isGuiRunning = FALSE;

int i=0, z=0;

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
	gtk_mainWindow_connect();
	ui_gtk_set_image();
	gtk_builder_connect_signals(builder, NULL);
	set_alarm();
	enco_sql_open_buffer();
	sql_select_table ();
	th_alarm_start();
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
	gtk_get_object_helper(&ui_clock.button_alarm	, "bt_alarm");


	gtk_get_object_helper(&ui_alarm.window_alarm		, "window_alarm");
	gtk_get_object_helper(&ui_alarm.w_alarm_box			, "w_alarm_box");
	gtk_get_object_helper(&ui_alarm.box4				, "box4");
	gtk_get_object_helper(&ui_alarm.box5				, "box5");
	gtk_get_object_helper(&ui_alarm.scroller_window		, "scroller_window");
	gtk_get_object_helper(&ui_alarm.view_port			, "view_port");
	gtk_get_object_helper(&ui_alarm.button_close		, "bt_close");
	gtk_get_object_helper(&ui_alarm.button_add_alarm	, "bt_add_alarm");
	gtk_get_object_helper(&ui_alarm.label_header_alarm	, "lb_header_alarm");
	gtk_get_object_helper(&ui_alarm.label_list_alarm	, "lb_list_alarm");
	gtk_get_object_helper(&ui_alarm.label_list_message	, "lb_list_message");


	gtk_get_object_helper(&ui_set_alarm.window_set_alarm		, "window_set_alarm");
	gtk_get_object_helper(&ui_set_alarm.box_set_alarm			, "box_set_alarm");
	gtk_get_object_helper(&ui_set_alarm.box_message				, "box_message");
	gtk_get_object_helper(&ui_set_alarm.box_time_alarm			, "box_time_alarm");
	gtk_get_object_helper(&ui_set_alarm.box_ringtones			, "box_ringtones");
	gtk_get_object_helper(&ui_set_alarm.box_tombol				, "box_tombol");
	gtk_get_object_helper(&ui_set_alarm.combo_box_jam			, "combo_box_jam");
	gtk_get_object_helper(&ui_set_alarm.combo_box_menit			, "combo_box_menit");
	gtk_get_object_helper(&ui_set_alarm.combo_box_ringtones		, "combo_box_ringtones");
	gtk_get_object_helper(&ui_set_alarm.label_header_set_alarm	, "lb_header_set_alarm");
	gtk_get_object_helper(&ui_set_alarm.label_1					, "lb1");
	gtk_get_object_helper(&ui_set_alarm.label_message			, "lb_set_message");
	gtk_get_object_helper(&ui_set_alarm.label_ringtone			, "lb_ringtones");
	gtk_get_object_helper(&ui_set_alarm.entry_message			, "entry_message");
	gtk_get_object_helper(&ui_set_alarm.button_ok				, "bt_ok");
	gtk_get_object_helper(&ui_set_alarm.button_cancel			, "bt_cancel");

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
	// gtk_window_fullscreen(GTK_WINDOW(ui_alarm.window_alarm));

	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(cssProvider), GTK_STYLE_PROVIDER_PRIORITY_USER);

}

static void view_windowAlarm(){
	debug(__func__,"INFO:","Open Window_Alarm");
	gtk_widget_show_all(ui_alarm.window_alarm);
	gtk_widget_hide(ui_clock.window);
}

static void close_windowAlarm(){
	debug(__func__,"INFO:","Close Window_Alarm");
	gtk_widget_show_all(ui_clock.window);
	gtk_widget_hide(ui_alarm.window_alarm);
}

static void view_window_SetAlarm(){
	debug(__func__,"INFO:","Open Window_SetAlarm");
	gtk_widget_show_all(ui_set_alarm.window_set_alarm);
	sql_insert_alarm_list("12:12","baka","aho");
}

static void close_window_SetAlarm(){
	debug(__func__,"INFO:","Close Window_SetAlarm");
	gtk_widget_hide(ui_set_alarm.window_set_alarm);
	cek_quary();
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
	g_signal_connect(ui_clock.button_alarm, "clicked", G_CALLBACK (view_windowAlarm), NULL);
	g_signal_connect(ui_alarm.button_close, "clicked", G_CALLBACK (close_windowAlarm), NULL);
	g_signal_connect(ui_alarm.button_add_alarm, "clicked", G_CALLBACK (view_window_SetAlarm), NULL);
	g_signal_connect(ui_set_alarm.button_cancel, "clicked", G_CALLBACK (close_window_SetAlarm), NULL);
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
	list_alarm();
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
	stim_get_time_colon_auto(tmp,hhmm,format_24);
    gtk_label_set_text ((GtkLabel *) ui_clock.value_waktu, tmp);
	//set detik
	stim_get_time_colon_auto(tmp,ss,NULL);
    gtk_label_set_text ((GtkLabel *) ui_clock.value_detik, tmp);
	//set day
	stim_get_wday_eng_short(_wday_name, mtm->tm_wday);
	gtk_label_set_text ((GtkLabel *) ui_clock.label_hari, _wday_name);
	//set maridiem (AM/PM)
	stim_get_maridiem(tmp);
	gtk_label_set_text ((GtkLabel *) ui_clock.label_waktu, tmp);
	while(gtk_events_pending()) gtk_main_iteration();
}

void list_alarm(){
	
	if(i<count){
		sql_GetValue_alarm();
		ui_alarm.hbox[i] = gtk_hbox_new(0,0);
		gtk_container_add(GTK_CONTAINER(ui_alarm.box5), ui_alarm.hbox[i]);

		ui_alarm.label1[i] = gtk_label_new(NULL);
		ui_alarm.label2[i] = gtk_label_new(alarm_mesg);
		const char *value = alarm_time;
		char *markup = g_strdup_printf ("<span font=\"14\" color=\"red\">"
                               		"<b>%s</b>"
									"</span>",value);
									
		gtk_label_set_markup (GTK_LABEL (ui_alarm.label1[i]), markup);
		g_free (markup);

		ui_alarm.icon_edit = gtk_image_new ();
		ui_alarm.icon_remove = gtk_image_new ();
		ui_load_image_helper(&ui_alarm.icon_edit,30,30,"asset/img/edit.png");
		ui_load_image_helper(&ui_alarm.icon_remove,30,30,"asset/img/remove.png");

		ui_alarm.button_edit_alarm[i] = gtk_button_new ();
		ui_alarm.button_delete_alarm[i] = gtk_button_new ();

		gtk_button_set_image(ui_alarm.button_edit_alarm[i],ui_alarm.icon_edit);
		gtk_button_set_image(ui_alarm.button_delete_alarm[i],ui_alarm.icon_remove);

		gtk_box_pack_start(GTK_BOX(ui_alarm.hbox[i]), ui_alarm.label1[i], 1, 0, 5);
		gtk_box_pack_start(GTK_BOX(ui_alarm.hbox[i]), ui_alarm.label2[i], 1, 0, 5);
		gtk_box_pack_start(GTK_BOX(ui_alarm.hbox[i]), ui_alarm.button_edit_alarm[i], 0, 0, 1);
		gtk_box_pack_start(GTK_BOX(ui_alarm.hbox[i]), ui_alarm.button_delete_alarm[i], 0, 0, 1);

		i++;
	}

}

enum
{
  TEXT_COL,
  ICON_NAME_COL

};


typedef struct _wrapper {
    char * text;
} Wrapper;

static void wrapper2text(GtkCellLayout *cell_layout, GtkCellRenderer *cell,
   			GtkTreeModel *model, GtkTreeIter *iter, gpointer data) 
{
    Wrapper * w;
    gtk_tree_model_get (model, iter, 0, &w, -1);
    g_object_set (cell, "text", w->text, NULL);
}

static void add_text(GtkListStore *model, char *text) {
    GtkTreeIter new_row;
    Wrapper * w;
     w = g_new0(Wrapper, 1);
    w->text = g_strdup(text);
    gtk_list_store_append(model, &new_row);
    gtk_list_store_set(model, &new_row, 0, w, -1);
}

char *IntToStr(int x){
	char *str=(char *)malloc(1 * sizeof (char));	// Mengalokasikan blok memory sebesar 1byte dan di pointing ke pointer str
	sprintf(str, "%02d", x);	// Memasukkan data integer x ke str
	return str;
}


void set_alarm(){
	GtkListStore * ringtones;
    GtkListStore * model_jam, *model_menit;
    GType *columns;
	GtkCellRenderer *renderer;;
	char str[100];

	columns = g_new0 (GType, 1);
    columns[0] = G_TYPE_POINTER;
    model_jam = gtk_list_store_newv(1, columns);
    model_menit = gtk_list_store_newv(1, columns);
    ringtones = gtk_list_store_newv(1, columns);
	get_list_ringtones(ringtones,str);
	for(int a=0;a<60;a++){
		if(a <= 23 )
			add_text(model_jam, IntToStr(a));
    	
		add_text(model_menit, IntToStr(a));
	}
    g_free(columns);
	// gtk_combo_box_set_active(GTK_COMBO_BOX(ui_set_alarm.combo_box_ringtones), -1);
    // ui_set_alarm.combo_box_menit = gtk_combo_box_new_with_model_and_entry(GTK_TREE_MODEL(model));
	gtk_combo_box_set_entry_text_column(ui_set_alarm.combo_box_menit,0);
	gtk_combo_box_set_entry_text_column(ui_set_alarm.combo_box_jam,0);
	gtk_combo_box_set_entry_text_column(ui_set_alarm.combo_box_ringtones,0);
	gtk_combo_box_set_model(ui_set_alarm.combo_box_menit,model_menit);
	gtk_combo_box_set_model(ui_set_alarm.combo_box_jam,model_jam);
	gtk_combo_box_set_model(ui_set_alarm.combo_box_ringtones,ringtones);
    renderer = gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(ui_set_alarm.combo_box_menit), renderer, TRUE);
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(ui_set_alarm.combo_box_jam), renderer, TRUE);
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(ui_set_alarm.combo_box_ringtones), renderer, TRUE);
    gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT(ui_set_alarm.combo_box_menit), renderer, NULL);
    gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT(ui_set_alarm.combo_box_jam), renderer, NULL);
    gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT(ui_set_alarm.combo_box_ringtones), renderer, NULL);
    gtk_cell_layout_set_cell_data_func(GTK_CELL_LAYOUT(ui_set_alarm.combo_box_menit), renderer,wrapper2text, NULL, NULL);
    gtk_cell_layout_set_cell_data_func(GTK_CELL_LAYOUT(ui_set_alarm.combo_box_jam), renderer,wrapper2text, NULL, NULL);
    gtk_cell_layout_set_cell_data_func(GTK_CELL_LAYOUT(ui_set_alarm.combo_box_ringtones), renderer,wrapper2text, NULL, NULL);

}

void get_list_ringtones(GtkListStore *_gtklist, char *_str){
	DIR *d;
    struct dirent *dir;
    d = opendir(RINGTONES_FILE);

    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {	
			memset(_str,0,sizeof(_str));
			sprintf(_str,"%s",dir->d_name);
			if(strcmp(_str,"."))
				if(strcmp(_str,"..")){
					add_text(_gtklist, _str);
            		printf("%s\n", _str);
				}
        }
        closedir(d);
    }

}

void alarm_start(){

	// const gchar *tmp = NULL;
	char tmp[10];
	char *alarm_time="21:53";

	while(1){
	// tmp = gtk_label_get_text(ui_clock.value_waktu);
	stim_get_time_colon_auto(tmp,hhmm,format_24);
	if(!strcmp(tmp, alarm_time))
		system("mpv asset/Ringtones/papa_ohayou.mp3");
	}
	
}

int8_t th_alarm_start()
{
	pthread_t th_s;
	if(pthread_create(&th_s,NULL,alarm_start,NULL))
	{
		debug(__func__, "INFO:", "ALARM START THREAD FAILED");
		return 1;
	}
	return 0;
}
