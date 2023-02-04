
WORKING_DIRECTORY = $(shell pwd)
CROSS_PLATFORM =

ARM_CFLAGS = -I/usr/lib/arm-linux-gnueabihf/glib-2.0/include/ \
             -I/usr/lib/arm-linux-gnueabihf/dbus-1.0/include/

ILOCAL_DIR = -I$(WORKING_DIRECTORY)/lib/ \
            -I$(WORKING_DIRECTORY)/src/
            
IADDITIONAL = -I/usr/include/atk-1.0 \
          -I/usr/include/at-spi-2.0 \
          -I/usr/include/at-spi2-atk/2.0 \
          -I/usr/include/dbus-1.0 \
          -I/usr/include/freetype2 \
          -I/usr/include/gio-unix-2.0/ \
          -I/usr/include/gdk-pixbuf-2.0 \
          -I/usr/include/pango-1.0 \
          -I/usr/include/pixman-1 \
          -I/usr/include/cairo \
          -I/usr/include/glib-2.0 \
          -I/usr/include/gtk-3.0 \

IFLAGS += $(ILOCAL_DIR)

PKG_CONFIG = `pkg-config --cflags --libs gtk+-3.0 glib-2.0`

LADDITIONAL = -latk-1.0 \
             -lcairo \
             -lcairo-gobject \
             -lcrypto \
             -lpangocairo-1.0 \
             -lpango-1.0 \
             -lwiringPi \
             -lgdk_pixbuf-2.0 \
             -lrt \
             -lgdk-3 \
             -lgio-2.0 \
             -lgobject-2.0

LFLAGS = -lcrypt \
         -lcrypto \
         -lgtk-3 \
         -lglib-2.0 \
         -lm \
         -lpthread \
	     -lssl \
         -lsqlite3 \
         $(PKG_CONFIG)


SHIKI_TOOLS = lib/shiki-system-tools/shiki-system-tools.c \
			  lib/shiki-config-tools/shiki-config-tools.c \
			  lib/shiki-uart-tools/shiki-uart-tools.c \
              lib/shiki-time-tools/shiki-time-tools.c \
              lib/shiki-tcp-ip-tools/shiki-tcp-ip-tools.c \
              lib/shiki-linked-list/shiki-linked-list.c \
              lib/shiki-net-tools/snet-ping.c \
              lib/shiki-net-tools/snet-core.c

SOURCE = src/ui_window.c \
		 src/fungsiDebug.c \
         $(SHIKI_TOOLS)

TARGET          = Gui_Clock
BUILD_DIRECTORY = build
OBJ_DIRECTORY   = obj
CC              = gcc 
CFLAGS          = -Wall
OBJECTS         = $(patsubst %.c,$(OBJ_DIRECTORY)/%.o,$(SOURCE))
TIME_CREATED    = `date +%y.%m.%d_%H.%M.%S`
GIT_IGNORE_CMD  = `cat .gitignore | grep -v $(OBJ_DIRECTORY) | grep -v $(BUILD_DIRECTORY)`

vpath $(TARGET) $(BUILD_DIRECTORY)
vpath %.o $(OBJ_DIRECTORY)

$(TARGET): $(OBJECTS)
	@echo
	@echo "  \033[1;33mCreating executable file : $@\033[0m"
	$(CC) $(CFLAGS) $(OBJECTS) -o $(BUILD_DIRECTORY)/$@ $(LFLAGS) $(IFLAGS) 
	@cp $(BUILD_DIRECTORY)/$@ $(BUILD_DIRECTORY)/$@_$(TIME_CREATED)

$(OBJ_DIRECTORY)/%.o: %.c
	@echo
	@echo "  \033[1;32mCompiling: $<\033[0m"
	$(call init_proc);
	$(CC) $(CFLAGS) -c $< -o $@ $(LFLAGS) $(IFLAGS) 

init:
	$(call init_proc);
	@echo "$(GIT_IGNORE_CMD)" > .gitignore
	@echo "$(OBJ_DIRECTORY)/" >> .gitignore
	@echo "$(BUILD_DIRECTORY)/" >> .gitignore
	@echo "dir.struct" >> .gitignore

clean:
	@rm -fv `find . -type f -name '*.o'`
	@rm -fv ./$(BUILD_DIRECTORY)/$(TARGET)

define init_proc
	@mkdir -p $(OBJ_DIRECTORY)
	@mkdir -p $(BUILD_DIRECTORY)
	@find . -type f -name '*.c' -printf '%h\n' |sort -u | grep -v '$(BUILD_DIRECTORY)' | grep -v '$(OBJ_DIRECTORY)' > dir.struct
	@cd $(OBJ_DIRECTORY) && xargs mkdir -p < ../dir.struct
endef

