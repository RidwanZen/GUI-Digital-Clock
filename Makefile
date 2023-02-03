ADDITIONAL_VER = `date +%y.%m.%d.%H`
CC = gcc -g
CFLAGS = -Wall `pkg-config --cflags gtk+-3.0` -D_VERSION=\"$(ADDITIONAL_VER)\"
INCLUDE = `pkg-config --libs gtk+-3.0 glib-2.0`
BUILD_DIRECTORY = build
OBJ_DIRECTORY = obj
SOURCE = 	src/ui_window.c \
			src/fungsiDebug.c 

OBJECTS = $(patsubst %.c,$(OBJ_DIRECTORY)/%.o,$(SOURCE))
TARGET = Gui_Clock
TIME_CREATED = `date +%y.%m.%d_%H.%M.%S`
GIT_IGNORE_CMD = `cat .gitignore | grep -v $(OBJ_DIRECTORY) | grep -v $(BUILD_DIRECTORY)`

vpath $(TARGET) $(BUILD_DIRECTORY)
vpath %.o $(OBJ_DIRECTORY)

$(TARGET): $(OBJECTS)
	@echo
	@echo "  \033[1;33mCreating executable file : $@\033[0m"
	$(CC) $(CFLAGS) $(OBJECTS) -o $(BUILD_DIRECTORY)/$@ $(INCLUDE)
	@cp $(BUILD_DIRECTORY)/$@ $(BUILD_DIRECTORY)/$@_$(TIME_CREATED)

$(OBJ_DIRECTORY)/%.o: %.c
	@echo
	@echo "  \033[1;32mCompiling: $<\033[0m"
	$(call init_proc);
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE) -fpic

debug:
	$(CC) $(CFLAGS) $(SOURCE) src/main.c $(INCLUDE) -g

init:
	$(call init_proc);
	@echo "$(GIT_IGNORE_CMD)" > .gitignore
	@echo "$(OBJ_DIRECTORY)/" >> .gitignore
	@echo "$(BUILD_DIRECTORY)/" >> .gitignore

clean:
	@rm -fv `find . -type f -name '*.o'`
	@rm -fv ./$(BUILD_DIRECTORY)/$(TARGET)

define init_proc
	@mkdir -p $(OBJ_DIRECTORY)
	@mkdir -p $(BUILD_DIRECTORY)
	@find . -type f -name '*.c' -printf '%h\n' |sort -u | grep -v '$(BUILD_DIRECTORY)' | grep -v '$(OBJ_DIRECTORY)' > dir.struct
	@cd $(OBJ_DIRECTORY) && xargs mkdir -p < ../dir.struct
endef
