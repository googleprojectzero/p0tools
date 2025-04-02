# Makefile to compile Objective-C and C/C++ source files with debug symbols

# Compilers
CC = clang
CXX = clang++

# Frameworks and Libraries
FRAMEWORKS = -framework Foundation -framework CoreAudio

# Compiler Flags
CFLAGS = -fno-omit-frame-pointer -Wall -Wunused-parameter -Wextra -std=c++17#-fsanitize=address

INCLUDE_PATHS = -I./helpers -I.

# Source Files
SOURCES = harness.mm \
          helpers/SwizzleHelper.mm \
          helpers/debug.cc \
          helpers/initialization.cc \
          helpers/load_library.cc \
          helpers/audit_token.cc \
          helpers/message.cc \

# Header Files (not mandatory to list them, but can be useful)
HEADERS = helpers/SwizzleHelper.h \
          helpers/debug.h \
          helpers/initialization.h \
          helpers/load_library.h \
          helpers/audit_token.h \
          helpers/message.h \
          harness.h

# Output Executables
OUTPUT = harness
DYLIB_OUTPUT = libmach-modify.dylib

# Default target
all: $(OUTPUT) $(DYLIB_OUTPUT)

# Link and compile the source files into the output executable
$(OUTPUT): $(SOURCES)
	$(CXX) $(CFLAGS) $(INCLUDE_PATHS) $(FRAMEWORKS) $(SOURCES) -o $(OUTPUT)

# Build the dynamic library
$(DYLIB_OUTPUT): mach-modify.c
	$(CC) -dynamiclib -g -o $(DYLIB_OUTPUT) mach-modify.c -ldl -framework CoreAudio $(INCLUDE_PATHS)

# Clean the build artifacts
clean:
	rm -f $(OUTPUT) $(DYLIB_OUTPUT)

# Phony targets
.PHONY: all clean