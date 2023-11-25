# Define tools and flags
CC = clang
XCRUN = xcrun -sdk iphoneos
CFLAGS = -arch arm64 -g
CODESIGN = codesign
DEVELOPER_ID = "YOUR DEVELOPER ID"
ENTITLEMENTS = entitlements.xml

# Targets
RUNNER_TARGET = runner
RUNNER_SRC = runner.c
INTERPOSE_TARGET = interpose.dylib
INTERPOSE_SRC = interpose.c
MAIN_TARGET = main.app/main
MAIN_SRC = main.c
APP_DIR = main.app

# Default target
all: $(RUNNER_TARGET) $(MAIN_TARGET)

# Build runner
$(RUNNER_TARGET): $(RUNNER_SRC)
        $(CC) -o $(RUNNER_TARGET) $(RUNNER_SRC)
        $(CODESIGN) -s $(DEVELOPER_ID) --entitlements $(ENTITLEMENTS) --force $(RUNNER_TARGET)

# Build main and create app bundle
$(MAIN_TARGET): $(MAIN_SRC) $(INTERPOSE_TARGET)
        $(XCRUN) $(CC) $(CFLAGS) -o main $(MAIN_SRC) $(INTERPOSE_TARGET)
        mkdir -p $(APP_DIR)
        cp Info.plist $(APP_DIR)/
        mv main $(APP_DIR)/
        $(CODESIGN) -s $(DEVELOPER_ID) --entitlements $(ENTITLEMENTS) --force $(APP_DIR)

# Build interpose.dylib
$(INTERPOSE_TARGET): $(INTERPOSE_SRC)
        $(XCRUN) $(CC) $(CFLAGS) -o $(INTERPOSE_TARGET) -shared $(INTERPOSE_SRC)

# Clean up build artifacts
clean:
        rm -rf $(RUNNER_TARGET) $(INTERPOSE_TARGET) $(APP_DIR)

.PHONY: all clean
