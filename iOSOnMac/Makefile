# Compiler and codesign settings
CC = xcrun -sdk iphoneos clang
CFLAGS = -arch arm64 -g
CODESIGN = codesign
DEVELOPER_ID = "Developer ID"  # Placeholder for developer identity

# Targets
RUNNER_TARGET = runner
RUNNER_SRC = runner.c
INTERPOSE_TARGET = interpose.dylib
INTERPOSE_SRC = interpose.c
MAIN_TARGET = main.app/main
MAIN_SRC = main.c
APP_DIR = main.app

# Default target
all: $(RUNNER_TARGET) $(INTERPOSE_TARGET) $(MAIN_TARGET)

# Build runner
$(RUNNER_TARGET): $(RUNNER_SRC)
	$(CC) -o $(RUNNER_TARGET) $(RUNNER_SRC)
	$(CODESIGN) -s $(DEVELOPER_ID) --entitlements entitlements.xml --force $(RUNNER_TARGET)

# Build interpose.dylib
$(INTERPOSE_TARGET): $(INTERPOSE_SRC)
	$(CC) $(CFLAGS) -o $(INTERPOSE_TARGET) -shared $(INTERPOSE_SRC)

# Build main and create app bundle
$(MAIN_TARGET): $(MAIN_SRC) $(INTERPOSE_TARGET)
	$(CC) $(CFLAGS) -o main $(MAIN_SRC) $(INTERPOSE_TARGET)
	mkdir -p $(APP_DIR)
	cp Info.plist $(APP_DIR)/
	mv main $(APP_DIR)/
	$(CODESIGN) -s $(DEVELOPER_ID) --entitlements entitlements.xml --force $(APP_DIR)

# Clean up build artifacts
clean:
	rm -rf $(RUNNER_TARGET) $(INTERPOSE_TARGET) $(APP_DIR)

.PHONY: all clean
