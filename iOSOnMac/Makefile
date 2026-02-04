CLANG_MACOS := xcrun --sdk macosx -r clang
CLANG_IOS := xcrun --sdk iphoneos -r clang
IOS_SYSROOT := $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG_IOS_FLAGS := -arch arm64 -isysroot $(IOS_SYSROOT)

.PHONY: all clean
all: runner main interpose.dylib

interpose.dylib: interpose.c
	$(CLANG_IOS) $(CLANG_IOS_FLAGS) -shared -o interpose.dylib interpose.c

main: main.c
	$(CLANG_IOS) $(CLANG_IOS_FLAGS) -o main main.c

runner: runner.c entitlements.xml
	$(CLANG_MACOS) -o runner runner.c
	@if [ -n "$(IDENTITY)" ]; then \
		codesign -s "$(IDENTITY)" --entitlements entitlements.xml --force runner; \
	elif command -v ldid >/dev/null 2>&1; then \
		ldid -Sentitlements.xml runner; \
	else \
		echo "Error: No signing method available. Set IDENTITY or install ldid."; \
		echo "Find available certificates using: security find-identity"; \
		exit 1; \
	fi

clean:
	@rm -f runner interpose.dylib main
