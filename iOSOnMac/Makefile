all : runner main interpose.dylib

interpose.dylib : interpose.c
	clang interpose.c -arch arm64 -o interpose.dylib -shared -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

main : main.c
	clang main.c -arch arm64 -o main -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

runner : runner.c entitlements.xml
	clang runner.c -o runner
	# Replace this identity, find available certificates usign `security find-identity`
	codesign -s "XXXXXXXXXX" --entitlements entitlements.xml --force runner
