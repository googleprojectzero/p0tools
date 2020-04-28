//
// Example runner implementation for fuzzing ImageIO on macOS
//

#include <Foundation/Foundation.h>
#include <Foundation/NSURL.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/shm.h>
#include <dirent.h>

#import <ImageIO/ImageIO.h>
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>

#include <libhfuzz/instrument.h>

extern bool CGRenderingStateGetAllowsAcceleration(void*);
extern bool CGRenderingStateSetAllowsAcceleration(void*, bool);
extern void* CGContextGetRenderingState(CGContextRef);

void dummyLogProc() { }

extern void HF_ITER(uint8_t** buf, size_t* len);
extern void ImageIOSetLoggingProc(void*);

int main(int argc, const char* argv[]) {
    NSError* err = 0;

    // Must manually load libOpenEXR
    dlopen("/System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libOpenEXR.dylib", RTLD_LAZY);
    //dlopen("/System/Library/PrivateFrameworks/AppleVPA.framework/AppleVPA", RTLD_LAZY);

    // Replace with dummy log procedure to save a few CPU cylces
    // (logging should additionally be disabled via environment variables).
    ImageIOSetLoggingProc(&dummyLogProc);

    initializeTrapfuzz();

    size_t len;
    uint8_t* buf;

    for (int i = 0; i < 10000; i++) {
        HF_ITER(&buf, &len);

        NSData* content = [NSData dataWithBytes:buf length:len];
        NSImage* img = [[NSImage alloc] initWithData:content];

        CGImageRef cgImg = [img CGImageForProposedRect:nil context:nil hints:nil];
        if (cgImg) {
            size_t width = CGImageGetWidth(cgImg);
            size_t height = CGImageGetHeight(cgImg);
            CGColorSpaceRef colorspace = CGColorSpaceCreateDeviceRGB();
            CGContextRef ctx = CGBitmapContextCreate(0, width, height, 8, 0, colorspace, 1);
            void* renderingState = CGContextGetRenderingState(ctx);
            CGRenderingStateSetAllowsAcceleration(renderingState, false);
            CGRect rect = CGRectMake(0, 0, width, height);
            CGContextDrawImage(ctx, rect, cgImg);

            CGColorSpaceRelease(colorspace);
            CGContextRelease(ctx);
            CGImageRelease(cgImg);
        }

        [img release];
        [content release];
    }

    return 0;
}
