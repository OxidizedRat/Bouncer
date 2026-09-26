//
//  Kernelcache.m
//  Bouncer
//
//  Created by praveen on 2026-09-27.
//

#import <Foundation/Foundation.h>
#import "Kernelcache.h"

@interface Kernelcache()
@property (readwrite) NSData *rawBytes;

@end

@implementation Kernelcache

- (instancetype) initWithPath:(NSString *)path error:(NSError *)error{
    self = [super init];
    
    NSData * data = [NSData dataWithContentsOfURL:[NSURL URLWithString:path] options:NSDataReadingMappedAlways error:&error];
    if (!data){
        error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Failed to map file"}];
        return nil;
    }
    uint32_t magic = 0;
    [data getBytes:&magic range:NSMakeRange(0, 4)];
    switch (magic) {
        case 0xCFFAEFFE:
            self.rawBytes = data;
            return self;
            break;
        case 0xCEFAEDFE:
            error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"32-bit mach-o not implemented"}];
            return nil;
            break;
        case 0xBEBAFECA:
            error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Universal binary not implemented"}];
            return nil;
            break;
        default:
            error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Invalid magic"}];
            break;
    }
    return nil;
}

@end
