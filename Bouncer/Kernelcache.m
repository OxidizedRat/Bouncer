//
//  Kernelcache.m
//  Bouncer
//
//  Created by praveen on 2026-09-27.
//

#import <Foundation/Foundation.h>
#import "Kernelcache.h"
#import <mach-o/loader.h>

@interface Kernelcache()
@property (readwrite) NSData *data;
@property (readwrite) struct mach_header_64 header;
@end

@implementation Kernelcache

- (instancetype) initWithPath:(NSString *)path error:(NSError **)error{
    if (!error){
        return nil;
    }
    self = [super init];
    if (!self){
        return nil;
    }
    NSData * data = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:path] options:NSDataReadingMappedAlways error:error];
    if (!data){
        return nil;
    }
    struct mach_header_64 header;
    if (data.length < sizeof(header)){
        *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"File is too small to be valid mach-o 64"}];
        return nil;
    }
    [data getBytes:&header range:NSMakeRange(0, sizeof(header))];
    
    if (header.magic != MH_MAGIC_64){
        *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Invalid or unsupported magic"}];
        return nil;
    }
    if (header.cputype != CPU_TYPE_ARM64){
        *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Invalid cpu type"}];
        return nil;
    }
    if (header.filetype != MH_FILESET){
        *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Invalid file type"}];
        return nil;
    }
    
    self.header = header;
    self.data = data;
    
    return self;
}

- (NSData *) extractSandboxKext{
    
    NSData * sandboxKext = [[NSData alloc]init];
    
    
    return nil;
    
}

@end
