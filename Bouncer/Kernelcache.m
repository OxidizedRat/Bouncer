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
@property (readwrite) NSDictionary<NSString *, NSNumber *> *sandboxKextInfo;
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
    NSDictionary * sandboxKextInfo = [self extractSandboxKextWithError:error];
    if(!sandboxKextInfo){
        return nil;
    }
    self.sandboxKextInfo = sandboxKextInfo;
    return self;
}

- (NSDictionary *) extractSandboxKextWithError:(NSError **)error{
    if(!error){
        return nil;
    }
    //locate fileset load command
    uint32_t numCmds = self.header.ncmds;
    uint64_t currentOffset = 0 + sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < numCmds; i++ ){
        struct load_command lc;
        if(self.data.length < currentOffset + sizeof(lc)){
            *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"OOB when reading load commands"}];
            return nil;
        }
        [self.data getBytes:&lc range:NSMakeRange(currentOffset, sizeof(lc))];
        if (lc.cmdsize == 0 || lc.cmdsize < sizeof(struct load_command)){
            *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"invalid load command size"}];
            return nil;
        }
        if(lc.cmd ==LC_FILESET_ENTRY){
            struct fileset_entry_command fileEntryCommand;
            [self.data getBytes:&fileEntryCommand range:NSMakeRange(currentOffset, sizeof(fileEntryCommand))];
            
            uint32_t idOffset = fileEntryCommand.entry_id.offset;
            if(idOffset > lc.cmdsize){
                *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"OOB when reading lc id"}];
                return nil;
            }
            
            const uint8_t *bytes = [self.data bytes];
            const char *entryID = (const char*)(bytes + currentOffset + idOffset);
            size_t maxLen = lc.cmdsize -idOffset;
            size_t len = strnlen(entryID, maxLen);
             
            NSString *name = (len < maxLen) ? [[NSString alloc] initWithBytes:entryID length:len encoding:NSUTF8StringEncoding] : nil;
            
            if ([name isEqualToString:@"com.apple.security.sandbox"]){
                
                uint64_t kextOffset = fileEntryCommand.fileoff;
                uint64_t kextVMAddr = fileEntryCommand.vmaddr;
                NSDictionary<NSString *, NSNumber *> *info = @{@"kextOffset": [NSNumber numberWithUnsignedLongLong:kextOffset], @"kextVMAddr": [NSNumber numberWithUnsignedLongLong:kextVMAddr]};
                return info;
                break;
            }
        }
        currentOffset += lc.cmdsize;
    }
    *error = [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Could not locate sandbox kext in mach-o"}];
    return nil;
    
}

- (NSData *) extractSandboxBlobsWithError:(NSError **)error{
    
    return nil;
}
@end
