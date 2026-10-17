//
//  Kernelcache.h
//  Bouncer
//
//  Created by praveen on 2026-09-27.
//

#ifndef Kernelcache_h
#define Kernelcache_h
#import <mach-o/loader.h>
#import <Foundation/Foundation.h>
#import "SandboxBlob.h"
NS_ASSUME_NONNULL_BEGIN
@interface Kernelcache : NSObject
@property (readonly, nonatomic) NSData * _Nullable data;
@property (readonly, nonatomic) struct mach_header_64 header;
@property (readonly) uint64_t sandboxKextOffset;
@property (readonly) SandboxBlob * builtin;
@property (readonly) SandboxBlob * protobox;
@property (readonly) SandboxBlob * profile;
@property (readonly, copy) NSArray<NSString *> * operationNames;
- (instancetype _Nullable ) initWithPath:(NSString * _Nonnull)path error: (NSError *_Nullable* _Nullable)error;
@end
NS_ASSUME_NONNULL_END
#endif /* Kernelcache_h */
