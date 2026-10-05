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
@interface Kernelcache : NSObject
@property (readonly, nonatomic) NSData * _Nullable data;
@property (readonly, nonatomic) struct mach_header_64 header;
@property (readonly) uint64_t sandboxKextOffset;
@property (readonly, nonatomic, copy) NSData * _Nullable blobProtobox;
@property (readonly, nonatomic, copy) NSData * _Nullable blobProfile;
@property (readonly, nonatomic, copy) NSData * _Nullable blobBuiltin;
- (instancetype _Nullable ) initWithPath:(NSString * _Nonnull)path error: (NSError *_Nullable* _Nullable)error;
@end

#endif /* Kernelcache_h */
