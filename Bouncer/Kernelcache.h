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
@property (readonly, nonatomic) NSData * data;
@property (readonly, nonatomic) struct mach_header_64 header;
@property (readonly, nonatomic) NSData * blobs;
- (instancetype) initWithPath:(NSString *)path error: (NSError **)error;
- (NSData *) extractSandboxKext;
- (NSData *) extractSandboxBlobs;
@end

#endif /* Kernelcache_h */
