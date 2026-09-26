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
@property (readonly, nonatomic) NSData * kData;
@property (readonly, nonatomic) struct mach_header_64 header;
- (instancetype) initWithPath:(NSString *)path error: (NSError **)error;
- (NSData *) extractSandboxKext;

@end

#endif /* Kernelcache_h */
