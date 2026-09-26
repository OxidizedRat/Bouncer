//
//  Kernelcache.h
//  Bouncer
//
//  Created by praveen on 2026-09-27.
//

#ifndef Kernelcache_h
#define Kernelcache_h

@interface Kernelcache : NSObject
@property (readonly, nonatomic) NSData * rawBytes;

- (instancetype) initWithPath:(NSString *)path error: (NSError *)error;
- (NSData *) extractSecurityKext;

@end

#endif /* Kernelcache_h */
