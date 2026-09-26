//
//  ipsw.h
//  Bouncer
//
//  Created by praveen on 2026-09-24.
//

#ifndef ipsw_h
#define ipsw_h

@interface Ipsw : NSObject
@property (nonatomic, readonly, copy)  NSData *kernelcache;

- (instancetype) initWithPath:(NSString *)path error:(NSError **)error;

@end
#endif /* ipsw_h */
