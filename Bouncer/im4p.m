//
//  im4p.m
//  Bouncer
//
//  Created by praveen on 2026-09-24.
//

#import <Foundation/Foundation.h>
#import "im4p.h"

@interface Im4p();

@property (nonatomic, readwrite, copy) NSData * kernelcache;

@end
@implementation Im4p

- (instancetype) initWithData:(NSData *) kernelcache{
    self = [super init];
    self.kernelcache = kernelcache;
    return self;
}
@end
