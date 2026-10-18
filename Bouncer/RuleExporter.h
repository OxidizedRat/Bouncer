//
//  RuleExporter.h
//  Bouncer
//
//  Created by praveen on 2026-10-18.
//

#ifndef RuleExporter_h
#define RuleExporter_h
#import <Foundation/Foundation.h>
#import "SandboxBlob.h"
NS_ASSUME_NONNULL_BEGIN

@interface RuleExporter : NSObject
+(nullable NSString *) textForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *)profile blob:(SandboxBlob *)blob;
+(nullable NSString *) dotForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *)profile blob:(SandboxBlob *)blob;
@end

NS_ASSUME_NONNULL_END
#endif /* RuleExporter_h */
