//
//  RuleTreeItem.h
//  Bouncer
//
//  Created by praveen on 2026-10-18.
//

#ifndef RuleTreeItem_h
#define RuleTreeItem_h
#import <Foundation/Foundation.h>
#import "SandboxBlob.h"
NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, RuleTreeItemKind){
    RuleTreeItemKindNode,
    RuleTreeItemKindAnyOf,
    RuleTreeItemKindAllOf,
    RuleTreeItemKindFirstOf,
    RuleTreeItemKindCondition,
    RuleTreeItemKindCase,
};

@interface RuleTreeItem : NSObject
@property (readonly) RuleTreeItemKind kind;
@property (readonly) uint16_t nodeIndex;
@property (readonly, weak) SandboxBlob * blob;
@property (readonly, copy, nullable) NSString * role;
@property (readonly, copy) NSString * title;
@property (readonly) BOOL isTerminal;
@property (readonly, copy) NSArray<NSNumber *> * chain;
@property (readonly, copy) NSArray<RuleTreeItem *> * children;

+(instancetype) itemForNode:(uint16_t)nodeIndex inBlob:(SandboxBlob *)blob role:(nullable NSString *)role;
@end

NS_ASSUME_NONNULL_END
#endif /* RuleTreeItem_h */
