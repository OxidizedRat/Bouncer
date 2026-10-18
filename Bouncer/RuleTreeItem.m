//
//  RuleTreeItem.m
//  Bouncer
//
//  Created by praveen on 2026-10-18.
//

#import "RuleTreeItem.h"

static const NSUInteger kMaxChainLength = 4096;

@interface RuleTreeItem()
@property (readwrite) RuleTreeItemKind kind;
@property (readwrite) uint16_t nodeIndex;
@property (readwrite, weak) SandboxBlob * blob;
@property (readwrite, copy, nullable) NSString * role;
@property (readwrite, copy) NSString * title;
@property (readwrite) BOOL isTerminal;
@property (readwrite, copy) NSArray<NSNumber *> * chain;
@property (nonatomic, nullable) NSArray<RuleTreeItem *> * builtChildren;
@end

@implementation RuleTreeItem

static NSArray<NSNumber *> * chainFrom(SandboxBlob * blob, uint16_t start, BOOL throughMatch, BOOL (^keepGoing)(OpNode first, OpNode next)){
    NSMutableArray<NSNumber *> * chain = [NSMutableArray arrayWithObject:@(start)];
    OpNode first = {0};
    OpNode current = {0};
    if(![blob node:&first atIndex:start] || first.type != 0){
        return chain;
    }
    current = first;
    while(chain.count < kMaxChainLength){
        uint16_t nextIndex = throughMatch ? current.matchNode : current.unmatchNode;
        OpNode next = {0};
        if(![blob node:&next atIndex:nextIndex] || next.type != 0 || !keepGoing(first, next)){
            break;
        }
        [chain addObject:@(nextIndex)];
        current = next;
    }
    return chain;
}

+(instancetype) itemForNode:(uint16_t)nodeIndex inBlob:(SandboxBlob *)blob role:(NSString *)role{
    RuleTreeItem * item = [[RuleTreeItem alloc] init];
    item.nodeIndex = nodeIndex;
    item.blob = blob;
    item.role = role;
    item.kind = RuleTreeItemKindNode;
    item.chain = @[];
    OpNode node = {0};
    if(![blob node:&node atIndex:nodeIndex]){
        item.title = [NSString stringWithFormat:@"<invalid node 0x%04x>", nodeIndex];
        item.isTerminal = YES;
        return item;
    }
    item.isTerminal = node.type == 1;
    item.title = [blob conditionDescriptionForNodeAtIndex:nodeIndex] ?: @"?";
    if(item.isTerminal){
        return item;
    }

    NSArray<NSNumber *> * anyOf = chainFrom(blob, nodeIndex, NO, ^BOOL(OpNode first, OpNode next){
        return next.matchNode == first.matchNode;
    });
    if(anyOf.count >= 2){
        item.kind = RuleTreeItemKindAnyOf;
        item.chain = anyOf;
        item.title = [NSString stringWithFormat:@"any of %lu conditions", (unsigned long)anyOf.count];
        return item;
    }
    NSArray<NSNumber *> * allOf = chainFrom(blob, nodeIndex, YES, ^BOOL(OpNode first, OpNode next){
        return next.unmatchNode == first.unmatchNode;
    });
    if(allOf.count >= 2){
        item.kind = RuleTreeItemKindAllOf;
        item.chain = allOf;
        item.title = [NSString stringWithFormat:@"all of %lu conditions", (unsigned long)allOf.count];
        return item;
    }
    NSArray<NSNumber *> * firstOf = chainFrom(blob, nodeIndex, NO, ^BOOL(OpNode first, OpNode next){
        return YES;
    });
    if(firstOf.count >= 3){
        item.kind = RuleTreeItemKindFirstOf;
        item.chain = firstOf;
        item.title = [NSString stringWithFormat:@"first matching of %lu cases", (unsigned long)firstOf.count];
    }
    return item;
}

-(NSArray<RuleTreeItem *> *) children{
    if(self.builtChildren){
        return self.builtChildren;
    }
    NSMutableArray<RuleTreeItem *> * children = [NSMutableArray array];
    SandboxBlob * blob = self.blob;
    OpNode node = {0};
    OpNode last = {0};
    if(blob && !self.isTerminal && self.kind != RuleTreeItemKindCondition && [blob node:&node atIndex:self.nodeIndex]){
        if(self.chain.count){
            [blob node:&last atIndex:self.chain.lastObject.unsignedShortValue];
        }
        switch(self.kind){
            case RuleTreeItemKindNode:
                [children addObject:[RuleTreeItem itemForNode:node.matchNode inBlob:blob role:@"then"]];
                [children addObject:[RuleTreeItem itemForNode:node.unmatchNode inBlob:blob role:@"else"]];
                break;
            case RuleTreeItemKindAnyOf:
            case RuleTreeItemKindAllOf:
                for(NSNumber * test in self.chain){
                    [children addObject:[RuleTreeItem conditionItemForNode:test.unsignedShortValue inBlob:blob kind:RuleTreeItemKindCondition]];
                }
                [children addObject:[RuleTreeItem itemForNode:last.matchNode inBlob:blob role:@"then"]];
                [children addObject:[RuleTreeItem itemForNode:last.unmatchNode inBlob:blob role:@"else"]];
                break;
            case RuleTreeItemKindFirstOf:
                for(NSNumber * test in self.chain){
                    [children addObject:[RuleTreeItem conditionItemForNode:test.unsignedShortValue inBlob:blob kind:RuleTreeItemKindCase]];
                }
                [children addObject:[RuleTreeItem itemForNode:last.unmatchNode inBlob:blob role:@"otherwise"]];
                break;
            case RuleTreeItemKindCase:
                [children addObject:[RuleTreeItem itemForNode:node.matchNode inBlob:blob role:@"then"]];
                break;
            case RuleTreeItemKindCondition:
                break;
        }
    }
    self.builtChildren = children;
    return children;
}

+(instancetype) conditionItemForNode:(uint16_t)nodeIndex inBlob:(SandboxBlob *)blob kind:(RuleTreeItemKind)kind{
    RuleTreeItem * item = [[RuleTreeItem alloc] init];
    item.nodeIndex = nodeIndex;
    item.blob = blob;
    item.kind = kind;
    item.chain = @[];
    item.role = kind == RuleTreeItemKindCase ? @"if" : nil;
    item.title = [blob conditionDescriptionForNodeAtIndex:nodeIndex] ?: @"?";
    return item;
}

@end
