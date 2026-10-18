//
//  RuleExporter.m
//  Bouncer
//
//  Created by praveen on 2026-10-18.
//

#import "RuleExporter.h"
#import "RuleTreeItem.h"

@implementation RuleExporter

static void appendIndent(NSMutableString * out, NSUInteger depth){
    for(NSUInteger i = 0; i < depth; i++){
        [out appendString:@"  "];
    }
}

static void appendItem(NSMutableString * out, RuleTreeItem * item, NSUInteger depth, NSMutableIndexSet * written){
    appendIndent(out, depth);
    if(item.isTerminal){
        [out appendFormat:@"%@\n", item.title];
        return;
    }
    if([written containsIndex:item.nodeIndex]){
        [out appendFormat:@"(goto 0x%04x)\n", item.nodeIndex];
        return;
    }
    [written addIndex:item.nodeIndex];
    NSArray<RuleTreeItem *> * children = item.children;
    switch(item.kind){
        case RuleTreeItemKindNode:
            [out appendFormat:@"(if %@ ; 0x%04x\n", item.title, item.nodeIndex];
            for(RuleTreeItem * child in children){
                appendItem(out, child, depth + 1, written);
            }
            break;
        case RuleTreeItemKindAnyOf:
        case RuleTreeItemKindAllOf:{
            [out appendFormat:@"(if (%@ ; 0x%04x\n", item.kind == RuleTreeItemKindAnyOf ? @"require-any" : @"require-all", item.nodeIndex];
            NSUInteger tests = item.chain.count;
            for(NSUInteger i = 0; i < tests; i++){
                appendIndent(out, depth + 2);
                [out appendFormat:@"%@%@\n", children[i].title, i + 1 == tests ? @")" : @""];
            }
            for(NSUInteger i = tests; i < children.count; i++){
                appendItem(out, children[i], depth + 1, written);
            }
            break;
        }
        case RuleTreeItemKindFirstOf:{
            [out appendFormat:@"(cond ; 0x%04x\n", item.nodeIndex];
            NSUInteger tests = item.chain.count;
            for(NSUInteger i = 0; i < tests; i++){
                appendIndent(out, depth + 1);
                [out appendFormat:@"(%@\n", children[i].title];
                for(RuleTreeItem * outcome in children[i].children){
                    appendItem(out, outcome, depth + 2, written);
                }
                appendIndent(out, depth + 1);
                [out appendString:@")\n"];
            }
            appendIndent(out, depth + 1);
            [out appendString:@"(else\n"];
            appendItem(out, children.lastObject, depth + 2, written);
            appendIndent(out, depth + 1);
            [out appendString:@")\n"];
            break;
        }
        case RuleTreeItemKindCondition:
        case RuleTreeItemKindCase:
            [out appendFormat:@"%@\n", item.title];
            return;
    }
    appendIndent(out, depth);
    [out appendString:@")\n"];
}

+(NSString *) textForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *)profile blob:(SandboxBlob *)blob{
    if(opIndex >= blob.operationNames.count){
        return nil;
    }
    uint16_t start = [profile nodeIndexForOperationAtIndex:opIndex];
    NSMutableString * out = [NSMutableString stringWithFormat:@";; %@ in %@\n(%@\n", blob.operationNames[opIndex], profile.name, blob.operationNames[opIndex]];
    appendItem(out, [RuleTreeItem itemForNode:start inBlob:blob role:nil], 1, [NSMutableIndexSet indexSet]);
    [out appendString:@")\n"];
    return out;
}

static NSString * dotEscaped(NSString * string){
    NSString * escaped = [string stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    return [escaped stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
}

+(NSString *) dotForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *)profile blob:(SandboxBlob *)blob{
    NSIndexSet * reachable = [blob reachableNodesForOperationAtIndex:opIndex inProfile:profile];
    if(!reachable){
        return nil;
    }
    uint16_t start = [profile nodeIndexForOperationAtIndex:opIndex];
    NSMutableString * out = [NSMutableString stringWithFormat:@"digraph \"%@\" {\n  node [fontname=\"Menlo\", fontsize=10];\n  label=\"%@ in %@\";\n",
                             dotEscaped(blob.operationNames[opIndex]), dotEscaped(blob.operationNames[opIndex]), dotEscaped(profile.name)];
    [reachable enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop){
        OpNode node = {0};
        if(![blob node:&node atIndex:index]){
            return;
        }
        NSString * label = dotEscaped([blob conditionDescriptionForNodeAtIndex:index limit:3] ?: @"?");
        NSString * extra = index == start ? @", penwidth=2" : @"";
        if(node.type == 1){
            NSString * color = (node.filterID & 1) ? @"#f4c7c3" : @"#c8e6c9";
            [out appendFormat:@"  n%lu [shape=box, style=filled, fillcolor=\"%@\", label=\"%@\"%@];\n", (unsigned long)index, color, label, extra];
            return;
        }
        [out appendFormat:@"  n%lu [shape=ellipse, label=\"0x%04lx\\n%@\"%@];\n", (unsigned long)index, (unsigned long)index, label, extra];
        [out appendFormat:@"  n%lu -> n%u [label=\"yes\"];\n", (unsigned long)index, node.matchNode];
        [out appendFormat:@"  n%lu -> n%u [label=\"no\", style=dashed];\n", (unsigned long)index, node.unmatchNode];
    }];
    [out appendString:@"}\n"];
    return out;
}

@end
