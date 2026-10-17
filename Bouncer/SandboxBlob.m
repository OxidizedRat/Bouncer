//
//  SandboxBlob.m
//  Bouncer
//
//  Created by praveen on 2026-10-05.
//

#import <Foundation/Foundation.h>
#import "SandboxBlob.h"
#include <os/overflow.h>

static NSError * sandboxError(NSString *errorMessage){
    return [NSError errorWithDomain:@"sandboxErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:errorMessage}];
}

@interface SandboxProfile()
@property (readwrite, nonatomic, copy) NSData * opTable;
@property (readwrite, copy) NSString * name;
@end
@implementation SandboxProfile
-(instancetype __nullable) initWithName:(NSString *)name opTable:(NSData *)opTable{
    self = [super init];
    if(!self){
        return nil;
    }
    self.name = name;
    self.opTable = opTable;
    return self;
}
-(uint16_t) nodeIndexForOperationAtIndex:(NSUInteger)index{
    if(index >= self.opTable.length/2){
        return UINT16_MAX;
    }
    uint16_t nodeIndex = UINT16_MAX;
    [self.opTable getBytes:&nodeIndex range:NSMakeRange(index * 2, sizeof(nodeIndex))];
    
    return nodeIndex;
}
@end
@interface SandboxBlob()
@property (readwrite, nonatomic, copy) NSData * data;
@property (readwrite) SandboxBlobHeader header;
@property (readwrite) SandboxBlobType type;
@property (readwrite, copy) NSData * nodes;
@property (readwrite) uint64_t baseStart;
@property (readwrite) uint64_t tablesEnd;
@property (readwrite) NSArray<SandboxProfile *> *profiles;
@property (readwrite, copy) NSArray<NSString *> * operationNames;
@end

@implementation SandboxBlob

- (instancetype __nullable) initWithData:(NSData *)blob operationNames:(NSArray<NSString *> *) operationNames error:(NSError *__autoreleasing *)error{
    self = [super init];
    if(!self) return nil;
    
    self.data = blob;
    SandboxBlobHeader header;
    
    if(![self readBlobChecked:&header offset:0 size:sizeof(header) error:error]){
        return nil;
    }
    self.header = header;
    uint64_t nodeStart = 0;
    uint64_t tablesEnd = sizeof(header) +
                         (self.header.sizeTable1 +
                         self.header.sizeTable2 +
                         self.header.sizeTable3 +
                         self.header.sizeTable4 +
                         self.header.numRegex +
                         self.header.numGlobalVariables ) * 2;
    self.tablesEnd = tablesEnd;
    switch (self.header.type){
        case SandboxBlobTypeProfile:
            self.type = SandboxBlobTypeProfile;
            nodeStart = tablesEnd + self.header.numOperations * 2;
            break;
        case SandboxBlobTypeCollection:
            self.type = SandboxBlobTypeCollection;
            nodeStart = tablesEnd + self.header.numProfiles * ( sizeof(SandboxProfileHeader) + self.header.numOperations * 2);
            break;
        default:
            if(error){*error = sandboxError(@"Invalid blob type");}
            return nil;
    }
    
    nodeStart = (nodeStart + 7 ) & ~7;
    
    uint16_t numNodes = self.header.numOpNodes;
    self.baseStart = nodeStart + numNodes * 8;
    if(![self rangeIsValid:nodeStart size: (numNodes * 8)]){
        if(error){*error = sandboxError(@"Invalid op node section size");}
        return nil;
    }
    self.nodes = [self.data subdataWithRange:NSMakeRange(nodeStart, numNodes * 8)];
    uint64_t currentProfilePosition = tablesEnd;
    uint64_t profileSize = sizeof(SandboxProfileHeader) + (2 * self.header.numOperations);
    NSMutableArray * profiles = [[NSMutableArray alloc]init];
    if(self.header.type == SandboxBlobTypeProfile){
        if(![self rangeIsValid:tablesEnd size: self.header.numOperations *2]){
            if(error){*error = sandboxError(@"OOB when reading sandbox profile data");}
            return nil;
        }
        NSData *profileData = [self.data subdataWithRange:NSMakeRange(tablesEnd, self.header.numOperations * 2)];
        NSData * opTable = [profileData subdataWithRange:NSMakeRange(0,  (self.header.numOperations * 2))];
        
        SandboxProfile *profile = [[SandboxProfile alloc] initWithName:@"Platform" opTable:opTable];
        if(!profile){
            if(error){*error = sandboxError(@"Failed to init SandboxProfile");}
            return nil;
        }
        [profiles addObject:profile];
        if(operationNames.count < self.header.numOperations){
            if(error){*error = sandboxError(@"Expected operation name count and provided operation name count mismatch");}
            return nil;
        }
        self.operationNames = [operationNames subarrayWithRange:NSMakeRange(0, self.header.numOperations)];
        self.profiles = profiles;
        if(![self validateNodesAndOperationsWithError:error]){
            return nil;
        }
        return self;
    }
    
    for(uint64_t i = 0; i < self.header.numProfiles; i++){
        
        if(![self rangeIsValid:currentProfilePosition size:profileSize]){
            if(error){*error = sandboxError(@"OOB when reading sandbox profiles");}
            return nil;
        }
        NSData * profileData = [self.data subdataWithRange:NSMakeRange(currentProfilePosition, profileSize)];
        SandboxProfileHeader profileHeader;
        if(![self readBlobChecked:&profileHeader offset:currentProfilePosition size:sizeof(profileHeader) error:error]){
            return nil;
        }
        
        NSData * opTable = [profileData subdataWithRange:NSMakeRange(sizeof(SandboxProfileHeader),  self.header.numOperations * 2)];
        
        NSString * profileString = [self stringAtBaseOffset:profileHeader.nameOffset];
        if(!profileString){
            if(error){*error = sandboxError(@"Failed to get sandbox profile string");}
            return nil;
        }
        SandboxProfile * profile = [[SandboxProfile alloc] initWithName:profileString opTable:opTable];
        if(!profile){
            if(error){*error = sandboxError(@"Failed to init SandboxProfile");}
            return nil;
        }
        [profiles addObject:profile];
        
        currentProfilePosition += profileSize;
    }
    if(operationNames.count < self.header.numOperations){
        if(error){*error = sandboxError(@"Expected operation name count and provided operation name count mismatch");}
        return nil;
    }
    self.operationNames = [operationNames subarrayWithRange:NSMakeRange(0, self.header.numOperations)];
    self.profiles = profiles;
    if(![self validateNodesAndOperationsWithError:error]){
        return nil;
    }
    return self;
}

- (BOOL)readBlobChecked:(void *)buffer offset:(uint64_t)offset size:(uint64_t)size error:(NSError *__autoreleasing *)error{
    
    if(!self.data){
        if(error){*error = sandboxError(@"blob data is empty");}
        return NO;
    }
    if(![self rangeIsValid:offset size:size]){
        if(error){*error = sandboxError(@"OOB when reading from data");}
        return NO;
    }
    [self.data getBytes:buffer range:NSMakeRange(offset, size)];
    return YES;
}
-(BOOL)rangeIsValid: (uint64_t) offset size:(uint64_t) size {
    if(!self.data){
        return NO;
    }
    uint64_t totalSize;
    if (os_add_overflow(offset,size, &totalSize )){
        return NO;
    }
    if(self.data.length < totalSize){
        return NO;
    }
    return YES;
}
-(nullable NSString *) stringAtBaseOffset: (uint64_t) offset{
    uint64_t stringDataOffset = self.baseStart + offset * 8;
    uint16_t stringLen;
    if(![self rangeIsValid:stringDataOffset size:sizeof(stringLen)]){
        return nil;
    }
    [self.data getBytes:&stringLen range:NSMakeRange(stringDataOffset, sizeof(stringLen))];
    
    if(!stringLen){
        return nil;
    }
    if(![self rangeIsValid:stringDataOffset + 2 size:stringLen]){
        return nil;
    }
    const uint8_t * bytes = self.data.bytes;
    if(bytes[stringDataOffset + 2 + stringLen -1] != 0){
        return nil;
    }
    NSString * profileString = [[NSString alloc] initWithBytes:(const char *)self.data.bytes + stringDataOffset + 2 length:stringLen - 1 encoding:NSUTF8StringEncoding];
    
    return profileString;
}
-(BOOL) node:(OpNode *)outNode atIndex:(uint16_t)index{
    if(index >= self.header.numOpNodes){
        return NO;
    }
    uint64_t indexOffset = (uint64_t) index * sizeof(OpNode);
    if(indexOffset + sizeof(OpNode) > self.nodes.length){
        return NO;
    }
    [self.nodes getBytes:outNode range:NSMakeRange(indexOffset, sizeof(OpNode))];
        
    return YES;
}
-(BOOL) validateNodesAndOperationsWithError:(NSError **) error{
    if(!self.nodes){
        if(error){*error = sandboxError(@"nodes object not created yet");}
        return NO;
    }
    
    for(uint64_t i = 0 ; i < self.header.numOpNodes; i++){
        OpNode node;
        if(![self node:&node atIndex:i]){
            if(error){*error = sandboxError(@"node lookup failed");}
            return NO;
        }
        switch (node.type){
            case 0:
                if(node.matchNode >= self.header.numOpNodes){
                    if(error){*error = sandboxError(@"OOB when validating nodes");}
                    return NO;
                }
                if(node.unmatchNode >= self.header.numOpNodes){
                    if(error){*error = sandboxError(@"OOB when validating nodes");}
                    return NO;
                }
                if(node.unmatchNode <= i || node.matchNode <= i){
                    if(error){*error = sandboxError(@"node forward only check failed");}
                    return NO;
                }
                
                break;
            case 1:
                continue;
            default:
                if(error){*error = sandboxError(@"unknown node type");}
                return NO;
        }
        
    }
    
    for (SandboxProfile* profile in self.profiles){
        for(uint64_t i = 0 ; i < self.header.numOperations; i++){
            uint16_t nodeIndex = [profile nodeIndexForOperationAtIndex:i];
            if(nodeIndex >= self.header.numOpNodes){
                if(error){*error = sandboxError(@"invalid operation for operation index");}
                return NO;
            }
        }
        
    }
    return YES;
}
-( NSIndexSet * _Nullable ) reachableNodesForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *) profile{
    if(opIndex >= self.operationNames.count){
        return nil;
    }
    NSMutableIndexSet * indexSet = [[NSMutableIndexSet alloc] init];
    uint16_t startNode = [profile nodeIndexForOperationAtIndex:opIndex];
    OpNode node = {0};
    NSMutableArray<NSNumber *> * stack = [[NSMutableArray alloc] init];
    [stack addObject:@(startNode)];
    while(stack.count > 0){
        uint16_t currentNodeIndex = [stack lastObject].unsignedShortValue;
        [stack removeLastObject];
        if([indexSet containsIndex:currentNodeIndex]){
            continue;
        }
        [self node:&node atIndex:currentNodeIndex];
        [indexSet addIndex:currentNodeIndex];
        if(node.type == 1){
            continue;
        }
        [stack addObject:@(node.matchNode)];
        [stack addObject:@(node.unmatchNode)];
    }
    return indexSet;


}

-(OperationVerdic) verdictForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *) profile{
    
    uint16_t startNodeIndex = [profile nodeIndexForOperationAtIndex:opIndex];
    OpNode startNode = {0};
    [self node:&startNode atIndex:startNodeIndex];
    
    if(startNode.type == 1){
        switch(startNode.filterID & 1){
            case NO:
                return OperationVerdictAlwaysAllow;
            case YES:
                return OperationVerdictAlwaysDeny;
        }
    }
    NSIndexSet *reachableNodes = [self reachableNodesForOperationAtIndex:opIndex inProfile:profile];
    if(opIndex >= self.operationNames.count){
        return OperationVerdictInvalid;
    }
    __block BOOL allowSeen = NO;
    __block BOOL denySeen = NO;
    [reachableNodes enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop){
        
        OpNode blockOpnode = {0};
        [self node:&blockOpnode atIndex:idx];
        if(blockOpnode.type != 1){
            return;
        }
        switch(blockOpnode.filterID & 1){
            case NO:
                allowSeen = YES;
                break;
            case YES:
                denySeen = YES;
                break;
        };
        if(allowSeen && denySeen){
            *stop = YES;
        }
    }];
    if(allowSeen && denySeen){
        return OperationVerdictConditional;
    }
    if(allowSeen && !denySeen){
        return OperationVerdictConditionalAllow;
    }
    if(denySeen && !allowSeen){
        return OperationVerdictConditionalDeny;
    }
    return OperationVerdictInvalid;
    
}
@end


