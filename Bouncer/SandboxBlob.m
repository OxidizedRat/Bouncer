//
//  SandboxBlob.m
//  Bouncer
//
//  Created by praveen on 2026-10-05.
//

#import <Foundation/Foundation.h>
#import "SandboxBlob.h"
#include <os/overflow.h>
#include "FilterInfo.h"
#import "SandboxRegex.h"
static NSError * sandboxError(NSString *errorMessage){
    return [NSError errorWithDomain:@"sandboxErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:errorMessage}];
}

@interface SandboxPattern()
@property (readwrite) SandboxPatternKind kind;
@property (readwrite, copy) NSString * string;
@property (readwrite, copy, nullable) NSArray<NSString *> * alternatives;
@end
@implementation SandboxPattern
@end

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
@property (nonatomic, nullable) NSMutableDictionary<NSNumber *, id> * regexCache;
@end

@implementation SandboxBlob
@synthesize globalVariables = _globalVariables;

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

-(OperationVerdict) verdictForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *) profile{
    
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
-(NSCountedSet<NSNumber *> *) filterIDUsage{
    NSCountedSet<NSNumber *> * usage = [[NSCountedSet alloc] init];
    for(uint64_t i = 0; i < self.header.numOpNodes; i++){
        OpNode node = {0};
        if(![self node:&node atIndex:i] || node.type != 0){
            continue;
        }
        [usage addObject:@(node.filterID)];
    }
    return usage;
}
// Pattern programs: u16 body length, then a matching program. Each instruction is a head, then
// (for most heads) a failure action. On success matching continues with the next instruction.
//   heads:   0x40-0x7f  literal run of (b & 0x3f) + 1 chars     0x04 n     literal run of n + 65 chars
//            0x00       end of input                            0x10-0x1f  global variable (b - 0x10)
//            0x01 u16   global variable                         0x02 c     [^c]*c
//            0x03 c     .*c                                     0x0b k ... class of (k & 0x7f) + 1 byte ranges;
//                                                                          with k & 0x80 it repeats ([..]*) and has no failure action
//            0x0a       accept (any remaining input)            0x06/0x05  save/restore the match position (no failure action)
//   failure: 0x0f reject, 0x80|n jump forward n + 1 bytes, 0x08 u16 jump forward u16 + 1 bytes (after the u16)
// The meaning of 0x02, 0x03, 0x05 and 0x06 is inferred from how they are used, not confirmed.
typedef NS_ENUM(uint8_t, PatternOp){
    PatternOpAccept,
    PatternOpSave,
    PatternOpRestore,
    PatternOpLiteral,
    PatternOpEnd,
    PatternOpVariable,
    PatternOpUntil,
    PatternOpAnyUntil,
    PatternOpClass,
    PatternOpClassStar,
};

typedef struct {
    PatternOp op;
    NSUInteger next;
    NSUInteger failTarget;
    BOOL hasFailTarget;
    NSUInteger operandOffset;
    NSUInteger operandLength;
    NSUInteger value;
} PatternStep;

static const NSUInteger kMaxPatternSteps = 20000;
static const NSUInteger kMaxPatternAlternatives = 2000;

static BOOL decodePatternStep(const uint8_t * body, NSUInteger length, NSUInteger pc, PatternStep * step){
    if(pc >= length){
        return NO;
    }
    *step = (PatternStep){0};
    uint8_t c = body[pc];
    BOOL hasFailureAction = YES;
    if(c == 0x0a || c == 0x06 || c == 0x05){
        step->op = c == 0x0a ? PatternOpAccept : c == 0x06 ? PatternOpSave : PatternOpRestore;
        step->next = pc + 1;
        return YES;
    }
    if(c >= 0x40 && c <= 0x7f){
        step->op = PatternOpLiteral;
        step->operandOffset = pc + 1;
        step->operandLength = (c & 0x3f) + 1;
        pc += 1 + step->operandLength;
    }
    else if(c == 0x04){
        if(pc + 1 >= length){
            return NO;
        }
        step->op = PatternOpLiteral;
        step->operandOffset = pc + 2;
        step->operandLength = (NSUInteger)body[pc + 1] + 65;
        pc += 2 + step->operandLength;
    }
    else if(c == 0x00){
        step->op = PatternOpEnd;
        pc += 1;
    }
    else if(c >= 0x10 && c <= 0x1f){
        step->op = PatternOpVariable;
        step->value = c - 0x10;
        pc += 1;
    }
    else if(c == 0x01){
        if(pc + 3 > length){
            return NO;
        }
        step->op = PatternOpVariable;
        step->value = body[pc + 1] | (body[pc + 2] << 8);
        pc += 3;
    }
    else if(c == 0x02 || c == 0x03){
        if(pc + 2 > length){
            return NO;
        }
        step->op = c == 0x02 ? PatternOpUntil : PatternOpAnyUntil;
        step->value = body[pc + 1];
        pc += 2;
    }
    else if(c == 0x0b){
        if(pc + 2 > length){
            return NO;
        }
        BOOL star = (body[pc + 1] & 0x80) != 0;
        step->op = star ? PatternOpClassStar : PatternOpClass;
        step->operandOffset = pc + 2;
        step->operandLength = 2 * ((NSUInteger)(body[pc + 1] & 0x7f) + 1);
        pc += 2 + step->operandLength;
        hasFailureAction = !star;
    }
    else{
        return NO;
    }
    if(pc > length){
        return NO;
    }
    if(!hasFailureAction){
        step->next = pc;
        return YES;
    }
    if(pc >= length){
        return NO;
    }
    uint8_t action = body[pc++];
    if(action == 0x08){
        if(pc + 2 > length){
            return NO;
        }
        NSUInteger distance = (NSUInteger)(body[pc] | (body[pc + 1] << 8)) + 1;
        pc += 2;
        step->hasFailTarget = YES;
        step->failTarget = pc + distance;
    }
    else if(action & 0x80){
        step->hasFailTarget = YES;
        step->failTarget = pc + (action & 0x7f) + 1;
    }
    else if(action != 0x0f){
        return NO;
    }
    if(step->hasFailTarget && step->failTarget > length){
        return NO;
    }
    step->next = pc;
    return YES;
}

static void appendDisplayByte(NSMutableString * out, uint8_t c){
    if(c < 0x20 || c >= 0x7f){
        [out appendFormat:@"\\x%02x", c];
    }
    else{
        if(c == ']' || c == '\\' || c == '^' || c == '-'){
            [out appendString:@"\\"];
        }
        [out appendFormat:@"%c", c];
    }
}

// Class text from byte ranges; written as a negated class when that is shorter.
static NSString * patternClassText(const uint8_t * ranges, NSUInteger rangeCount){
    BOOL members[256] = {NO};
    NSUInteger memberCount = 0;
    for(NSUInteger r = 0; r < rangeCount; r++){
        for(NSUInteger c = ranges[2 * r]; c <= ranges[2 * r + 1]; c++){
            if(!members[c]){
                members[c] = YES;
                memberCount++;
            }
        }
    }
    BOOL negate = memberCount > 128;
    NSMutableString * out = [NSMutableString stringWithString:negate ? @"[^" : @"["];
    for(NSUInteger c = 0; c < 256; c++){
        if(members[c] == negate){
            continue;
        }
        NSUInteger last = c;
        while(last + 1 < 256 && members[last + 1] != negate){
            last++;
        }
        appendDisplayByte(out, (uint8_t)c);
        if(last > c){
            [out appendString:@"-"];
            appendDisplayByte(out, (uint8_t)last);
        }
        c = last;
    }
    [out appendString:@"]"];
    return out;
}

-(NSArray<NSString *> *) globalVariables{
    if(_globalVariables){
        return _globalVariables;
    }
    NSMutableArray<NSString *> * names = [NSMutableArray array];
    uint64_t tableOffset = sizeof(SandboxBlobHeader) + (uint64_t)self.header.numRegex * 2;
    for(uint16_t i = 0; i < self.header.numGlobalVariables; i++){
        uint16_t nameOffset = 0;
        NSString * name = nil;
        if([self rangeIsValid:tableOffset + i * 2 size:sizeof(nameOffset)]){
            [self.data getBytes:&nameOffset range:NSMakeRange(tableOffset + i * 2, sizeof(nameOffset))];
            name = [self stringAtBaseOffset:nameOffset];
        }
        [names addObject:name ?: [NSString stringWithFormat:@"var%u", i]];
    }
    _globalVariables = [names copy];
    return _globalVariables;
}

-(nullable NSArray<NSString *> *) alternativesForPatternBody:(const uint8_t *)body length:(NSUInteger)length{
    NSMutableArray<NSString *> * alternatives = [NSMutableArray array];
    NSMutableSet<NSString *> * seen = [NSMutableSet set];
    // Each pending path: @[pc, prefix, saved prefix or NSNull].
    NSMutableArray<NSArray *> * pending = [NSMutableArray arrayWithObject:@[@0, @"", [NSNull null]]];
    NSArray<NSString *> * variables = self.globalVariables;
    NSUInteger steps = 0;
    while(pending.count){
        NSArray * path = pending.lastObject;
        [pending removeLastObject];
        NSUInteger pc = [path[0] unsignedIntegerValue];
        NSMutableString * prefix = [path[1] mutableCopy];
        NSString * saved = path[2] == [NSNull null] ? nil : path[2];
        BOOL finished = NO;
        while(!finished){
            if(++steps > kMaxPatternSteps){
                return nil;
            }
            PatternStep step;
            if(!decodePatternStep(body, length, pc, &step)){
                return nil;
            }
            if(step.hasFailTarget){
                [pending addObject:@[@(step.failTarget), [prefix copy], saved ?: [NSNull null]]];
            }
            NSString * alternative = nil;
            switch(step.op){
                case PatternOpAccept:
                    alternative = [prefix stringByAppendingString:@"…"];
                    finished = YES;
                    break;
                case PatternOpEnd:
                    alternative = [prefix copy];
                    finished = YES;
                    break;
                case PatternOpSave:
                    saved = [prefix copy];
                    break;
                case PatternOpRestore:
                    [prefix setString:saved ?: @""];
                    break;
                case PatternOpLiteral:{
                    NSString * run = [[NSString alloc] initWithBytes:body + step.operandOffset length:step.operandLength encoding:NSUTF8StringEncoding] ?:
                                     [[NSString alloc] initWithBytes:body + step.operandOffset length:step.operandLength encoding:NSISOLatin1StringEncoding];
                    [prefix appendString:run];
                    break;
                }
                case PatternOpVariable:
                    [prefix appendFormat:@"${%@}", step.value < variables.count ? variables[step.value] : [NSString stringWithFormat:@"var%lu", (unsigned long)step.value]];
                    break;
                case PatternOpUntil:
                    [prefix appendString:@"[^"];
                    appendDisplayByte(prefix, (uint8_t)step.value);
                    [prefix appendString:@"]*"];
                    appendDisplayByte(prefix, (uint8_t)step.value);
                    break;
                case PatternOpAnyUntil:
                    [prefix appendString:@".*"];
                    appendDisplayByte(prefix, (uint8_t)step.value);
                    break;
                case PatternOpClass:
                case PatternOpClassStar:
                    [prefix appendString:patternClassText(body + step.operandOffset, step.operandLength / 2)];
                    if(step.op == PatternOpClassStar){
                        [prefix appendString:@"*"];
                    }
                    break;
            }
            if(alternative && ![seen containsObject:alternative]){
                [seen addObject:alternative];
                [alternatives addObject:alternative];
                if(alternatives.count > kMaxPatternAlternatives){
                    return nil;
                }
            }
            pc = step.next;
        }
    }
    return alternatives;
}

-(nullable SandboxPattern *) patternAtBaseOffset: (uint64_t) offset{
    static const uint8_t literalTail[] = {0x0f, 0x00, 0x0f, 0x0a};
    static const uint8_t subpathTail[] = {0x0f, 0x40, '/', 0x80, 0x0a, 0x00, 0x0f, 0x0a};
    uint64_t patternDataOffset = self.baseStart + offset * 8;
    uint16_t bodyLen;
    if(![self rangeIsValid:patternDataOffset size:sizeof(bodyLen)]){
        return nil;
    }
    [self.data getBytes:&bodyLen range:NSMakeRange(patternDataOffset, sizeof(bodyLen))];
    if(!bodyLen || ![self rangeIsValid:patternDataOffset + 2 size:bodyLen]){
        return nil;
    }
    const uint8_t * body = (const uint8_t *)self.data.bytes + patternDataOffset + 2;

    SandboxPattern * pattern = [[SandboxPattern alloc] init];
    pattern.kind = SandboxPatternKindComplex;
    pattern.string = @"";
    pattern.alternatives = [self alternativesForPatternBody:body length:bodyLen];
    if(body[0] < 0x40 || body[0] > 0x7f){
        return pattern;
    }
    uint64_t runLen = (body[0] & 0x3f) + 1;
    if(1 + runLen > bodyLen){
        return pattern;
    }
    NSString * run = [[NSString alloc] initWithBytes:body + 1 length:runLen encoding:NSUTF8StringEncoding];
    if(!run){
        return nil;
    }
    pattern.string = run;

    const uint8_t * tail = body + 1 + runLen;
    uint64_t tailLen = bodyLen - 1 - runLen;
    if(tailLen == sizeof(literalTail) && memcmp(tail, literalTail, tailLen) == 0){
        pattern.kind = SandboxPatternKindLiteral;
    }
    else if(tailLen == sizeof(subpathTail) && memcmp(tail, subpathTail, tailLen) == 0){
        pattern.kind = SandboxPatternKindSubpath;
    }
    return pattern;
}

-(nullable NSString *) regexStringAtIndex:(uint16_t)index{
    if(index >= self.header.numRegex){
        return nil;
    }
    if(!self.regexCache){
        self.regexCache = [NSMutableDictionary dictionary];
    }
    id cached = self.regexCache[@(index)];
    if(cached){
        return cached == [NSNull null] ? nil : cached;
    }
    NSString * text = nil;
    uint16_t regexOffset = 0;
    uint16_t regexLength = 0;
    uint64_t tableEntry = sizeof(SandboxBlobHeader) + (uint64_t)index * 2;
    if([self rangeIsValid:tableEntry size:sizeof(regexOffset)]){
        [self.data getBytes:&regexOffset range:NSMakeRange(tableEntry, sizeof(regexOffset))];
        uint64_t regexDataOffset = self.baseStart + (uint64_t)regexOffset * 8;
        if([self rangeIsValid:regexDataOffset size:sizeof(regexLength)]){
            [self.data getBytes:&regexLength range:NSMakeRange(regexDataOffset, sizeof(regexLength))];
            if([self rangeIsValid:regexDataOffset + 2 size:regexLength]){
                text = SandboxRegexString([self.data subdataWithRange:NSMakeRange(regexDataOffset + 2, regexLength)]);
            }
        }
    }
    self.regexCache[@(index)] = text ?: [NSNull null];
    return text;
}

// Value sets: u16 1, u16 byte count, then a bitmap where bit i of byte k is the value 8k + i.
-(nullable NSIndexSet *) valueSetAtBaseOffset: (uint64_t) offset{
    uint64_t setOffset = self.baseStart + offset * 8;
    uint16_t header[2];
    if(![self rangeIsValid:setOffset size:sizeof(header)]){
        return nil;
    }
    [self.data getBytes:header range:NSMakeRange(setOffset, sizeof(header))];
    if(header[0] != 1 || ![self rangeIsValid:setOffset + sizeof(header) size:header[1]]){
        return nil;
    }
    const uint8_t * bitmap = (const uint8_t *)self.data.bytes + setOffset + sizeof(header);
    NSMutableIndexSet * values = [NSMutableIndexSet indexSet];
    for(NSUInteger byte = 0; byte < header[1]; byte++){
        for(NSUInteger bit = 0; bit < 8; bit++){
            if(bitmap[byte] & (1 << bit)){
                [values addIndex:byte * 8 + bit];
            }
        }
    }
    return values;
}

static NSString * quoted(NSString * string){
    return [NSString stringWithFormat:@"\"%@\"", [string stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]];
}

static NSString * integerText(uint8_t baseID, NSUInteger value){
    const char * name = value <= UINT16_MAX ? FilterValueName(baseID, (uint16_t)value) : NULL;
    return name ? @(name) : [NSString stringWithFormat:@"%lu", (unsigned long)value];
}

static NSString * listText(NSArray<NSString *> * items, NSUInteger limit){
    if(items.count <= limit){
        return [items componentsJoinedByString:@", "];
    }
    NSString * shown = [[items subarrayWithRange:NSMakeRange(0, limit)] componentsJoinedByString:@", "];
    return [NSString stringWithFormat:@"%@, … (%lu in total)", shown, (unsigned long)items.count];
}

-(NSString *) descriptionForArgument:(uint16_t)arg filterID:(uint8_t)filterID kind:(FilterArgKind)kind form:(FilterArgForm)form limit:(NSUInteger)limit{
    uint8_t baseID = filterID & 0x7F;
    if(form == FilterArgFormRegex){
        NSString * regex = [self regexStringAtIndex:arg];
        return regex ? [NSString stringWithFormat:@"#%@", quoted(regex)] : [NSString stringWithFormat:@"#regex %u", arg];
    }
    if(form == FilterArgFormValueSet){
        NSIndexSet * values = [self valueSetAtBaseOffset:arg];
        if(!values){
            return [NSString stringWithFormat:@"<bad value set 0x%04x>", arg];
        }
        NSMutableArray<NSString *> * names = [NSMutableArray array];
        [values enumerateIndexesUsingBlock:^(NSUInteger value, BOOL *stop){
            [names addObject:integerText(baseID, value)];
        }];
        return [NSString stringWithFormat:@"in {%@}", listText(names, limit)];
    }
    switch(kind){
        case FilterArgKindString:{
            NSString * string = [self stringAtBaseOffset:arg];
            return string ? quoted(string) : [NSString stringWithFormat:@"<bad string 0x%04x>", arg];
        }
        case FilterArgKindPattern:{
            SandboxPattern * pattern = [self patternAtBaseOffset:arg];
            if(!pattern){
                return [NSString stringWithFormat:@"<bad pattern 0x%04x>", arg];
            }
            switch(pattern.kind){
                case SandboxPatternKindLiteral:
                    return quoted(pattern.string);
                case SandboxPatternKindSubpath:
                    return [NSString stringWithFormat:@"%@ + subtree", quoted(pattern.string)];
                case SandboxPatternKindComplex:{
                    if(pattern.alternatives.count == 1){
                        return quoted(pattern.alternatives.firstObject);
                    }
                    if(pattern.alternatives.count){
                        NSMutableArray<NSString *> * items = [NSMutableArray array];
                        for(NSString * alternative in pattern.alternatives){
                            [items addObject:quoted(alternative)];
                        }
                        return [NSString stringWithFormat:@"any of %@", listText(items, limit)];
                    }
                    if(pattern.string.length){
                        return [NSString stringWithFormat:@"<complex pattern 0x%04x, starts %@>", arg, quoted(pattern.string)];
                    }
                    return [NSString stringWithFormat:@"<complex pattern 0x%04x>", arg];
                }
            }
        }
        case FilterArgKindInteger:
            return integerText(baseID, arg);
        case FilterArgKindUnknown:
            break;
    }
    return [NSString stringWithFormat:@"0x%04x", arg];
}

// Terminal: "allow" / "deny" (bit 0 of the flags byte), the other flag bits named after the macOS
// flag modifiers, and for extended terminals (u16 at byte 2 == 0x8000) a string modifier.
-(NSString *) actionDescriptionForNode:(OpNode)node{
    NSMutableString * description = [NSMutableString stringWithString:(node.filterID & 1) ? @"deny" : @"allow"];
    const char * names[7];
    NSUInteger count = TerminalFlagNames(node.filterID, names);
    for(NSUInteger i = 0; i < count; i++){
        [description appendFormat:@" (with %s)", names[i]];
    }
    if(node.filterArg == 0x8000){
        const char * modifier = ModifierName(node.matchNode);
        NSString * string = [self stringAtBaseOffset:node.unmatchNode];
        [description appendFormat:@" (with %@ %@)",
            modifier ? @(modifier) : [NSString stringWithFormat:@"modifier-%u", node.matchNode],
            string ? quoted(string) : [NSString stringWithFormat:@"0x%04x", node.unmatchNode]];
    }
    if(node.filterID & ~1){
        [description appendFormat:@" [flags 0x%02x]", node.filterID];
    }
    return description;
}

-(nullable NSString *) conditionDescriptionForNodeAtIndex:(uint16_t)index limit:(NSUInteger)limit{
    OpNode node = {0};
    if(![self node:&node atIndex:index]){
        return nil;
    }
    if(node.type == 1){
        return [self actionDescriptionForNode:node];
    }
    FilterArgForm form = FilterArgFormPlain;
    FilterInfo info = FilterInfoForID(node.filterID, &form);
    NSString * name = info.name ? @(info.name) : [NSString stringWithFormat:@"filter-0x%02x", node.filterID];
    NSString * argument = [self descriptionForArgument:node.filterArg filterID:node.filterID kind:info.kind form:form limit:limit];
    return [NSString stringWithFormat:@"(%@ %@)", name, argument];
}

-(nullable NSString *) conditionDescriptionForNodeAtIndex:(uint16_t)index{
    return [self conditionDescriptionForNodeAtIndex:index limit:8];
}

// Non-terminal: "(name arg) -> match 0x.... / unmatch 0x....". Terminal: the action.
-(nullable NSString *) descriptionForNodeAtIndex:(uint16_t)index{
    OpNode node = {0};
    NSString * condition = [self conditionDescriptionForNodeAtIndex:index];
    if(!condition || ![self node:&node atIndex:index]){
        return nil;
    }
    if(node.type == 1){
        return condition;
    }
    return [NSString stringWithFormat:@"%@ -> match 0x%04x / unmatch 0x%04x", condition, node.matchNode, node.unmatchNode];
}
@end


