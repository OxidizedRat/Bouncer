//
//  SandboxBlob.h
//  Bouncer
//
//  Created by praveen on 2026-10-05.
//

#ifndef SandboxBlob_h
#define SandboxBlob_h
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
typedef struct __attribute__((packed)){
    uint16_t type;
    uint16_t numOpNodes;
    uint8_t numOperations;
    uint8_t numGlobalVariables;
    uint8_t sizeTable1;
    uint8_t sizeTable2;
    uint16_t sizeTable3;
    uint16_t numProfiles;
    uint16_t numRegex;
    uint16_t sizeTable4;
}SandboxBlobHeader;

typedef NS_ENUM(uint16_t, SandboxBlobType) {
    SandboxBlobTypeProfile    = 0x0000,
    SandboxBlobTypeCollection = 0x8000,
};

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t filterID;
    uint16_t filterArg;
    uint16_t matchNode;
    uint16_t unmatchNode;
}OpNode;

typedef struct __attribute__((packed)){
    uint16_t nameOffset;
    uint16_t unknownField0;
    uint16_t unknownField1;
    uint16_t unknownField2;
}SandboxProfileHeader;

typedef NS_ENUM(uint64_t, OperationVerdict){
    OperationVerdictAlwaysAllow,
    OperationVerdictAlwaysDeny,
    OperationVerdictConditional,
    OperationVerdictConditionalAllow,
    OperationVerdictConditionalDeny,
    OperationVerdictInvalid,
};

typedef NS_ENUM(NSInteger, SandboxPatternKind){
    SandboxPatternKindLiteral,
    SandboxPatternKindSubpath,
    SandboxPatternKindComplex,
};

@interface SandboxPattern : NSObject
@property (readonly) SandboxPatternKind kind;
// Literal and subpath: the full literal text. Complex: the first literal run, or empty if the pattern does not start with one.
@property (readonly, copy) NSString * string;
// Every string the pattern matches, in program order. "…" at the end means any further input is accepted;
// ${NAME} is a global variable; [..], [^c]*c and .*c are wildcards. nil if the program could not be decoded.
@property (readonly, copy, nullable) NSArray<NSString *> * alternatives;
@end

@interface SandboxProfile: NSObject
@property (readonly, copy) NSString * name;
@property (readonly, nonatomic, copy) NSData * opTable;

- (instancetype __nullable) initWithName:(NSString *)Name opTable: (NSData *) opTable;
-(uint16_t) nodeIndexForOperationAtIndex:(NSUInteger)index;
@end

@interface SandboxBlob : NSObject
@property (readonly, nonatomic, copy) NSData * data;
@property (readonly) SandboxBlobHeader header;
@property (readonly) SandboxBlobType type;
@property (readonly, copy) NSData *nodes;
@property (readonly) uint64_t baseStart;
@property (readonly, copy) NSArray<SandboxProfile *> * profiles;
@property (readonly, copy) NSArray<NSString *> * operationNames;
// Names from the global variable table (e.g. HOME, ANY_UUID), referenced by patterns.
@property (readonly, copy) NSArray<NSString *> * globalVariables;

- (instancetype __nullable) initWithData:(NSData *) data operationNames: (NSArray<NSString *> *) operationNames error: (NSError **)error;
- (NSIndexSet  * _Nullable ) reachableNodesForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *) profile;
-(OperationVerdict) verdictForOperationAtIndex:(NSUInteger)opIndex inProfile:(SandboxProfile *) profile;
-(NSCountedSet<NSNumber *> *) filterIDUsage;
-(nullable NSString *) stringAtBaseOffset: (uint64_t) offset;
-(nullable SandboxPattern *) patternAtBaseOffset: (uint64_t) offset;
-(nullable NSIndexSet *) valueSetAtBaseOffset: (uint64_t) offset;
-(nullable NSString *) regexStringAtIndex:(uint16_t)index;
-(BOOL) node:(OpNode *)outNode atIndex:(uint16_t)index;
// "(name argument)" for a non-terminal, the action for a terminal. limit caps how many set members or
// pattern alternatives are listed.
-(nullable NSString *) conditionDescriptionForNodeAtIndex:(uint16_t)index limit:(NSUInteger)limit;
-(nullable NSString *) conditionDescriptionForNodeAtIndex:(uint16_t)index;
-(nullable NSString *) descriptionForNodeAtIndex:(uint16_t)index;
@end
NS_ASSUME_NONNULL_END
#endif /* SandboxBlob_h */

