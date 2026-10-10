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

@interface SandboxProfile: NSObject
@property (readonly, copy) NSString * name;
@property (readonly, nonatomic, copy) NSData * opTable;

- (instancetype __nullable) initWithName:(NSString *)Name opTable: (NSData *) opTable;
@end

@interface SandboxBlob : NSObject
@property (readonly, nonatomic, copy) NSData * data;
@property (readonly) SandboxBlobHeader header;
@property (readonly) SandboxBlobType type;
@property (readonly, copy) NSData *nodes;
@property (readonly) uint64_t baseStart;
@property (readonly) NSArray<SandboxProfile *> * profiles;

- (instancetype __nullable) initWithData:(NSData *) data error: (NSError **)error;
@end
NS_ASSUME_NONNULL_END
#endif /* SandboxBlob_h */

