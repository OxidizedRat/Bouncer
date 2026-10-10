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
@end
@interface SandboxBlob()
@property (readwrite, nonatomic, copy) NSData * data;
@property (readwrite) SandboxBlobHeader header;
@property (readwrite) SandboxBlobType type;
@property (readwrite, copy) NSData * nodes;
@property (readwrite) uint64_t baseStart;
@property (readwrite) uint64_t tablesEnd;
@property (readwrite) NSArray<SandboxProfile *> *profiles;
@end

@implementation SandboxBlob

- (instancetype __nullable) initWithData:(NSData *)blob error:(NSError *__autoreleasing *)error{
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
        self.profiles = profiles;
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
    self.profiles = profiles;
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
@end


