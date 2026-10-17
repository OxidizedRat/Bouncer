//
//  Kernelcache.m
//  Bouncer
//
//  Created by praveen on 2026-09-27.
//

#import <Foundation/Foundation.h>
#import "Kernelcache.h"
#import <mach-o/loader.h>
#import "SandboxBlob.h"
#include <os/overflow.h>
typedef enum {InsOther, InsADRP, InsADD, InsMOVZ, InsMOVK, InsBL, InsSTP} InsKind;

typedef struct {
    InsKind kind;
    uint8_t rd, rn, rt2;
    bool is64;
    uint64_t value;
    uint32_t shift;
} DecodedIns;
struct regState{
    uint64_t value[32];
    BOOL known[32];
};

static NSError * kernelCacheError(NSString *errorMessage){
    return [NSError errorWithDomain:@"KernelcacheErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey:errorMessage}];
}

static BOOL readBytesChecked(NSData * data, uint64_t offset, uint64_t length, void * buffer, NSError **error){
    if( length > data.length || offset > data.length - length){
        if (error){*error = kernelCacheError(@"OOB when copying bytes");}
        return NO;
    }
    [data getBytes:buffer range:NSMakeRange(offset, length)];
    return YES;
}

static inline int64_t signExtend(uint64_t value, unsigned bits){
    uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((value ^ m) - m);
}


static DecodedIns decodeInstruction(uint32_t ins, uint64_t pc){
    
    DecodedIns decodedIns = {0};
    uint32_t rd = ins & 0x1F;
    uint32_t rn = (ins >> 5) & 0x1F;
    bool     sf = ins >> 31;
    
    decodedIns.rd = rd;
    decodedIns.rn = rn;
    decodedIns.is64 = sf;
    //ADRP
    if((ins & 0x9F000000) == 0x90000000){
        uint64_t imm = (((ins >> 5) & 0x7FFFF) << 2) | ((ins >> 29) & 3);
        decodedIns.value = (pc & ~0xFFFULL) + ((uint64_t)signExtend(imm, 21) << 12);
        decodedIns.kind = InsADRP;
        return decodedIns;
    }
    //ADD
    if((ins & 0xFF800000) == 0x91000000){
        uint64_t imm = (ins >> 10) & 0xFFF;
        if (ins & (1u << 22)) imm <<= 12;
        decodedIns.value = imm;
        decodedIns.kind = InsADD;
        return decodedIns;
    }
    //MOVZ
    if((ins & 0x7F800000) == 0x52800000){
        uint32_t shift = ((ins >> 21) & 3) * 16;
        uint64_t imm   = (uint64_t)((ins >> 5) & 0xFFFF) << shift;
        decodedIns.value =imm;
        decodedIns.shift = shift;
        decodedIns.kind = InsMOVZ;
        return decodedIns;
    }
    //MOVK
    if((ins & 0x7F800000) == 0x72800000){
        uint32_t shift = ((ins >> 21) & 3) * 16;
        uint64_t imm   = (uint64_t)((ins >> 5) & 0xFFFF) << shift;
        decodedIns.shift = shift;
        decodedIns.value = imm;
        decodedIns.kind = InsMOVK;
        return decodedIns;
    }
    //BL
    if((ins & 0xFC000000) == 0x94000000){
        uint32_t imm26 = ins  & 0x3FFFFFF;
        uint64_t target = (uint64_t)signExtend(imm26, 26) << 2;
        decodedIns.value = target + pc;
        decodedIns.kind = InsBL;
        return decodedIns;
    }
    //STP
    if((ins & 0xFFC00000) == 0xA9000000){
        decodedIns.rt2 = (ins >> 10) & 0x1F;
        decodedIns.kind = InsSTP;
        return decodedIns;
    }
    decodedIns.kind = InsOther;
    return decodedIns;
}
static void applyState(DecodedIns *ins, struct regState *state) {
    switch (ins->kind){
        case InsADRP:
            if(ins->rd == 31){
                return;
            }
            state->value[ins->rd] =  ins->value;
            state->known[ins->rd] = YES;
            return;
        case InsADD:
            if(ins->rd == 31){
                return;
            }
            if(state->known[ins->rn]){
                uint64_t v = state->value[ins->rn] + ins->value;
                state->value[ins->rd] = ins->is64 ? v : (uint32_t)v;
                state->known[ins->rd] = YES;
            }else{
                state->known[ins->rd] = NO;
            }
            return;
        case InsMOVZ:
            if(ins->rd == 31){
                return;
            }
            state->value[ins->rd] = ins->value;
            state->known[ins->rd] = YES;
            return;
        case InsMOVK:
            if(ins->rd == 31){
                return;
            }
            if (state->known[ins->rd]) {
                uint64_t v = (state->value[ins->rd] & ~(0xFFFFULL << ins->shift)) | ins->value;
                state->value[ins->rd] = ins->is64 ? v : (uint32_t)v;
            } else {
                state->known[ins->rd] = false;
            }
            return;
        case InsBL:
            for (int r = 0; r <= 18; r++){
                state->known[r] = false;
            }
            return;
        case InsSTP:
            return;
        case InsOther:
            return;
    }
    return;
}


@interface Kernelcache()
@property (readwrite) NSData *data;
@property (readwrite) struct mach_header_64 header;
@property (readwrite, nonatomic, copy) NSData * _Nullable blobProtobox;
@property (readwrite, nonatomic, copy) NSData * _Nullable blobProfile;
@property (readwrite, nonatomic, copy) NSData * _Nullable blobBuiltin;
@property (readwrite) uint64_t sandboxKextOffset;
@property (readwrite) uint64_t builtinVMAddress;
@property (readwrite) uint64_t autoboxVMAddress;
@property (readwrite) struct section_64 textCString;
@property (readwrite) struct section_64 textConst;
@property (readwrite) struct section_64 textExecText;
@property (readwrite) struct section_64 dataConstConst;
@property (readwrite) SandboxBlob * builtin;
@property (readwrite) SandboxBlob * protobox;
@property (readwrite) SandboxBlob * profile;
@property (readwrite, copy) NSArray<NSString *> * operationNames;
@end

@implementation Kernelcache

- (instancetype) initWithPath:(NSString *)path error:(NSError **)error{
    self = [super init];
    if (!self){
        return nil;
    }
    NSData * data = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:path] options:NSDataReadingMappedAlways error:error];
    if (!data){
        return nil;
    }
    struct mach_header_64 header;
    if (data.length < sizeof(header)){
        
        if(error){*error = kernelCacheError(@"File is too small to be valid mach-o");}
        return nil;
    }
    [data getBytes:&header range:NSMakeRange(0, sizeof(header))];
    
    if (header.magic != MH_MAGIC_64){
        if(error){*error = kernelCacheError(@"Invalid or unsupported magic");}
        return nil;
    }
    if (header.cputype != CPU_TYPE_ARM64){
        if(error){*error = kernelCacheError(@"Invalid cpu type");}
        return nil;
    }
    if (header.filetype != MH_FILESET){
        if(error){*error = kernelCacheError(@"Invalid file type");}
        return nil;
    }
    
    self.header = header;
    self.data = data;
    uint64_t sandboxKextInfo = [self extractSandboxKextWithError:error];
    if(sandboxKextInfo == 0){
        return nil;
    }
    self.sandboxKextOffset = sandboxKextInfo;
    BOOL result = [self extractBuiltinAndAutoboxVMA:error];
    if(!result){
        return nil;
    }
    if(![self findBlobsWithError:error]){
        return nil;
    }
    if(![self operationNamesWithError:error]){
        return nil;
    }
    
    if(![self createSandboxBlobs:error]){
        return nil;
    }
    return self;
}
//returns 0 on error as sandbox kext cannot start at offset 0
- (uint64_t) extractSandboxKextWithError:(NSError **)error{
    //locate fileset load command
    uint32_t numCmds = self.header.ncmds;
    uint64_t currentOffset = 0 + sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < numCmds; i++ ){
        struct load_command lc;
        if(!readBytesChecked(self.data, currentOffset, sizeof(lc), &lc, error)){
            return 0;
        }
        if (lc.cmdsize == 0 || lc.cmdsize < sizeof(struct load_command)){
            if(error){*error = kernelCacheError(@"invalid load command size");}
            return 0;
        }
        if(lc.cmd ==LC_FILESET_ENTRY){
            struct fileset_entry_command fileEntryCommand;
            if(!readBytesChecked(self.data, currentOffset, sizeof(fileEntryCommand), &fileEntryCommand, error)){
                return 0;
            }
            uint32_t idOffset = fileEntryCommand.entry_id.offset;
            if(idOffset > lc.cmdsize){
                if(error){*error = kernelCacheError(@"OOB when reading lc id");}
                return 0;
            }
            
            const uint8_t *bytes = [self.data bytes];
            if(currentOffset + lc.cmdsize > self.data.length){
                if(error){*error = kernelCacheError(@"OOB when reading kext name");}
                return 0;
            }
            const char *entryID = (const char*)(bytes + currentOffset + idOffset);
            size_t maxLen = lc.cmdsize -idOffset;
            size_t len = strnlen(entryID, maxLen);
             
            NSString *name = (len < maxLen) ? [[NSString alloc] initWithBytes:entryID length:len encoding:NSUTF8StringEncoding] : nil;
            
            if ([name isEqualToString:@"com.apple.security.sandbox"]){
                
                uint64_t kextOffset = fileEntryCommand.fileoff;
                return kextOffset;
            }
        }
        currentOffset += lc.cmdsize;
    }
    if(error){*error = kernelCacheError(@"Could not locate sandbox kext in mach-o");}
    return 0;
    
}

- (BOOL) extractBuiltinAndAutoboxVMA:(NSError **)error{
    
    uint64_t fileOffset = self.sandboxKextOffset;

    struct mach_header_64 header;
    if(!readBytesChecked(self.data, fileOffset, sizeof(header), &header, error)){return 0;}
    
    if ( header.magic != MH_MAGIC_64){
        if(error){*error = kernelCacheError(@"Invalid kext magic");}
        return 0;
    }

    struct section_64 textConst = {0};
    struct section_64 textCstring = {0};
    struct section_64 textExecText = {0};
    struct section_64 dataConstConst = {0};
    //iterate load commands for __TEXT__const __TEXT_cstring and __TEXT_EXEC __text sections
    uint32_t numCommands = header.ncmds;
    uint64_t currentOffset = fileOffset + sizeof(header);
    for(uint32_t i =0; i < numCommands; i++){
        struct load_command lc;
        if(!readBytesChecked(self.data, currentOffset, sizeof(lc), &lc, error)){
            return 0;
        }
        if(lc.cmdsize == 0 || lc.cmdsize < sizeof(struct load_command)){
            
            if(error){*error =kernelCacheError(@"Invalid load command size");}
            return 0;
        }
        if (lc.cmd != LC_SEGMENT_64){
            currentOffset += lc.cmdsize;
            continue;
        }

        struct segment_command_64 segment64;
        
        if(!readBytesChecked(self.data, currentOffset, sizeof(segment64), &segment64, error)){ return 0;}
        
        if(sizeof(segment64) + segment64.nsects * sizeof(struct section_64) > lc.cmdsize){
            if(error){*error =kernelCacheError(@"Invalid number of sections in lc");}
            return 0;
        }
        uint64_t sectionOffset = currentOffset + sizeof(segment64);
        struct section_64 section;
        for(uint64_t s = 0; s < segment64.nsects; s++, sectionOffset+=sizeof(section)){
            if(!readBytesChecked(self.data, sectionOffset, sizeof(section), &section, error)){return 0;}
            
            if(strncmp(section.segname, "__TEXT",16) == 0 && strncmp(section.sectname, "__const", 16) == 0 ){
                textConst = section;
                continue;
            }
            
            if(strncmp(section.segname, "__TEXT",16)== 0 && strncmp(section.sectname, "__cstring", 16)== 0){
                textCstring = section;
                continue;
            }
            
            if(strncmp(section.segname, "__TEXT_EXEC",16)== 0 && strncmp(section.sectname, "__text", 16)== 0 ){
                textExecText = section;
                continue;
            }
            
            if(strncmp(section.segname, "__DATA_CONST",16)== 0 && strncmp(section.sectname, "__const", 16)== 0){
                 dataConstConst = section;
                continue;
            }
        }
        currentOffset += lc.cmdsize;
    }
    if(textConst.size == 0){
        if(error){*error =kernelCacheError(@"__TEXT__const section not found");}
        return 0;
    }
    if(textCstring.size == 0){
        if(error){*error =kernelCacheError(@"__TEXT__cstring section not found");}
        return 0;
    }
    if(textExecText.size == 0){
        if(error){*error = kernelCacheError(@"__TEXT_EXEC__text section not found");}
        return 0;
    }
    if(dataConstConst.size == 0){
        if(error){*error = kernelCacheError(@"__DATA_CONST__const section not found");}
        return 0;
    }
    
    //iterate cstring and look for the builtin collections and autobox
    const char * builtinCstring = "builtin collection";
    const char * autoboxCstring = "autobox collection";
    uint64_t builtinVMAddress = 0;
    uint64_t autoboxVMAddress = 0;
    
    if((textCstring.size > self.data.length || textCstring.offset > self.data.length - textCstring.size) ){
        if(error){*error = kernelCacheError(@"OOB when reading Cstring section");}
        return 0;
    }
    const char *sectionBase = (const char*)self.data.bytes + textCstring.offset;
    const char *bytesStart = (const char*)self.data.bytes + textCstring.offset;
    const char *bytesEnd = bytesStart + textCstring.size;
    BOOL builtinFound = NO;
    BOOL autoboxFound = NO;
    while(bytesStart < bytesEnd){
        const char *candidateEnd = memchr(bytesStart, 0, bytesEnd - bytesStart);
        if(!candidateEnd){break;}
        uint64_t candidateLen = candidateEnd - bytesStart;
        
        if(builtinFound && autoboxFound){break;}
        if(candidateLen != 18){
            bytesStart = candidateEnd +1;
            continue;
        }
        if(!memcmp(bytesStart, builtinCstring, 19)) {
            builtinFound = YES;
            builtinVMAddress = textCstring.addr + (bytesStart - sectionBase);
            bytesStart = candidateEnd +1;
            continue;
        }else if (!memcmp(bytesStart, autoboxCstring, 19)){
            autoboxFound = YES;
            autoboxVMAddress = textCstring.addr + (bytesStart - sectionBase);
            bytesStart = candidateEnd +1;
            continue;
        }
        bytesStart = candidateEnd +1;
    }
    if(!builtinFound){
        if(error){*error = kernelCacheError(@"builtin string not found");}
        return 0;
    }
    if(!autoboxFound){
        if(error){*error = kernelCacheError(@"autobox string not found");}
        return 0;
    }
    self.autoboxVMAddress = autoboxVMAddress;
    self.builtinVMAddress = builtinVMAddress;
    self.textConst = textConst;
    self.textCString = textCstring;
    self.textExecText = textExecText;
    self.dataConstConst = dataConstConst;
    return 1;
}

- (BOOL) findBlobsWithError:(NSError **)error{
    
    if(self.textExecText.size > self.data.length || self.textExecText.offset > self.data.length - self.textExecText.size){
        if(error){*error = kernelCacheError(@"OOB when reading __TEXT_EXEC,__text section");}
        return NO;
    }
    
    struct regState state = {0};
    
    const uint8_t *textBase = (const uint8_t *)[self.data bytes] + self.textExecText.offset;
    BOOL builtinFound = NO;
    BOOL autoboxFound = NO;
    BOOL profileFound = NO;
    for(uint64_t i = 0; i + 4 <= self.textExecText.size; i += 4){
        uint64_t pc = self.textExecText.addr + i;
        uint32_t ins;
        memcpy(&ins, textBase + i, sizeof(ins));
        DecodedIns decodedIns = decodeInstruction(ins, pc);
        if(decodedIns.kind == InsBL){
            //if x1 is known and equal to a lable VMAddr and x2 is known and inside __const, x2 is that blobs start and x3 lower 32 bits is the size
            if(state.known[1] == YES && state.value[1] == self.builtinVMAddress && state.known[3] == YES && state.known[2] && !builtinFound){
                if(state.value[2] < self.textConst.addr + self.textConst.size && state.value[2] >= self.textConst.addr){
                    uint64_t builtinBlobOffset = (state.value[2] - self.textConst.addr) + self.textConst.offset;
                    uint32_t builtinSize = (uint32_t)state.value[3];
                    builtinFound = YES;
                    self.blobBuiltin = [self.data subdataWithRange:NSMakeRange(builtinBlobOffset, builtinSize)];
                }
            }
            if(state.known[1] == YES && state.value[1] == self.autoboxVMAddress && state.known[3] == YES && state.known[2] && !autoboxFound){
                if(state.value[2] < self.textConst.addr + self.textConst.size && state.value[2] >= self.textConst.addr){
                    uint64_t autoboxBlobOffset = (state.value[2] - self.textConst.addr) + self.textConst.offset;
                    uint32_t autoboxSize = (uint32_t)state.value[3];
                    autoboxFound =YES;
                    self.blobProtobox = [self.data subdataWithRange:NSMakeRange(autoboxBlobOffset, autoboxSize)];
                }
            }
        }
        if(decodedIns.kind == InsSTP && builtinFound && !profileFound){
            if(state.known[decodedIns.rd] == YES && state.known[decodedIns.rt2] ){
                if(state.value[decodedIns.rd] < self.textConst.addr + self.textConst.size && state.value[decodedIns.rd] >= self.textConst.addr){
                    uint64_t profileOffset = (state.value[decodedIns.rd] - self.textConst.addr) + self.textConst.offset;
                    uint32_t profileSize = (uint32_t)state.value[decodedIns.rt2];
                    profileFound = YES;
                    self.blobProfile = [self.data subdataWithRange:NSMakeRange(profileOffset, profileSize)];
                }
            }
        }
        if(builtinFound && profileFound && autoboxFound){
            break;
        }
        applyState(&decodedIns, &state);
    }
    if(!builtinFound){
        if(error){*error = kernelCacheError(@"Builtin blob not found");}
        return NO;
    }
    if(!autoboxFound){
        if(error){*error = kernelCacheError(@"autobox collection blob not found");}
        return NO;
    }
    if(!profileFound){
        if(error){*error = kernelCacheError(@"platform profile collection blob not found");}
        return NO;
    }
    return YES;
}
-(BOOL) createSandboxBlobs:(NSError **) error{
    SandboxBlob * builtinBlob = [[SandboxBlob alloc] initWithData:self.blobBuiltin operationNames: self.operationNames error:error];
    if(!builtinBlob){return NO;}
    SandboxBlob * profileBlob = [[SandboxBlob alloc] initWithData:self.blobProfile operationNames: self.operationNames  error:error];
    if(!profileBlob){return NO;}
    SandboxBlob * protoboxBlob = [[SandboxBlob alloc] initWithData:self.blobProtobox operationNames: self.operationNames  error:error];
    if(!protoboxBlob){return NO;}
    
    self.builtin = builtinBlob;
    self.protobox = protoboxBlob;
    self.profile = profileBlob;
    return YES;
}
-(BOOL) operationNamesWithError: (NSError**) error{
    uint64_t opStringOffset = [self defaultOpStringDataWithError:error];
    if(opStringOffset == 0){
        return NO;
    }
    //iterate through __DATA_CONST,__const looking for the pointer to the string offset
    uint64_t size = self.dataConstConst.size;
    uint64_t base = self.dataConstConst.offset;
    uint64_t total;
    if(os_add_overflow(size, base, &total)){
        if(error){*error =kernelCacheError(@"overflow when reading __DATA_CONST,__const");}
        return NO;
    }
    if(total > self.data.length){
        if(error){*error =kernelCacheError(@"OOB when reading __DATA_CONST,__const");}
        return NO;
    }
    uint64_t arrayOffset = 0;
    BOOL arrayFound = NO;
    const uint8_t *bytes = (const uint8_t *)[self.data bytes];
    for(uint64_t i = 0; i + 8 <= size ; i +=8){
        uint64_t currentPtr;
        memcpy(&currentPtr, bytes + base + i, sizeof(currentPtr));
        if((currentPtr & 0x3FFFFFFF) == opStringOffset){
            arrayOffset = base + i;
            arrayFound = YES;
            break;
        }
    }
    if(!arrayFound){
        if(error){*error = kernelCacheError(@"operation string array not found");}
        return NO;
    }
    NSMutableArray<NSString *> * operationStrings = [[NSMutableArray alloc]init];
    uint64_t maxOffset;
    if(os_add_overflow(self.textCString.offset, self.textCString.size, &maxOffset)){
        if(error){*error = kernelCacheError(@"overflow when reading __TEXT,__cstring");}
        return NO;
    }
    for(uint64_t i = 0; arrayOffset + i + 8  <= base + size ; i +=8){
        uint64_t currentPtr;
        memcpy(&currentPtr, bytes + arrayOffset + i, sizeof(currentPtr));
        uint64_t cstringOffset = currentPtr & 0x3FFFFFFF;
        if(cstringOffset < self.textCString.offset || cstringOffset >= maxOffset){
            break;
        }
        const uint8_t *stringEnd = memchr(bytes + cstringOffset, 0x00, maxOffset - cstringOffset);
        if(!stringEnd){
            if(error){*error = kernelCacheError(@"String null terminator not found");}
            return NO;
        }
        uint64_t stringLen = stringEnd - (bytes + cstringOffset);
        
        NSString * operationString = [[NSString alloc] initWithBytes:bytes+cstringOffset length:stringLen encoding:NSUTF8StringEncoding];
        if(!operationString){
            if(error){*error = kernelCacheError(@"failed to get operation NSString");}
            return NO;
        }
        [operationStrings addObject:operationString];
    }
    if(![operationStrings[0] isEqualToString:@"default"]){
        if(error){*error = kernelCacheError(@"retrieved operation string appear to be corrupted");}
        return NO;
    }
    self.operationNames = operationStrings;
    return YES;
}
-(uint64_t) defaultOpStringDataWithError: (NSError **)error{
    
    uint64_t startOffset = self.textCString.offset;
    uint64_t size = self.textCString.size;
    NSData * stringData = [NSData dataWithBytes:"\0default" length:9];
    NSRange opStringRange = [self.data rangeOfData:stringData options:0 range:NSMakeRange(startOffset, size)];
    
    if(opStringRange.location == NSNotFound){
        if(error){*error = kernelCacheError(@"Failed to find start of operation name strings list");}
        return 0;
    }
    
    return opStringRange.location + 1;
}
@end
