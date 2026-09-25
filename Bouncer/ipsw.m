//
//  ipsw.m
//  Bouncer
//
//  Created by praveen on 2026-09-24.
//

#import <Foundation/Foundation.h>
#import "ipsw.h"
#import <zlib.h>

struct __attribute__((packed)) EOCD {
    uint32_t magic;
    uint16_t diskNo;
    uint16_t cdDisk;
    uint16_t noCDRecords;
    uint16_t totalCDRecords;
    uint32_t cdsizeBytes;
    uint32_t cdOffset;
    uint16_t commentLenght;
};
struct __attribute__((packed)) EOCD64Locator{
    uint32_t magic;
    uint32_t disk;
    uint64_t eocd64Offset;
    uint32_t totalDisks;
};
struct __attribute__((packed)) EOCD64{
    uint32_t magic;
    uint64_t size;
    uint16_t version;
    uint16_t minimumVersion;
    uint32_t diskNo;
    uint32_t cdDisk;
    uint64_t numCDRecordsOnDisk;
    uint64_t totalNumCDRecords;
    uint64_t cdSize;
    uint64_t cdOffset;
};
struct __attribute__((packed)) CentralDirectoryEntry{
    uint32_t magic;
    uint16_t version;
    uint16_t minVersion;
    uint16_t gpFlag;
    uint16_t compressionMethod;
    uint16_t lastModifiedTime;
    uint16_t lastModifiedDate;
    uint32_t crc32Uncompressed;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t fileNameLength;
    uint16_t extraFieldLength;
    uint16_t commentLength;
    uint16_t diskNo;
    uint16_t internalFileAttr;
    uint32_t externalFileAttr;
    uint32_t localOffset;
};

struct __attribute__((packed)) LocalHeaderRecord{
    uint32_t magic;
    uint16_t version;
    uint16_t gpFlag;
    uint16_t compressionMethod;
    uint16_t lastModifiedTime;
    uint16_t lastModifiedDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t filenameLength;
    uint16_t extraFieldlength;
};
@implementation Ipsw

+(instancetype) initWithPath:(NSString *)path
                       error:(NSError **) error
{
    Ipsw *ipsw = [[Ipsw alloc]init];
    NSData * contents = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedAlways error:error];
    if(contents == nil){
        return nil;
    }
    const uint8_t *bytes = contents.bytes;
    uint64_t archiveSize = contents.length;
    
    uint64_t maxEOCDSize = 65535 +22;
    
    if(archiveSize < maxEOCDSize){
        *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Not Implemented"}];
        return nil;
    }
    uint64_t EOCDStart = 0;
    BOOL eocdFound = NO;
    for( uint64_t i = maxEOCDSize; i >= 22 ; i--){
        uint32_t magic = 0x06054b50;
        uint32_t outputBuf;
        memcpy(&outputBuf, &bytes[archiveSize - i], sizeof(outputBuf));
        
        if(outputBuf == magic ){
            EOCDStart = archiveSize - i;
            eocdFound =YES;
            break;
        }
    }
    if(!eocdFound){
        *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"EOCD was not found"}];
        return nil;
    }
    struct EOCD eocd;
    memcpy(&eocd,bytes + EOCDStart ,sizeof(eocd));
    if(eocd.cdOffset != 0xFFFFFFFF ){
        *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Non ZIP64 Not Implemented"}];
        return nil;
    }
    //EOCD64 Locator always 20 bytes before EOCD
    struct EOCD64Locator eocd64Locator;
    memcpy(&eocd64Locator, bytes + (EOCDStart - 20), sizeof(eocd64Locator));
    if(eocd64Locator.magic != 0x7064b50){
        *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"EOCD64 Locator bad magic"}];
        return nil;
    }
    
    //get EOCD64
    struct EOCD64 eocd64;
    memcpy(&eocd64, bytes + (eocd64Locator.eocd64Offset), sizeof(eocd64));
    if(eocd64.magic != 0x6064b50){
        *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"EOCD64 bad magic"}];
        return nil;
    }
    
    //iterate over central directory entries until kernelcache.release* is found
    
    struct CentralDirectoryEntry cdEntry;
    uint64_t cdAdditionalSize = 0;
    uint64_t numCDEntries = eocd64.totalNumCDRecords;
    uint64_t currentOffset = eocd64.cdOffset;
    uint64_t kernelcacheCDOffset = 0;
    BOOL kernelcacheFound = NO;
    for(uint64_t i = 0; i < numCDEntries; i++){
        if(currentOffset + sizeof(cdEntry) > archiveSize){
            *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"OOB read when parsing Central Directory"}];
            return nil;
        }
        
        memcpy(&cdEntry, bytes + currentOffset, sizeof(cdEntry));
        if(cdEntry.magic != 0x02014b50){
            *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Central Directory Entry bad magic"}];
            return nil;
        }
        uint64_t filenameStart = currentOffset + 46;
        if(filenameStart + cdEntry.fileNameLength > archiveSize){
            *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"OOB read when parsing file name"}];
            return nil;
        }
        NSString* filename = [[NSString alloc] initWithBytes:bytes + filenameStart length:cdEntry.fileNameLength encoding:NSUTF8StringEncoding];
        
        
        if(![filename hasPrefix:@"kernelcache.release"]){
            cdAdditionalSize = cdEntry.fileNameLength + cdEntry.commentLength + cdEntry.extraFieldLength;
            currentOffset = currentOffset + sizeof(cdEntry) + cdAdditionalSize;
            continue;
        }
        kernelcacheFound = YES;
        kernelcacheCDOffset = currentOffset;
        break;
        
    }
    if(!kernelcacheFound){
        *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Kernelcache was not found in ipsw"}];
        return ipsw;
    }
    //if kernel cache is found check which CD header fields have overflowed and retrieve the  values from extrafields
    uint64_t extraStart = cdEntry.fileNameLength + kernelcacheCDOffset + 46;
    uint64_t extraEnd = extraStart + cdEntry.extraFieldLength;
    uint64_t localOffset = cdEntry.localOffset;
    uint64_t uncompressedSize = cdEntry.uncompressedSize;
    uint64_t compressedSize = cdEntry.compressedSize;
    
    for (uint64_t p = extraStart; p + 4 <= extraEnd; ) {
        uint16_t ident, size;
        memcpy(&ident, bytes + p, 2);
        memcpy(&size,  bytes + p + 2, 2);
        if (ident == 0x0001) {
            uint64_t q = p + 4, qEnd = q + size;
            if (uncompressedSize  == 0xFFFFFFFFu) { if (q + 8 > qEnd) break; memcpy(&uncompressedSize,  bytes + q, 8); q += 8; }
            if (compressedSize    == 0xFFFFFFFFu) { if (q + 8 > qEnd) break; memcpy(&compressedSize,    bytes + q, 8); q += 8; }
            if (localOffset == 0xFFFFFFFFu) { if (q + 8 > qEnd) break; memcpy(&localOffset, bytes + q, 8); q += 8; }
            break;
        }
        p += 4 + size;
    }
    
    struct LocalHeaderRecord localHeader;
    //todo: add check before memcpy
    memcpy(&localHeader, bytes+ localOffset, sizeof(localHeader));
    
    uint64_t dataStart = localOffset + localHeader.filenameLength + localHeader.extraFieldlength + sizeof(localHeader);
    uint64_t dataEnd = dataStart + compressedSize;
    
    NSMutableData *KernelCache = [NSMutableData dataWithLength:(NSUInteger)uncompressedSize];
    if(localHeader.compressionMethod == 8){
        z_stream z = {0};
        inflateInit2(&z, -MAX_WBITS);
        z.next_in = (Bytef *)(bytes + dataStart);
        z.avail_in = (uInt)compressedSize;
        z.next_out = KernelCache.mutableBytes;
        z.avail_out = (uInt)KernelCache.length;
        int result = inflate(&z, Z_FINISH);
        uLong totalOut = z.total_out;
        inflateEnd(&z);
        if(result != Z_STREAM_END || totalOut != uncompressedSize){
            *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Kernelcache deflate error"}];
            return nil;
        }
        if(crc32(0, KernelCache.bytes, (uInt)KernelCache.length)!= cdEntry.crc32Uncompressed){
            *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"uncompressed CRC32 check failed"}];
            return nil;
        }
        ipsw.kernelcache = KernelCache;
        return ipsw;
    }else if(localHeader.compressionMethod == 0){
        uint8_t *kernelcacheBytes = KernelCache.mutableBytes;
        if((dataStart + uncompressedSize) > archiveSize){
            *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"OOB when reading kernelcache"}];
            return nil;
        }
        memcpy(kernelcacheBytes, bytes+dataStart, uncompressedSize);
        ipsw.kernelcache = KernelCache;
        return ipsw;
    }else {
        *error = [NSError errorWithDomain:@"IPSWErrorDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Unsupported compression method"}];
    }
    
    return nil;
}

@end
