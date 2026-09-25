//
//  im4p.m
//  Bouncer
//
//  Created by praveen on 2026-09-24.
//

#import <Foundation/Foundation.h>
#import "im4p.h"

@implementation Im4p

+ (instancetype) initWithPath:(NSString *)path{
    Im4p *im4p = [[Im4p alloc]init];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error =nil;
    NSDictionary<NSString *,id> *attributes =  [fileManager attributesOfItemAtPath:path error:&error];
    if (error != nil ){
        NSLog(@"%@", error);
        return NULL;
    }
    NSString *fileType = [attributes fileType];
    if([fileType isNotEqualTo:@"NSFileTypeRegular"]){
        return NULL;
    }
    NSData *contents = [fileManager contentsAtPath:path];
    const uint8_t *bytes = contents.bytes;
    for(int i =0; i<4;i++){
        NSLog(@"%u", bytes[i]);
    }
    return im4p;
}

@end
