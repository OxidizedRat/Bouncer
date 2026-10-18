//
//  SandboxRegex.m
//  Bouncer
//
//  Created by praveen on 2026-10-18.
//

#import "SandboxRegex.h"

typedef NS_ENUM(uint8_t, RegexOp) {
    RegexOpChar,
    RegexOpAny,
    RegexOpBOL,
    RegexOpEOL,
    RegexOpMatch,
    RegexOpSplit,
    RegexOpJump,
    RegexOpClass,
};

typedef struct {
    RegexOp op;
    uint32_t offset;
    uint32_t target;
    uint32_t operandOffset;
    uint8_t operand;
} RegexInstruction;

static const NSUInteger kMaxInstructions = 4096;
static const NSUInteger kMaxDepth = 64;

@interface RegexDecompiler : NSObject
@property (nonatomic) const uint8_t * program;
@property (nonatomic) NSUInteger programLength;
@property (nonatomic) RegexInstruction * instructions;
@property (nonatomic) NSUInteger count;
@property (nonatomic) uint32_t * postDominator;
@property (nonatomic) NSUInteger depth;
@end

@implementation RegexDecompiler

-(void) dealloc{
    free(_instructions);
    free(_postDominator);
}

-(BOOL) disassemble{
    const uint8_t * p = self.program;
    NSUInteger length = self.programLength;
    int32_t * indexForOffset = malloc((length + 1) * sizeof(int32_t));
    self.instructions = calloc(length + 1, sizeof(RegexInstruction));
    if(!indexForOffset || !self.instructions){
        free(indexForOffset);
        return NO;
    }
    for(NSUInteger i = 0; i <= length; i++){
        indexForOffset[i] = -1;
    }
    NSUInteger pc = 0;
    NSUInteger count = 0;
    BOOL ok = YES;
    while(ok && pc < length){
        if(count >= kMaxInstructions){
            ok = NO;
            break;
        }
        RegexInstruction ins = { .offset = (uint32_t)pc };
        uint8_t opcode = p[pc];
        NSUInteger size = 1;
        if(opcode == 0x02 || opcode == 0x15){
            size = 2;
            ins.op = opcode == 0x02 ? RegexOpChar : RegexOpMatch;
        }
        else if(opcode == 0x09){
            ins.op = RegexOpAny;
        }
        else if(opcode == 0x19){
            ins.op = RegexOpBOL;
        }
        else if(opcode == 0x29){
            ins.op = RegexOpEOL;
        }
        else if(opcode == 0x2f || opcode == 0x0a){
            size = 3;
            ins.op = opcode == 0x2f ? RegexOpSplit : RegexOpJump;
        }
        else if((opcode & 0x0f) == 0x0b && (opcode >> 4) > 0){
            ins.op = RegexOpClass;
            ins.operand = opcode >> 4;
            size = 1 + 2 * (NSUInteger)ins.operand;
        }
        else{
            ok = NO;
            break;
        }
        if(pc + size > length){
            ok = NO;
            break;
        }
        ins.operandOffset = (uint32_t)pc + 1;
        if(ins.op == RegexOpChar){
            ins.operand = p[pc + 1];
        }
        if(ins.op == RegexOpSplit || ins.op == RegexOpJump){
            ins.target = (uint32_t)(p[pc + 1] | (p[pc + 2] << 8));
        }
        indexForOffset[pc] = (int32_t)count;
        self.instructions[count++] = ins;
        pc += size;
    }
    indexForOffset[length] = (int32_t)count;
    self.count = count;

    for(NSUInteger i = 0; ok && i < count; i++){
        RegexInstruction * ins = &self.instructions[i];
        if(ins->op != RegexOpSplit && ins->op != RegexOpJump){
            continue;
        }
        if(ins->target > length || indexForOffset[ins->target] < 0){
            ok = NO;
            break;
        }
        ins->target = (uint32_t)indexForOffset[ins->target];
    }
    free(indexForOffset);
    return ok;
}

-(NSUInteger) successorsOf:(NSUInteger)i into:(NSUInteger[2])successors{
    NSUInteger exitNode = self.count;
    if(i >= exitNode){
        return 0;
    }
    RegexInstruction ins = self.instructions[i];
    switch(ins.op){
        case RegexOpMatch:
            successors[0] = exitNode;
            return 1;
        case RegexOpJump:
            successors[0] = ins.target;
            return 1;
        case RegexOpSplit:
            successors[0] = i + 1;
            successors[1] = ins.target;
            return 2;
        default:
            successors[0] = i + 1;   // i + 1 == count is the exit
            return 1;
    }
}


-(BOOL) computePostDominators{
    NSUInteger nodes = self.count + 1;
    NSUInteger words = (nodes + 63) / 64;
    uint64_t * sets = malloc(nodes * words * sizeof(uint64_t));
    self.postDominator = malloc(nodes * sizeof(uint32_t));
    if(!sets || !self.postDominator){
        free(sets);
        return NO;
    }
    for(NSUInteger v = 0; v < nodes; v++){
        memset(&sets[v * words], v == nodes - 1 ? 0 : 0xff, words * sizeof(uint64_t));
    }
    sets[(nodes - 1) * words + (nodes - 1) / 64] |= 1ULL << ((nodes - 1) % 64);
    uint64_t * scratch = malloc(words * sizeof(uint64_t));
    BOOL changed = YES;
    while(changed){
        changed = NO;
        for(NSInteger v = (NSInteger)nodes - 2; v >= 0; v--){
            NSUInteger successors[2];
            NSUInteger n = [self successorsOf:(NSUInteger)v into:successors];
            memset(scratch, 0xff, words * sizeof(uint64_t));
            for(NSUInteger s = 0; s < n; s++){
                for(NSUInteger w = 0; w < words; w++){
                    scratch[w] &= sets[successors[s] * words + w];
                }
            }
            scratch[v / 64] |= 1ULL << (v % 64);
            if(memcmp(scratch, &sets[v * words], words * sizeof(uint64_t)) != 0){
                memcpy(&sets[v * words], scratch, words * sizeof(uint64_t));
                changed = YES;
            }
        }
    }

    NSUInteger * sizes = calloc(nodes, sizeof(NSUInteger));
    for(NSUInteger v = 0; v < nodes; v++){
        for(NSUInteger w = 0; w < words; w++){
            sizes[v] += (NSUInteger)__builtin_popcountll(sets[v * words + w]);
        }
    }
    for(NSUInteger v = 0; v < nodes; v++){
        uint32_t best = (uint32_t)(nodes - 1);
        NSUInteger bestSize = 0;
        for(NSUInteger d = 0; d < nodes; d++){
            if(d == v || !(sets[v * words + d / 64] & (1ULL << (d % 64)))){
                continue;
            }
            if(sizes[d] > bestSize){
                bestSize = sizes[d];
                best = (uint32_t)d;
            }
        }
        self.postDominator[v] = best;
    }
    free(sizes);
    free(scratch);
    free(sets);
    return YES;
}

static void appendEscapedByte(NSMutableString * out, uint8_t c, BOOL inClass){
    const char * special = inClass ? "]\\^-" : ".^$|()[]{}*+?\\";
    if(c < 0x20 || c >= 0x7f){
        [out appendFormat:@"\\x%02x", c];
        return;
    }
    if(strchr(special, c)){
        [out appendString:@"\\"];
    }
    [out appendFormat:@"%c", c];
}

-(NSString *) classText:(RegexInstruction)ins{
    const uint8_t * ranges = self.program + ins.operandOffset;
    NSMutableString * out = [NSMutableString stringWithString:@"["];
    if(ins.operand == 1 && ranges[0] > ranges[1]){

        uint8_t first = ranges[1] + 1;
        uint8_t last = ranges[0] - 1;
        [out appendString:@"^"];
        appendEscapedByte(out, first, YES);
        if(last != first){
            [out appendString:@"-"];
            appendEscapedByte(out, last, YES);
        }
    }
    else{
        for(uint8_t r = 0; r < ins.operand; r++){
            uint8_t lo = ranges[2 * r];
            uint8_t hi = ranges[2 * r + 1];
            appendEscapedByte(out, lo, YES);
            if(hi != lo){
                [out appendString:@"-"];
                appendEscapedByte(out, hi, YES);
            }
        }
    }
    [out appendString:@"]"];
    return out;
}


static BOOL isSingleAtom(NSString * text){
    if(text.length == 1){
        return YES;
    }
    if(text.length == 2 && [text characterAtIndex:0] == '\\'){
        return YES;
    }
    unichar first = [text characterAtIndex:0];
    unichar close = first == '[' ? ']' : first == '(' ? ')' : 0;
    if(!close || [text characterAtIndex:text.length - 1] != close){
        return NO;
    }

    NSInteger level = 0;
    for(NSUInteger i = 0; i < text.length; i++){
        unichar c = [text characterAtIndex:i];
        if(c == '\\'){
            i++;
            continue;
        }
        if(first == '['){
            if(c == ']' && i != 0){
                return i == text.length - 1;
            }
            continue;
        }
        if(c == '('){
            level++;
        }
        else if(c == ')'){
            level--;
            if(level == 0 && i != text.length - 1){
                return NO;
            }
        }
    }
    return YES;
}

typedef NS_ENUM(uint8_t, RegexLoop) {
    RegexLoopPlus,
    RegexLoopStar,
    RegexLoopStarOutOfLine,
};



-(NSUInteger) loopJumpTo:(NSUInteger)loopHead kind:(RegexLoop *)kind{
    RegexInstruction head = self.instructions[loopHead];
    for(NSUInteger j = loopHead + 1; j < self.count; j++){
        RegexInstruction ins = self.instructions[j];
        if(ins.op != RegexOpJump || ins.target != loopHead){
            continue;
        }
        RegexInstruction beforeJump = self.instructions[j - 1];
        if(j > loopHead + 1 && beforeJump.op == RegexOpSplit && beforeJump.target == j + 1){
            *kind = RegexLoopPlus;
            return j;
        }
        if(head.op == RegexOpSplit && head.target == j + 1){
            *kind = RegexLoopStar;
            return j;
        }
        if(head.op == RegexOpSplit && head.target > loopHead + 1 && head.target < j){
            *kind = RegexLoopStarOutOfLine;
            return j;
        }
    }
    return NSNotFound;
}

-(BOOL) collectAlternativesFrom:(NSUInteger)i join:(NSUInteger)join into:(NSMutableArray<NSString *> *)alternatives{
    RegexInstruction ins = self.instructions[i];
    RegexLoop kind;
    if(ins.op == RegexOpSplit && self.postDominator[i] == join && [self loopJumpTo:i kind:&kind] == NSNotFound){
        return [self collectAlternativesFrom:i + 1 join:join into:alternatives] &&
               [self collectAlternativesFrom:ins.target join:join into:alternatives];
    }
    NSString * text = [self emitFrom:i to:join loopCheck:YES];
    if(!text){
        return NO;
    }
    [alternatives addObject:text];
    return YES;
}

-(nullable NSString *) emitFrom:(NSUInteger)start to:(NSUInteger)stop loopCheck:(BOOL)loopCheck{
    if(++self.depth > kMaxDepth){
        return nil;
    }
    NSMutableString * out = [NSMutableString string];
    NSUInteger i = start;
    BOOL checkLoop = loopCheck;
    NSUInteger steps = 0;
    while(i != stop && i < self.count){
        if(++steps > kMaxInstructions){
            self.depth--;
            return nil;
        }
        RegexLoop kind = RegexLoopPlus;
        NSUInteger back = checkLoop ? [self loopJumpTo:i kind:&kind] : NSNotFound;
        if(back != NSNotFound){
            NSString * body = nil;
            NSUInteger next = back + 1;
            switch(kind){
                case RegexLoopPlus:
                    body = [self emitFrom:i to:back - 1 loopCheck:NO];
                    break;
                case RegexLoopStar:
                    body = [self emitFrom:i + 1 to:back loopCheck:YES];
                    break;
                case RegexLoopStarOutOfLine:
                    body = [self emitFrom:self.instructions[i].target to:back loopCheck:YES];
                    next = i + 1;
                    break;
            }
            if(!body || !body.length){
                self.depth--;
                return nil;
            }
            NSString * quantifier = kind == RegexLoopPlus ? @"+" : @"*";
            if(isSingleAtom(body)){
                [out appendFormat:@"%@%@", body, quantifier];
            }
            else{
                [out appendFormat:@"(%@)%@", body, quantifier];
            }
            i = next;
            continue;
        }
        checkLoop = YES;
        RegexInstruction ins = self.instructions[i];
        switch(ins.op){
            case RegexOpChar:
                appendEscapedByte(out, ins.operand, NO);
                i++;
                break;
            case RegexOpAny:
                [out appendString:@"."];
                i++;
                break;
            case RegexOpBOL:
                [out appendString:@"^"];
                i++;
                break;
            case RegexOpEOL:
                [out appendString:@"$"];
                i++;
                break;
            case RegexOpClass:
                [out appendString:[self classText:ins]];
                i++;
                break;
            case RegexOpMatch:
                self.depth--;
                return out;
            case RegexOpJump:

                i = ins.target;
                break;
            case RegexOpSplit:{
                NSUInteger join = self.postDominator[i];
                NSMutableArray<NSString *> * alternatives = [NSMutableArray array];
                if(![self collectAlternativesFrom:i join:join into:alternatives]){
                    self.depth--;
                    return nil;
                }
                NSMutableArray<NSString *> * nonEmpty = [NSMutableArray array];
                for(NSString * alternative in alternatives){
                    if(alternative.length && ![nonEmpty containsObject:alternative]){
                        [nonEmpty addObject:alternative];
                    }
                }
                BOOL optional = nonEmpty.count < alternatives.count;
                NSString * group = [nonEmpty componentsJoinedByString:@"|"];
                if(nonEmpty.count == 1 && isSingleAtom(group)){
                    [out appendString:group];
                }
                else if(nonEmpty.count){
                    [out appendFormat:@"(%@)", group];
                }
                if(optional && nonEmpty.count){
                    [out appendString:@"?"];
                }
                i = join;
                break;
            }
        }
    }
    self.depth--;
    return out;
}

@end

NSString * SandboxRegexString(NSData * regexData){
    const uint8_t * bytes = regexData.bytes;
    if(regexData.length < 6){
        return nil;
    }
    uint32_t version = (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3];
    uint16_t programLength = (uint16_t)(bytes[4] | (bytes[5] << 8));
    if(version != 3 || 6 + (NSUInteger)programLength > regexData.length || programLength == 0){
        return nil;
    }
    RegexDecompiler * decompiler = [[RegexDecompiler alloc] init];
    decompiler.program = bytes + 6;
    decompiler.programLength = programLength;
    if(![decompiler disassemble] || ![decompiler computePostDominators]){
        return nil;
    }
    return [decompiler emitFrom:0 to:decompiler.count loopCheck:YES];
}
