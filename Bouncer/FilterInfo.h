//
//  FilterInfo.h
//  Bouncer
//
//  Created by praveen on 2026-10-18.
//

#ifndef FilterInfo_h
#define FilterInfo_h
#import <Foundation/Foundation.h>
// Filter IDs, names and argument kinds from macOS 26.5 (25F84) libsandbox filter_info.
// IDs >= 0x80 are an alternate form of (id & 0x7F): a regex index for string and pattern
// filters, a value-set bitmap for integer filters.
typedef NS_ENUM(uint8_t, FilterArgKind) {
    FilterArgKindUnknown = 0,
    FilterArgKindInteger,
    FilterArgKindString,
    FilterArgKindPattern,
};

typedef NS_ENUM(uint8_t, FilterArgForm) {
    FilterArgFormPlain = 0,
    FilterArgFormRegex,
    FilterArgFormValueSet,
};

typedef struct {
    const char * _Nullable name;
    FilterArgKind kind;
} FilterInfo;

FilterInfo FilterInfoForID(uint8_t rawID, FilterArgForm * _Nullable form);

// Name of an integer argument value, e.g. vnode-type 1 -> "REGULAR-FILE". NULL if unknown.
const char * _Nullable FilterValueName(uint8_t baseID, uint16_t value);

// Terminal flag bits other than bit 0 (deny), named after the macOS libsandbox flag modifiers.
// Fills names with up to 7 entries and returns how many were written; unnamed bits are skipped.
NSUInteger TerminalFlagNames(uint8_t flags, const char * _Nonnull names[_Nonnull 7]);

// Name of a string-argument modifier used by extended terminals, e.g. 12 -> "assign-storage-class". NULL if unknown.
const char * _Nullable ModifierName(uint16_t modifier);

#endif /* FilterInfo_h */
