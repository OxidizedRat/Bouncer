//
//  FilterInfo.m
//  Bouncer
//
//  Created by praveen on 2026-10-18.
//

#import <Foundation/Foundation.h>
#import "FilterInfo.h"

static const FilterInfo kFilterInfo[256] = {
    [  1] = { "path",                                        FilterArgKindPattern },
    [  2] = { "mount-relative-path",                         FilterArgKindPattern },
    [  3] = { "xattr",                                       FilterArgKindPattern },
    [  4] = { "file-mode",                                   FilterArgKindInteger },
    [  5] = { "ipc-posix-name",                              FilterArgKindPattern },
    [  6] = { "global-name",                                 FilterArgKindPattern },
    [  7] = { "local-name",                                  FilterArgKindPattern },
    [  8] = { "local",                                       FilterArgKindUnknown }, // macOS type 8, args look like small integers
    [  9] = { "remote",                                      FilterArgKindUnknown }, // macOS type 8, args look like small integers
    [ 10] = { "control-name",                                FilterArgKindPattern },
    [ 11] = { "socket-domain",                               FilterArgKindInteger },
    [ 12] = { "socket-type",                                 FilterArgKindInteger },
    [ 13] = { "socket-protocol",                             FilterArgKindInteger },
    [ 14] = { "target",                                      FilterArgKindInteger },
    [ 15] = { "fsctl-command",                               FilterArgKindInteger },
    [ 16] = { "ioctl-command",                               FilterArgKindInteger },
    [ 17] = { "iokit-registry-entry-class",                  FilterArgKindPattern },
    [ 18] = { "iokit-property",                              FilterArgKindPattern },
    [ 19] = { "iokit-connection",                            FilterArgKindPattern },
    [ 20] = { "device-major",                                FilterArgKindInteger },
    [ 21] = { "device-minor",                                FilterArgKindInteger },
    [ 22] = { "device-conforms-to",                          FilterArgKindString },
    [ 23] = { "extension",                                   FilterArgKindString },
    [ 24] = { "extension-class",                             FilterArgKindPattern },
    [ 25] = { "appleevent-destination",                      FilterArgKindPattern },
    [ 26] = { "system-attribute",                            FilterArgKindInteger },
    [ 27] = { "right-name",                                  FilterArgKindPattern },
    [ 28] = { "preference-domain",                           FilterArgKindPattern },
    [ 29] = { "vnode-type",                                  FilterArgKindInteger },
    [ 30] = { "entitlement-load",                            FilterArgKindString },
    [ 31] = { "entitlement-boolean",                         FilterArgKindInteger },
    [ 32] = { "entitlement-string",                          FilterArgKindUnknown }, // macOS says pattern, args are neither strings nor patterns
    [ 33] = { "kext-bundle-id",                              FilterArgKindPattern },
    [ 34] = { "info-type",                                   FilterArgKindPattern },
    [ 35] = { "notification-name",                           FilterArgKindPattern },
    [ 36] = { "notification-payload",                        FilterArgKindInteger },
    [ 37] = { "semaphore-owner",                             FilterArgKindInteger },
    [ 38] = { "sysctl-name",                                 FilterArgKindPattern },
    [ 39] = { "process-path",                                FilterArgKindPattern },
    [ 40] = { "rootless-boot-device-filter",                 FilterArgKindInteger },
    [ 41] = { "rootless-disk-filter",                        FilterArgKindInteger },
    [ 42] = { "privilege-id",                                FilterArgKindInteger },
    [ 43] = { "process-attribute",                           FilterArgKindInteger },
    [ 44] = { "uid",                                         FilterArgKindInteger },
    [ 45] = { "nvram-variable",                              FilterArgKindPattern },
    [ 46] = { "csr",                                         FilterArgKindInteger },
    [ 47] = { "host-special-port",                           FilterArgKindInteger },
    [ 48] = { "filesystem-name",                             FilterArgKindPattern },
    [ 49] = { "boot-arg",                                    FilterArgKindPattern },
    [ 50] = { "xpc-service-name",                            FilterArgKindPattern },
    [ 51] = { "signing-identifier",                          FilterArgKindPattern },
    [ 52] = { "signal-number",                               FilterArgKindInteger },
    [ 53] = { "target-signing-identifier",                   FilterArgKindPattern },
    [ 54] = { "reboot-flags",                                FilterArgKindInteger },
    [ 55] = { "datavault-disk-filter",                       FilterArgKindInteger },
    [ 56] = { "extension-path-ancestor",                     FilterArgKindInteger },
    [ 57] = { "file-attribute",                              FilterArgKindInteger },
    [ 58] = { "storage-class",                               FilterArgKindString },
    [ 59] = { "storage-class-extension",                     FilterArgKindInteger },
    [ 60] = { "iokit-usb-interface-class",                   FilterArgKindInteger },
    [ 61] = { "iokit-usb-interface-subclass",                FilterArgKindInteger },
    [ 62] = { "ancestor-signing-identifier",                 FilterArgKindPattern },
    [ 63] = { "require-ancestor-with-entitlement",           FilterArgKindString },
    [ 64] = { "persona-type",                                FilterArgKindInteger },
    [ 65] = { "syscall-number",                              FilterArgKindInteger },
    [ 66] = { "require-target-with-entitlement",             FilterArgKindString },
    [ 67] = { "iokit-registry-entry-attribute",              FilterArgKindInteger },
    [ 68] = { "user-intent-extension",                       FilterArgKindString },
    [ 69] = { "snapshot-name",                               FilterArgKindPattern },
    [ 70] = { "mach-derived-port-role",                      FilterArgKindPattern },
    [ 71] = { "message-number",                              FilterArgKindInteger },
    [ 72] = { "message-name",                                FilterArgKindPattern },
    [ 73] = { "iokit-method-number",                         FilterArgKindInteger },
    [ 74] = { "iokit-trap-number",                           FilterArgKindInteger },
    [ 75] = { "machtrap-number",                             FilterArgKindInteger },
    [ 76] = { "kernel-mig-routine",                          FilterArgKindInteger },
    [ 77] = { "iokit-user-client-type",                      FilterArgKindInteger },
    [ 78] = { "fcntl-command",                               FilterArgKindInteger },
    [ 79] = { "socket-option-level",                         FilterArgKindInteger },
    [ 80] = { "socket-option-name",                          FilterArgKindInteger },
    [ 81] = { "mac-policy-name",                             FilterArgKindPattern },
    [ 82] = { "mac-syscall-number",                          FilterArgKindInteger },
    [ 83] = { "necp-client-action",                          FilterArgKindInteger },
    [ 84] = { "memorystatus-control-command",                FilterArgKindInteger },
    [ 85] = { "state-flag",                                  FilterArgKindInteger }, // macOS says string, args look like state-flag table indices
    [ 86] = { "require-responsible-binary-with-entitlement", FilterArgKindString },
    [ 87] = { "entitlement-is-bool-true",                    FilterArgKindString },
    [ 88] = { "entitlement-is-present",                      FilterArgKindString },
    [ 89] = { "task-special-port",                           FilterArgKindInteger },
    [ 90] = { "fileprovider-syncroot-path",                  FilterArgKindPattern },
    [ 91] = { "mount-root-path",                             FilterArgKindPattern },
    [ 92] = { "codesigning-operation",                       FilterArgKindInteger },
    [ 93] = { "profile-flag",                                FilterArgKindInteger }, // macOS says string, args mostly small integers
    [ 94] = { "kas-info-selector",                           FilterArgKindInteger },
    [ 95] = { "mach-exception-behavior",                     FilterArgKindInteger },
    [ 96] = { "mach-exception-type",                         FilterArgKindInteger },
    [ 97] = { "check-operation",                             FilterArgKindPattern },
    [ 98] = { "extension-token-type",                        FilterArgKindInteger },
    [ 99] = { "extension-token-attribute",                   FilterArgKindInteger },
    [100] = { "iopolicy-type",                               FilterArgKindInteger },
    [101] = { "iopolicy-scope",                              FilterArgKindInteger },
    [102] = { "iopolicy-policy",                             FilterArgKindInteger },
    [103] = { "target-attribute",                            FilterArgKindInteger },
    [104] = { "exception-entitlement-name",                  FilterArgKindString },
    [105] = { "exception-entitlement-value",                 FilterArgKindPattern },
};

FilterInfo FilterInfoForID(uint8_t rawID, FilterArgForm *form){
    FilterArgForm argForm = FilterArgFormPlain;
    FilterInfo info = kFilterInfo[rawID & 0x7F];
    if(rawID >= 0x80){
        switch(info.kind){
            case FilterArgKindInteger:
                argForm = FilterArgFormValueSet;
                break;
            case FilterArgKindString:
            case FilterArgKindPattern:
                argForm = FilterArgFormRegex;
                break;
            case FilterArgKindUnknown:
                break;
        }
    }
    if(form){
        *form = argForm;
    }
    return info;
}

// Bit -> modifier name, from the macOS libsandbox modifier table. Bit 0 is allow/deny.
static const char * const kTerminalFlagNames[8] = {
    [1] = "grant",
    [2] = "report",
    [3] = "no-sandbox",
    [4] = "sip-override",
    [5] = "no-times",
    [6] = "authority",
    [7] = "telemetry",
};

NSUInteger TerminalFlagNames(uint8_t flags, const char *names[7]){
    NSUInteger count = 0;
    for(int bit = 1; bit < 8; bit++){
        if((flags & (1 << bit)) && kTerminalFlagNames[bit]){
            names[count++] = kTerminalFlagNames[bit];
        }
    }
    return count;
}

// Modifier numbers count from 1 through the macOS libsandbox modifier table.
static const char * const kModifierNames[] = {
    [1]  = "send-signal",
    [2]  = "errno",
    [3]  = "report",
    [4]  = "no-report",
    [5]  = "no-sandbox",
    [6]  = "grant",
    [7]  = "sip-override",
    [8]  = "no-times",
    [9]  = "user-approval",
    [10] = "message",
    [11] = "default-sandbox",
    [12] = "assign-storage-class",
    [13] = "authority",
    [14] = "telemetry",
    [15] = "telemetry-backtrace",
    [16] = "no-approval-prompt",
    [17] = "enable-state-flag",
    [18] = "no-storage-class",
    [19] = "autobox-telemetry",
    [20] = "restrictive-default",
    [21] = "message-filter",
};

const char *ModifierName(uint16_t modifier){
    if(modifier >= sizeof(kModifierNames) / sizeof(kModifierNames[0])){
        return NULL;
    }
    return kModifierNames[modifier];
}
