//
//  ViewController.m
//  Bouncer
//
//  Created by praveen on 2026-09-24.
//

#import "ViewController.h"
#import "im4p.h"
#import "ipsw.h"
#import "Kernelcache.h"
@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    NSButton *button = [NSButton buttonWithTitle:@"Choose file" target:self action:@selector(chooseFile:)];
    button.bezelStyle = NSBezelStyleGlass;
    [self.view addSubview:button];
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

-(void)chooseFile:(id)sender{
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    panel.message = @"Select kernelcache or ipsw file to load";
    
    [panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse result){
        if(result != NSModalResponseOK){
            return;
        }
        NSURL *url = panel.URL;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSError *error = nil;
            NSData *im4pData = nil;
            BOOL isIPSW = [url.pathExtension caseInsensitiveCompare:@"ipsw"] == NSOrderedSame;
            if(isIPSW){
                
                Ipsw *ipsw = [[Ipsw alloc] initWithPath:url.path error:&error];
                if (ipsw){
                    im4pData = ipsw.kernelcache;
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (!im4pData) {
                        [self showError:error];
                        return;
                    }
                });
            } else {
                Kernelcache *kernelcache = [[Kernelcache alloc] initWithPath:url.path error:&error];
                if (!kernelcache){
                    [self showError:error];
                    return;
                }
            }
        });
        
    }];
}
-(void)showError:(NSError*) error{
    if (!error) return;
    NSAlert *alert = [NSAlert alertWithError:error];
    alert.alertStyle = NSAlertStyleWarning;
    NSWindow *window = self.view.window;
    if(window){
        [alert beginSheetModalForWindow:window completionHandler:nil];
    }else {
        [alert runModal];
    }
}
@end




