//
//  ViewController.m
//  Bouncer
//
//  Created by praveen on 2026-09-24.
//

#import "ViewController.h"
#import "im4p.h"
#import "ipsw.h"
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
        NSLog(@"Picked file %@", url.path);
        NSError *error = nil;
        Ipsw *ipsw = [Ipsw initWithPath:url.path error:&error];
        if(ipsw != nil){
            NSLog(@"success");
        }
    }];
    
    
    
}

@end




