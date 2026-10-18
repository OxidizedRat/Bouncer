//
//  ViewController.m
//  Bouncer
//
//  Created by praveen on 2026-09-24.
//

#import "ViewController.h"
#import "Kernelcache.h"
#import "RuleTreeItem.h"
#import "RuleExporter.h"

@interface ProfileGroup : NSObject
@property (copy) NSString * name;
@property (strong) SandboxBlob * blob;
@end
@implementation ProfileGroup
@end

static NSString * const kTextCellIdentifier = @"TextCell";

@interface ViewController () <NSOutlineViewDataSource, NSOutlineViewDelegate, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate>
@property (nonatomic, nullable) Kernelcache * kernelcache;
@property (nonatomic, copy) NSArray<ProfileGroup *> * groups;
@property (nonatomic) NSOutlineView * profileOutline;
@property (nonatomic) NSTableView * operationTable;
@property (nonatomic) NSOutlineView * ruleOutline;
@property (nonatomic) NSSearchField * searchField;
@property (nonatomic) NSTextField * statusLabel;
@property (nonatomic) NSButton * textButton;
@property (nonatomic) NSButton * dotButton;
@property (nonatomic, nullable) SandboxProfile * selectedProfile;
@property (nonatomic, nullable) SandboxBlob * selectedBlob;
@property (nonatomic, copy) NSArray<NSNumber *> * visibleOperations;
@property (nonatomic, nullable) RuleTreeItem * ruleRoot;
@property (nonatomic) NSSplitView * splitView;
@property (nonatomic) BOOL didPlaceDividers;
// Verdicts are computed when a row is first shown and kept per profile.
@property (nonatomic) NSMapTable<SandboxProfile *, NSMutableDictionary<NSNumber *, NSNumber *> *> * verdictCache;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.groups = @[];
    self.visibleOperations = @[];
    self.verdictCache = [NSMapTable strongToStrongObjectsMapTable];
    [self buildInterface];
    [self updateButtons];
}

- (void)viewDidAppear {
    [super viewDidAppear];
    NSWindow * window = self.view.window;
    if(window.frame.size.width < 900){
        [window setContentSize:NSMakeSize(1280, 760)];
        [window center];
    }
    window.contentMinSize = NSMakeSize(900, 500);
    window.title = @"Bouncer";
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

-(NSScrollView *) scrollViewFor:(NSTableView *)tableView{
    NSScrollView * scrollView = [[NSScrollView alloc] init];
    scrollView.documentView = tableView;
    scrollView.hasVerticalScroller = YES;
    scrollView.hasHorizontalScroller = YES;
    scrollView.autohidesScrollers = YES;
    return scrollView;
}

-(NSTableColumn *) columnWithIdentifier:(NSString *)identifier title:(NSString *)title width:(CGFloat)width{
    NSTableColumn * column = [[NSTableColumn alloc] initWithIdentifier:identifier];
    column.title = title;
    column.width = width;
    column.minWidth = 40;
    return column;
}

-(void) buildInterface{
    NSButton * openButton = [NSButton buttonWithTitle:@"Open Kernelcache" target:self action:@selector(chooseFile:)];
    [openButton setContentHuggingPriority:NSLayoutPriorityDefaultHigh forOrientation:NSLayoutConstraintOrientationHorizontal];
    self.textButton = [NSButton buttonWithTitle:@"Copy as Text" target:self action:@selector(copyAsText:)];
    self.dotButton = [NSButton buttonWithTitle:@"Export DOT…" target:self action:@selector(exportDOT:)];
    self.statusLabel = [NSTextField labelWithString:@""];
    self.statusLabel.textColor = NSColor.secondaryLabelColor;
    self.statusLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    [self.statusLabel setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];
    [self.statusLabel setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    self.searchField = [[NSSearchField alloc] init];
    self.searchField.placeholderString = @"Filter operations";
    self.searchField.delegate = self;
    [self.searchField.widthAnchor constraintEqualToConstant:220].active = YES;

    NSStackView * toolbar = [NSStackView stackViewWithViews:@[openButton, self.statusLabel, self.searchField, self.textButton, self.dotButton]];
    toolbar.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    toolbar.spacing = 8;
    [toolbar setHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];

    self.profileOutline = [[NSOutlineView alloc] init];
    NSTableColumn * profileColumn = [self columnWithIdentifier:@"profile" title:@"Profiles" width:220];
    [self.profileOutline addTableColumn:profileColumn];
    self.profileOutline.outlineTableColumn = profileColumn;
    self.profileOutline.style = NSTableViewStyleSourceList;
    self.profileOutline.headerView = nil;
    self.profileOutline.floatsGroupRows = NO;
    self.profileOutline.dataSource = self;
    self.profileOutline.delegate = self;

    self.operationTable = [[NSTableView alloc] init];
    [self.operationTable addTableColumn:[self columnWithIdentifier:@"operation" title:@"Operation" width:220]];
    [self.operationTable addTableColumn:[self columnWithIdentifier:@"verdict" title:@"Verdict" width:150]];
    self.operationTable.columnAutoresizingStyle = NSTableViewFirstColumnOnlyAutoresizingStyle;
    self.operationTable.usesAlternatingRowBackgroundColors = YES;
    self.operationTable.dataSource = self;
    self.operationTable.delegate = self;

    self.ruleOutline = [[NSOutlineView alloc] init];
    NSTableColumn * ruleColumn = [self columnWithIdentifier:@"rule" title:@"Rule" width:640];
    [self.ruleOutline addTableColumn:ruleColumn];
    [self.ruleOutline addTableColumn:[self columnWithIdentifier:@"node" title:@"Node" width:70]];
    self.ruleOutline.outlineTableColumn = ruleColumn;
    self.ruleOutline.columnAutoresizingStyle = NSTableViewFirstColumnOnlyAutoresizingStyle;
    self.ruleOutline.dataSource = self;
    self.ruleOutline.delegate = self;

    NSSplitView * splitView = [[NSSplitView alloc] init];
    splitView.vertical = YES;
    splitView.dividerStyle = NSSplitViewDividerStyleThin;
    NSScrollView * profilePane = [self scrollViewFor:self.profileOutline];
    NSScrollView * operationPane = [self scrollViewFor:self.operationTable];
    NSScrollView * rulePane = [self scrollViewFor:self.ruleOutline];
    [splitView addArrangedSubview:profilePane];
    [splitView addArrangedSubview:operationPane];
    [splitView addArrangedSubview:rulePane];
    [profilePane.widthAnchor constraintGreaterThanOrEqualToConstant:160].active = YES;
    [operationPane.widthAnchor constraintGreaterThanOrEqualToConstant:260].active = YES;
    [rulePane.widthAnchor constraintGreaterThanOrEqualToConstant:300].active = YES;
    [splitView setHoldingPriority:NSLayoutPriorityDefaultLow - 1 forSubviewAtIndex:2];

    for(NSView * view in @[toolbar, splitView]){
        view.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:view];
    }
    [NSLayoutConstraint activateConstraints:@[
        [toolbar.topAnchor constraintEqualToAnchor:self.view.topAnchor constant:10],
        [toolbar.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [toolbar.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],
        [splitView.topAnchor constraintEqualToAnchor:toolbar.bottomAnchor constant:10],
        [splitView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [splitView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [splitView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    ]];
    self.splitView = splitView;
}

// Divider positions only stick once the split view has its real width, so they are set on the first layout.
- (void)viewDidLayout {
    [super viewDidLayout];
    if(!self.didPlaceDividers && self.splitView.bounds.size.width > 900){
        self.didPlaceDividers = YES;
        [self.splitView setPosition:240 ofDividerAtIndex:0];
        [self.splitView setPosition:640 ofDividerAtIndex:1];
    }
}

-(NSTableCellView *) textCellIn:(NSTableView *)tableView{
    NSTableCellView * cell = [tableView makeViewWithIdentifier:kTextCellIdentifier owner:self];
    if(cell){
        return cell;
    }
    cell = [[NSTableCellView alloc] init];
    cell.identifier = kTextCellIdentifier;
    NSTextField * textField = [NSTextField labelWithString:@""];
    textField.lineBreakMode = NSLineBreakByTruncatingTail;
    textField.translatesAutoresizingMaskIntoConstraints = NO;
    [cell addSubview:textField];
    cell.textField = textField;
    [NSLayoutConstraint activateConstraints:@[
        [textField.leadingAnchor constraintEqualToAnchor:cell.leadingAnchor constant:2],
        [textField.trailingAnchor constraintEqualToAnchor:cell.trailingAnchor constant:-2],
        [textField.centerYAnchor constraintEqualToAnchor:cell.centerYAnchor],
    ]];
    return cell;
}

-(void) updateButtons{
    BOOL hasOperation = self.selectedProfile && self.operationTable.selectedRow >= 0;
    self.textButton.enabled = hasOperation;
    self.dotButton.enabled = hasOperation;
}


-(void)chooseFile:(id)sender{
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    panel.message = @"Select a decompressed kernelcache to load";

    [panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse result){
        if(result != NSModalResponseOK){
            return;
        }
        NSURL *url = panel.URL;
        self.statusLabel.stringValue = [NSString stringWithFormat:@"Loading %@…", url.lastPathComponent];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSError *error = nil;
            Kernelcache *kernelcache = [[Kernelcache alloc] initWithPath:url.path error:&error];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!kernelcache){
                    self.statusLabel.stringValue = @"Loading failed.";
                    [self showError:error];
                    return;
                }
                [self showKernelcache:kernelcache name:url.lastPathComponent];
            });
        });
    }];
}

-(void) showKernelcache:(Kernelcache *)kernelcache name:(NSString *)name{
    self.kernelcache = kernelcache;
    NSMutableArray<ProfileGroup *> * groups = [NSMutableArray array];
    NSArray * entries = @[@[@"Platform", kernelcache.profile], @[@"Collection", kernelcache.builtin], @[@"Protobox", kernelcache.protobox]];
    NSMutableArray<NSString *> * counts = [NSMutableArray array];
    for(NSArray * entry in entries){
        ProfileGroup * group = [[ProfileGroup alloc] init];
        group.name = entry[0];
        group.blob = entry[1];
        [groups addObject:group];
        [counts addObject:[NSString stringWithFormat:@"%@ %lu", group.name, (unsigned long)group.blob.profiles.count]];
    }
    self.groups = groups;
    [self.verdictCache removeAllObjects];
    self.selectedProfile = nil;
    self.selectedBlob = nil;
    self.visibleOperations = @[];
    self.ruleRoot = nil;
    [self.profileOutline reloadData];
    [self.operationTable reloadData];
    [self.ruleOutline reloadData];
    for(ProfileGroup * group in groups){
        [self.profileOutline expandItem:group];
    }
    self.statusLabel.stringValue = [NSString stringWithFormat:@"%@ — profiles: %@", name, [counts componentsJoinedByString:@", "]];
    [self updateButtons];
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

-(void) reloadOperations{
    NSString * filter = self.searchField.stringValue;
    NSMutableArray<NSNumber *> * operations = [NSMutableArray array];
    NSArray<NSString *> * names = self.selectedBlob.operationNames;
    for(NSUInteger i = 0; i < names.count; i++){
        if(!filter.length || [names[i] rangeOfString:filter options:NSCaseInsensitiveSearch].location != NSNotFound){
            [operations addObject:@(i)];
        }
    }
    self.visibleOperations = operations;
    [self.operationTable reloadData];
    [self showRuleForOperation:NSNotFound];
}

-(OperationVerdict) verdictForOperation:(NSUInteger)opIndex{
    NSMutableDictionary<NSNumber *, NSNumber *> * verdicts = [self.verdictCache objectForKey:self.selectedProfile];
    if(!verdicts){
        verdicts = [NSMutableDictionary dictionary];
        [self.verdictCache setObject:verdicts forKey:self.selectedProfile];
    }
    NSNumber * verdict = verdicts[@(opIndex)];
    if(!verdict){
        verdict = @([self.selectedBlob verdictForOperationAtIndex:opIndex inProfile:self.selectedProfile]);
        verdicts[@(opIndex)] = verdict;
    }
    return (OperationVerdict)verdict.unsignedLongLongValue;
}

static NSString * verdictText(OperationVerdict verdict){
    switch(verdict){
        case OperationVerdictAlwaysAllow:      return @"allow";
        case OperationVerdictAlwaysDeny:       return @"deny";
        case OperationVerdictConditional:      return @"allow or deny";
        case OperationVerdictConditionalAllow: return @"conditional, allow only";
        case OperationVerdictConditionalDeny:  return @"conditional, deny only";
        case OperationVerdictInvalid:          return @"invalid";
    }
    return @"?";
}

static NSColor * verdictColor(OperationVerdict verdict){
    switch(verdict){
        case OperationVerdictAlwaysAllow:
        case OperationVerdictConditionalAllow:
            return NSColor.systemGreenColor;
        case OperationVerdictAlwaysDeny:
        case OperationVerdictConditionalDeny:
            return NSColor.systemRedColor;
        case OperationVerdictConditional:
            return NSColor.systemOrangeColor;
        case OperationVerdictInvalid:
            break;
    }
    return NSColor.secondaryLabelColor;
}

-(NSUInteger) selectedOperation{
    NSInteger row = self.operationTable.selectedRow;
    if(row < 0 || (NSUInteger)row >= self.visibleOperations.count){
        return NSNotFound;
    }
    return self.visibleOperations[row].unsignedIntegerValue;
}

-(void) showRuleForOperation:(NSUInteger)opIndex{
    if(opIndex == NSNotFound || !self.selectedProfile){
        self.ruleRoot = nil;
    }
    else{
        uint16_t start = [self.selectedProfile nodeIndexForOperationAtIndex:opIndex];
        self.ruleRoot = [RuleTreeItem itemForNode:start inBlob:self.selectedBlob role:nil];
    }
    [self.ruleOutline reloadData];
    if(self.ruleRoot){
        [self.ruleOutline expandItem:self.ruleRoot];
    }
    [self updateButtons];
}

-(void) controlTextDidChange:(NSNotification *)notification{
    if(notification.object == self.searchField){
        [self reloadOperations];
    }
}

-(void) copyAsText:(id)sender{
    NSUInteger opIndex = [self selectedOperation];
    if(opIndex == NSNotFound){
        return;
    }
    NSString * text = [RuleExporter textForOperationAtIndex:opIndex inProfile:self.selectedProfile blob:self.selectedBlob];
    if(!text){
        return;
    }
    [NSPasteboard.generalPasteboard clearContents];
    [NSPasteboard.generalPasteboard setString:text forType:NSPasteboardTypeString];
    self.statusLabel.stringValue = [NSString stringWithFormat:@"Copied %@ (%lu lines).", self.selectedBlob.operationNames[opIndex],
                                    (unsigned long)[text componentsSeparatedByString:@"\n"].count - 1];
}

-(void) exportDOT:(id)sender{
    NSUInteger opIndex = [self selectedOperation];
    if(opIndex == NSNotFound){
        return;
    }
    NSString * dot = [RuleExporter dotForOperationAtIndex:opIndex inProfile:self.selectedProfile blob:self.selectedBlob];
    if(!dot){
        return;
    }
    NSSavePanel * panel = [NSSavePanel savePanel];
    panel.nameFieldStringValue = [NSString stringWithFormat:@"%@-%@.dot", self.selectedProfile.name, self.selectedBlob.operationNames[opIndex]];
    [panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse result){
        if(result != NSModalResponseOK){
            return;
        }
        NSError * error = nil;
        if(![dot writeToURL:panel.URL atomically:YES encoding:NSUTF8StringEncoding error:&error]){
            [self showError:error];
            return;
        }
        self.statusLabel.stringValue = [NSString stringWithFormat:@"Saved %@. Render it with: dot -Tsvg -O \"%@\"", panel.URL.lastPathComponent, panel.URL.path];
    }];
}


-(NSInteger) outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item{
    if(outlineView == self.profileOutline){
        if(!item){
            return (NSInteger)self.groups.count;
        }
        if([item isKindOfClass:[ProfileGroup class]]){
            return (NSInteger)((ProfileGroup *)item).blob.profiles.count;
        }
        return 0;
    }
    if(!item){
        return self.ruleRoot ? 1 : 0;
    }
    return (NSInteger)((RuleTreeItem *)item).children.count;
}

-(id) outlineView:(NSOutlineView *)outlineView child:(NSInteger)index ofItem:(id)item{
    if(outlineView == self.profileOutline){
        if(!item){
            return self.groups[index];
        }
        return ((ProfileGroup *)item).blob.profiles[index];
    }
    if(!item){
        return self.ruleRoot;
    }
    return ((RuleTreeItem *)item).children[index];
}

-(BOOL) outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item{
    if(outlineView == self.profileOutline){
        return [item isKindOfClass:[ProfileGroup class]];
    }
    RuleTreeItem * rule = item;
    return !rule.isTerminal && rule.kind != RuleTreeItemKindCondition;
}

-(BOOL) outlineView:(NSOutlineView *)outlineView isGroupItem:(id)item{
    return outlineView == self.profileOutline && [item isKindOfClass:[ProfileGroup class]];
}

-(BOOL) outlineView:(NSOutlineView *)outlineView shouldSelectItem:(id)item{
    return outlineView != self.profileOutline || ![item isKindOfClass:[ProfileGroup class]];
}

-(NSView *) outlineView:(NSOutlineView *)outlineView viewForTableColumn:(NSTableColumn *)tableColumn item:(id)item{
    NSTableCellView * cell = [self textCellIn:outlineView];
    NSTextField * textField = cell.textField;
    textField.toolTip = nil;
    textField.textColor = NSColor.labelColor;
    if(outlineView == self.profileOutline){
        textField.font = [NSFont systemFontOfSize:NSFont.systemFontSize];
        if([item isKindOfClass:[ProfileGroup class]]){
            ProfileGroup * group = item;
            textField.stringValue = [NSString stringWithFormat:@"%@ (%lu)", group.name, (unsigned long)group.blob.profiles.count];
        }
        else{
            textField.stringValue = ((SandboxProfile *)item).name;
        }
        return cell;
    }
    RuleTreeItem * rule = item;
    textField.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
    if([tableColumn.identifier isEqualToString:@"node"]){
        textField.stringValue = [NSString stringWithFormat:@"0x%04x", rule.nodeIndex];
        textField.textColor = NSColor.secondaryLabelColor;
        return cell;
    }
    NSString * title = rule.role ? [NSString stringWithFormat:@"%@ → %@", rule.role, rule.title] : rule.title;
    textField.stringValue = title;
    if(rule.isTerminal){
        OpNode node = {0};
        [rule.blob node:&node atIndex:rule.nodeIndex];
        textField.textColor = (node.filterID & 1) ? NSColor.systemRedColor : NSColor.systemGreenColor;
    }
    if(rule.kind == RuleTreeItemKindNode || rule.kind == RuleTreeItemKindCondition || rule.kind == RuleTreeItemKindCase){
        textField.toolTip = [rule.blob conditionDescriptionForNodeAtIndex:rule.nodeIndex limit:500];
    }
    return cell;
}

-(void) outlineViewSelectionDidChange:(NSNotification *)notification{
    if(notification.object != self.profileOutline){
        return;
    }
    id item = [self.profileOutline itemAtRow:self.profileOutline.selectedRow];
    if(![item isKindOfClass:[SandboxProfile class]]){
        return;
    }
    self.selectedProfile = item;
    self.selectedBlob = ((ProfileGroup *)[self.profileOutline parentForItem:item]).blob;
    [self reloadOperations];
}

-(NSInteger) numberOfRowsInTableView:(NSTableView *)tableView{
    return (NSInteger)self.visibleOperations.count;
}

-(NSView *) tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row{
    NSTableCellView * cell = [self textCellIn:tableView];
    NSUInteger opIndex = self.visibleOperations[row].unsignedIntegerValue;
    if([tableColumn.identifier isEqualToString:@"verdict"]){
        OperationVerdict verdict = [self verdictForOperation:opIndex];
        cell.textField.stringValue = verdictText(verdict);
        cell.textField.textColor = verdictColor(verdict);
    }
    else{
        cell.textField.stringValue = self.selectedBlob.operationNames[opIndex];
        cell.textField.textColor = NSColor.labelColor;
    }
    return cell;
}

-(void) tableViewSelectionDidChange:(NSNotification *)notification{
    [self showRuleForOperation:[self selectedOperation]];
}

@end
