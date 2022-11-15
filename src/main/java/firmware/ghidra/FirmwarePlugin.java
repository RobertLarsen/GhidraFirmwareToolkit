package firmware.ghidra;

import docking.action.builder.ActionBuilder;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.internal.GTreeModel;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.FileSystemBrowserService;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.RefdFile;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.MiscellaneousPluginPackage;
import ghidra.plugins.fsbrowser.FSBActionContext;
import ghidra.plugins.fsbrowser.FSBFileNode;
import ghidra.plugins.fsbrowser.FSBNode;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.util.HashMap;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

@PluginInfo(
    status=PluginStatus.RELEASED,
    packageName=MiscellaneousPluginPackage.NAME,
    category=PluginCategoryNames.SUPPORT,
    shortDescription="Help analyzing firmware",
    description="Set of tools for working with firmware images",
    servicesRequired={ FileSystemBrowserService.class },
    servicesProvided={ FirmwareService.class },
    eventsConsumed={ ProgramActivatedPluginEvent.class, ProgramLocationPluginEvent.class }
)
public class FirmwarePlugin extends Plugin implements ApplicationLevelPlugin, FirmwareService {
    private final static String BINWALK_PATH = "Binwalk path";
    private final static String SASQUATCH_PATH = "Sasquatch path";

    public static final Logger log = LogManager.getLogger(FirmwarePlugin.class);
    private static FirmwarePlugin instance = null;

    private PluginTool tool;

    public FirmwarePlugin(PluginTool tool) {
        super(tool);
        this.tool = tool;
        instance = this;
    }

    public static FirmwarePlugin getInstance() {
        return instance;
    }

    public static String readString(InputStream in, String charset) throws IOException {
        byte buffer[] = new byte[1024];
        int bytesRead;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while ((bytesRead = in.read(buffer)) > 0) {
            out.write(buffer, 0, bytesRead);
        }
        return new String(out.toByteArray(), charset);
    }

    public void init() {
        super.init();
        registerOptions();
        setupActions();
    }

    private void setupActions() {
        tool.addAction(new FixupExternalsAction("Fixup Externals", getClass().getSimpleName(), tool));
        tool.addAction(createMarkDependenciesAction());
    }

    private DockingAction createMarkDependenciesAction() {
        return new ActionBuilder("Mark Dependencies", getName())
            .withContext(FSBActionContext.class)
            .enabledWhen(ac -> ac.notBusy() && ac.getFileFSRL() != null)
            .popupMenuPath("Mark Dependencies")
            .popupMenuGroup("G")
            .onAction(
                    ac -> {
                        doMarkDependencies(ac);
                    }
            )
            .build();
    }

    private String[] getDynamicLibraryNames(FSBFileNode node) {
        try (RefdFile file = FileSystemService.getInstance().getRefdFile(node.getFSRL(), TaskMonitor.DUMMY)) {
            GFileSystem fs =  file.fsRef.getFilesystem();
            byte bytes[] = new byte[(int)file.file.getLength()];
            fs.getInputStream(file.file, TaskMonitor.DUMMY).read(bytes);
            ElfHeader elf = new ElfHeader(new ByteArrayProvider(bytes), null);
            elf.parse();
            return elf.getDynamicLibraryNames();
        } catch (Exception e) {
            FirmwarePlugin.log.error(e);
        }
        return null;
    }

    private FSBFileNode getTreeNode(GTreeModel model, GTreeNode parent, String name) {
        if (parent instanceof FSBFileNode && parent.toString().equals(name)) return (FSBFileNode)parent;
        for (int i = 0; i < model.getChildCount(parent); i++) {
            GTreeNode child = (GTreeNode)model.getChild(parent, i);
            child = getTreeNode(model, child, name);
            if (child != null) {
                return (FSBFileNode) child;
            }
        }
        return null;
    }

    private void doMarkDependencies(ActionContext ctx) {
        try {
            FSBNode[] nodes = (FSBNode[])ctx.getContextObject();
            FSBFileNode node = (FSBFileNode)nodes[0];
            HashMap<String, GTreeNode> deps = new HashMap<>();
            updateDependencies(deps, node);
            node.getTree().setSelectedNodes(deps.values());
        } catch (CancelledException ce) {
        }
    }

    private void updateDependencies(HashMap<String, GTreeNode> deps, FSBFileNode node) throws CancelledException {
        if (!deps.containsKey(node.toString())) {
            deps.put(node.toString(), node);
            String needs[] = getDynamicLibraryNames(node);
            if (needs != null) {
                GTreeModel model = node.getTree().getModel();
                GTreeNode root = (GTreeNode)model.getRoot();
                root.loadAll(TaskMonitor.DUMMY);
                FSBFileNode neededNode;
                for (String needed : needs) {
                    if ((neededNode = getTreeNode(model, root, needed)) != null) {
                        updateDependencies(deps, neededNode);
                    }
                }
            }
        }
    }

    private ToolOptions getOptions() {
        return tool.getOptions("Firmware plugin");
    }

    private File getDefaultProgramPath(String program) {
        String parents[] = new String[] { "/bin", "/usr/bin", "/usr/local/bin" };
        for (String p : parents) {
            File f = new File(p, program);
            if (f.exists()) {
                return f;
            }
        }
        return new File(parents[0], program);
    }

    private File getPath(String option) {
        ToolOptions options = getOptions();
        return options.getFile(option, (File)options.getDefaultValue(option));
    }

    public File getBinwalkPath() {
        return getPath(BINWALK_PATH);
    }

    public File getSasquatchPath() {
        return getPath(SASQUATCH_PATH);
    }
    private File getDefaultBinwalkPath() {
        return getDefaultProgramPath("binwalk");
    }

    private File getDefaultSasquatchPath() {
        return getDefaultProgramPath("sasquatch");
    }

    private void registerOptions() {
        String topic = getClass().getSimpleName();
        ToolOptions options = getOptions();
        if (!options.isRegistered(BINWALK_PATH))
            options.registerOption(
                    BINWALK_PATH,
                    getDefaultBinwalkPath(),
                    new HelpLocation(topic, "BinwalkPath"),
                    "Location of the `binwalk` program");
        if (!options.isRegistered(SASQUATCH_PATH))
            options.registerOption(
                    SASQUATCH_PATH,
                    getDefaultSasquatchPath(),
                    new HelpLocation(topic, "SasquatchPath"),
                    "Location of the `sasquatch` program");
    }
}
