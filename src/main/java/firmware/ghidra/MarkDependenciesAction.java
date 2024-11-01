package firmware.ghidra;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.plugins.fsbrowser.FSBActionContext;

import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.internal.GTreeModel;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.RefdFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.plugins.fsbrowser.FSBFileHandler;
import ghidra.plugins.fsbrowser.FSBFileHandlerContext;
import ghidra.plugins.fsbrowser.FSBFileNode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.HelpLocation;

import java.util.HashMap;
import java.util.List;

public class MarkDependenciesAction implements FSBFileHandler {
    private FSBFileHandlerContext context;

    @Override
    public void init(FSBFileHandlerContext context) {
        this.context = context;
    }

    @Override
    public List<DockingAction> createActions() {
        return List.of(new ActionBuilder("Mark Dependencies", context.plugin().getName())
                .withContext(FSBActionContext.class)
                .enabledWhen(ac -> ac.notBusy() && ac.getSelectedCount() == 1)
                .popupMenuPath("Mark Dependencies")
                .popupMenuGroup("F", "B")
                .helpLocation(new HelpLocation(context.plugin().getClass().getSimpleName(), "MultiFileFunctionality"))
                .onAction(ctx -> {
                    try {
                        FSBFileNode node = (FSBFileNode)ctx.getContextObject();
                        HashMap<String, GTreeNode> deps = new HashMap<>();
                        updateDependencies(deps, node);
                        node.getTree().setSelectedNodes(deps.values());
                    } catch (CancelledException ce) {
                    }
                })
                .build());
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
}
