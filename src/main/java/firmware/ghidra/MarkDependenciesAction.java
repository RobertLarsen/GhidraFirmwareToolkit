package firmware.ghidra;

import docking.ActionContext;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.internal.GTreeModel;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.RefdFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.plugins.fsbrowser.FSBAction;
import ghidra.plugins.fsbrowser.FSBActionContext;
import ghidra.plugins.fsbrowser.FSBFileNode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.HelpLocation;

import java.util.HashMap;

public class MarkDependenciesAction extends FSBAction {
    public MarkDependenciesAction(String actionName, Plugin plugin) {
        super(actionName, plugin);
        setEnabled(true);
        setHelpLocation(new HelpLocation(plugin.getClass().getSimpleName(), "MultiFileFunctionality"));
        setPopupMenuData(new MenuData(new String[] { actionName }, null, "I"));
    }

    @Override
    public void actionPerformed(ActionContext ctx) {
        try {
            FSBFileNode node = (FSBFileNode)ctx.getContextObject();
            HashMap<String, GTreeNode> deps = new HashMap<>();
            updateDependencies(deps, node);
            node.getTree().setSelectedNodes(deps.values());
        } catch (CancelledException ce) {
        }
    }

    @Override
    public boolean isEnabledForContext(ActionContext ctx) {
        return ctx instanceof FSBActionContext && ctx.getContextObject() instanceof FSBFileNode;
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
