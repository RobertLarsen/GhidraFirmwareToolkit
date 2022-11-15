package firmware.ghidra;

import docking.action.MenuData;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.util.ELFExternalSymbolResolver;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.util.LinkedList;
import java.util.List;
import ghidra.util.HelpLocation;
import ghidra.framework.plugintool.PluginTool;

public class FixupExternalsAction extends FrontendProjectTreeAction {
    private PluginTool tool;

    public FixupExternalsAction(String name, String owner, PluginTool tool) {
        super(name, owner);
        this.tool = tool;
        setPopupMenuData(new MenuData(new String[] { name }, "Language"));
        setEnabled(true);
        setHelpLocation(new HelpLocation(owner, "FixExternals"));
    }

    @Override
    public void actionPerformed(ProjectDataContext context) {
        DomainFolder root = context.getSelectedFolders().get(0);
        List<DomainFile> allFiles = getFilesUnder(root, Program.class);
        int count = 0;
        for (DomainFile file : allFiles) {
            count += fixupExternals(file, allFiles);
        }
        Msg.showInfo(this, tool.getToolFrame(), "Externals Fixed", "Fixed " + count + " external location" + (count == 1 ? "" : "s"));
    }

    @Override
    protected boolean isAddToPopup(ProjectDataContext context) {
        return context.getFileCount() == 0 && context.getFolderCount() == 1;
    }

    private int fixupExternals(DomainFile file, List<DomainFile> allFiles) {
        int count = 0;
        try {
            Program program = (Program)file.getDomainObject(this, true, true, TaskMonitor.DUMMY);
            count += fixupExternals(file, program, allFiles);
            MessageLog log = new MessageLog();
            ELFExternalSymbolResolver.fixUnresolvedExternalSymbols(program, false, log, TaskMonitor.DUMMY);
            program.save("Updated Externals", TaskMonitor.DUMMY);
            program.release(this);
        } catch (Exception e) {
            FirmwarePlugin.log.error(e);
        }
        return count;
    }

    private int fixupExternals(DomainFile file, Program program, List<DomainFile> allFiles) throws InvalidInputException {
        int count = 0;
        ExternalManager externalManager = program.getExternalManager();
        int transactionId = program.startTransaction("Update Externals");
        for (String name : externalManager.getExternalLibraryNames()) {
            Library lib = externalManager.getExternalLibrary(name);
            if (lib.getAssociatedProgramPath() == null) {
                DomainFile external = findNamedFile(allFiles, name);
                if (external != null) {
                    externalManager.setExternalPath(lib.getName(true), external.getPathname(), false);
                    count++;
                }
            }
        }
        program.endTransaction(transactionId, true);
        return count;
    }

    private DomainFile findNamedFile(List<DomainFile> allFiles, String name) {
        for (DomainFile f : allFiles) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    private List<DomainFile> getFilesUnder(DomainFolder folder, Class<? extends DomainObject> domainObjectClass) {
        return getFilesUnder(folder, domainObjectClass, new LinkedList<>());

    }

    private List<DomainFile> getFilesUnder(DomainFolder folder, Class<? extends DomainObject> domainObjectClass, List<DomainFile> result) {
        for (DomainFile child : folder.getFiles()) {
            if (domainObjectClass.isAssignableFrom(child.getDomainObjectClass())) {
                result.add(child);
            }
        }
        for (DomainFolder child : folder.getFolders()) {
            getFilesUnder(child, domainObjectClass, result);
        }
        return result;
    }
}
