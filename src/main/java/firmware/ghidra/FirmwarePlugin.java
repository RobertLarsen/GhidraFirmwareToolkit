package firmware.ghidra;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.FileSystemBrowserService;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.MiscellaneousPluginPackage;
import ghidra.util.HelpLocation;
import java.io.File;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

@PluginInfo(
    status=PluginStatus.RELEASED,
    packageName=MiscellaneousPluginPackage.NAME,
    category=PluginCategoryNames.SUPPORT,
    shortDescription="Help analyzing firmware",
    description="Set of tools for working with firmware images",
    servicesRequired={ FileSystemBrowserService.class },
    servicesProvided={ FirmwareService.class }
)
public class FirmwarePlugin extends Plugin implements FrontEndable, FirmwareService {
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
        tool.addAction(new MarkDependenciesAction("Mark dependencies", this));
        tool.addAction(new FixupExternalsAction("Fixup Externals", getClass().getSimpleName(), tool));
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
