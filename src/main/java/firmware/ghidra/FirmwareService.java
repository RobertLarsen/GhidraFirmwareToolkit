package firmware.ghidra;

import ghidra.framework.plugintool.ServiceInfo;
import java.io.File;

@ServiceInfo(
    defaultProvider=FirmwarePlugin.class,
    description="API for working with firmware"
)
public interface FirmwareService {
    public File getBinwalkPath();

    public File getSasquatchPath();
}
