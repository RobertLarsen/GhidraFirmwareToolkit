package firmware.ghidra;

import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.File;

import firmware.binwalk.Binwalk;
import firmware.binwalk.BinwalkAnalysis;

public class BinwalkFileSystemFactory implements GFileSystemFactoryByteProvider<BinwalkFileSystem>, GFileSystemProbeByteProvider {
    public BinwalkFileSystemFactory() {
    }

    private BinwalkAnalysis analyze(File container) throws IOException {
        BinwalkAnalysis analysis = null;
        FirmwarePlugin plugin = FirmwarePlugin.getInstance();
        //if (plugin != null) {
            Binwalk binwalk = new Binwalk(plugin.getBinwalkPath());
            analysis = binwalk.analyze(container);
        //}
        return analysis;
    }

    @Override
    public BinwalkFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {
        return new BinwalkFileSystem(targetFSRL, analyze(Util.getAsFile(byteProvider)));
    }

    private boolean isElf(ByteProvider provider) {
        try {
            new ElfHeader(provider, null);
            return true;
        } catch (Exception e) {
        }
        return false;
    }

    @Override
    public boolean probe(ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
        throws IOException, CancelledException {
        File file;
        monitor.setMessage("Binwalk analyzes " + byteProvider.getClass());
        if (isElf(byteProvider) == false) {
            if ((file = Util.getAsFile(byteProvider)) != null) {

                BinwalkAnalysis a = analyze(file);
                if (a.count() > 1 || (a.count() > 0 && a.get(0).getType().toUpperCase().equals("DATA") == false)) {
                    return true;
                }
            }
        }

        return false;
    }
}
