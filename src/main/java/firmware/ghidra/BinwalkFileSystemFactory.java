package firmware.ghidra;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;

import firmware.binwalk.Binwalk;
import firmware.binwalk.BinwalkAnalysis;

public class BinwalkFileSystemFactory implements GFileSystemFactoryFull<BinwalkFileSystem>, GFileSystemProbeFull {
    public BinwalkFileSystemFactory() {
    }

    private BinwalkAnalysis analyze(File container) throws IOException {
        BinwalkAnalysis analysis = null;
        FirmwarePlugin plugin = FirmwarePlugin.getInstance();
        if (plugin != null) {
            Binwalk binwalk = new Binwalk(plugin.getBinwalkPath());
            analysis = binwalk.analyze(container);
        }
        return analysis;
    }

    @Override
    public BinwalkFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider byteProvider, File containerFile, FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {
        return new BinwalkFileSystem(targetFSRL, analyze(containerFile));
    }

    public static void log(String log) {
        try {
            FileOutputStream out = new FileOutputStream("/tmp/binwalkfs.log", true);
            out.write(log.getBytes("utf-8"));
            out.write("\n".getBytes("utf-8"));
            out.close();
        } catch (Exception e) {
        }
    }

    private boolean isElf(ByteProvider provider) {
        try {
            ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
            return true;
        } catch (Exception e) {
        }
        return false;
    }

    @Override
    public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
            FileSystemService fsService, TaskMonitor monitor)
        throws IOException, CancelledException {
        monitor.setMessage("Binwalk analyzes " + containerFile);

        return isElf(byteProvider) == false && analyze(containerFile).count() > 1;
    }
}
