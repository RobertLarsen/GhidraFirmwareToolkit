package firmware.ghidra;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.bin.format.elf.ElfException;
import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;

import firmware.elf.CoreDump;

public class CoreDumpFileSystemFactory implements GFileSystemFactoryByteProvider<CoreDumpFileSystem>, GFileSystemProbeByteProvider {
    public CoreDumpFileSystemFactory() {
    }

    @Override
    public CoreDumpFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {
        CoreDumpFileSystem res = null;

        try {
            res = new CoreDumpFileSystem(targetFSRL, new CoreDump(byteProvider));
        } catch (ElfException e) {}

        return res;
    }

    @Override
    public boolean probe(ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
        throws IOException, CancelledException {
        boolean res = false;
        try {
            CoreDump dump = new CoreDump(byteProvider);
            res = true;
        } catch (Exception e) {}
        return res;
    }
}
