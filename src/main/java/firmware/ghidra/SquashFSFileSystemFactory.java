package firmware.ghidra;

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

import firmware.binwalk.Sasquatch;

public class SquashFSFileSystemFactory implements GFileSystemFactoryFull<SquashFSFileSystem>, GFileSystemProbeFull {
    private Sasquatch sasquatch;

    public SquashFSFileSystemFactory() throws IOException {
        this.sasquatch = new Sasquatch(FirmwarePlugin.getInstance().getSasquatchPath());
    }

    @Override
    public SquashFSFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider byteProvider, File containerFile, FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {
        return new SquashFSFileSystem(targetFSRL, sasquatch, containerFile);
    }

    @Override
    public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
            FileSystemService fsService, TaskMonitor monitor)
        throws IOException, CancelledException {
        monitor.setMessage("Sasquatch analyzes " + containerFile);

        return sasquatch.extract(containerFile) != null;
    }
}
