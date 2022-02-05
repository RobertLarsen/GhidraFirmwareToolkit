package firmware.ghidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.File;

import firmware.binwalk.Sasquatch;

public class SquashFSFileSystemFactory implements GFileSystemFactoryByteProvider<SquashFSFileSystem>, GFileSystemProbeByteProvider {
    private Sasquatch sasquatch;

    public SquashFSFileSystemFactory() throws IOException {
        this.sasquatch = new Sasquatch(FirmwarePlugin.getInstance().getSasquatchPath());
    }

    @Override
    public SquashFSFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {
        return new SquashFSFileSystem(targetFSRL, sasquatch, Util.getAsFile(byteProvider));
    }

    @Override
    public boolean probe(ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
        throws IOException, CancelledException {
        monitor.setMessage("Sasquatch analyzes " + byteProvider.getClass());
        File f;

        if ((f = Util.getAsFile(byteProvider)) != null) {
            return sasquatch.extract(f) != null;
        }

        return false;
    }
}
