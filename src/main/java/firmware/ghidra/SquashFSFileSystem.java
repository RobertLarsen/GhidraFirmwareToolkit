package firmware.ghidra;

import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import firmware.fs.Regular;
import firmware.binwalk.Sasquatch;

@FileSystemInfo(type = "squashfs", // ([a-z0-9]+ only)
		description = "SquashFS",
        factory = SquashFSFileSystemFactory.class)
public class SquashFSFileSystem extends SimpleFSFileSystem {
    private Sasquatch sasquatch;
    private File container;

    protected SquashFSFileSystem(FSRLRoot root, Sasquatch sasquatch, File container) throws IOException {
        super(root, sasquatch.extract(container));
        this.sasquatch = sasquatch;
        this.container = container;
    }

    protected InputStream getInputStream(Regular file, TaskMonitor monitor) throws IOException {
        return new ByteArrayInputStream(sasquatch.extract(container, file));
    }
}
