package firmware.ghidra;

import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import firmware.fs.Regular;
import firmware.elf.CoreDump;

@FileSystemInfo(type = "coredumpfs", // ([a-z0-9]+ only)
		description = "CoreDump",
        factory = CoreDumpFileSystemFactory.class,
        priority = FileSystemInfo.PRIORITY_LOW)
public class CoreDumpFileSystem extends SimpleFSFileSystem {
    private CoreDump dump;

    protected CoreDumpFileSystem(FSRLRoot root, CoreDump dump) throws IOException {
        super(root, dump.getFilesystem());
        this.dump = dump;
    }

    protected InputStream getInputStream(Regular file, TaskMonitor monitor) throws IOException {
        return new ByteArrayInputStream(dump.getBytes(file));
    }
}

