package firmware.ghidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Iterator;

import firmware.binwalk.BinwalkAnalysis;
import firmware.binwalk.BinwalkPart;

@FileSystemInfo(type = "binwalkfs", // ([a-z0-9]+ only)
		description = "Binwalk",
        factory = BinwalkFileSystemFactory.class)
public class BinwalkFileSystem implements GFileSystem {
	private FileSystemRefManager refManager;
    private FSRLRoot root;
    private FileSystemIndexHelper<BinwalkPart> fsIndexHelper;

    public BinwalkFileSystem(FSRLRoot root, BinwalkAnalysis analysis) {
        this.refManager = new FileSystemRefManager(this);
        this.root = root;
		this.fsIndexHelper = new FileSystemIndexHelper<>(this, root);
        int count = 0;
        for (Iterator<BinwalkPart> i = analysis.iterator(); i.hasNext(); i.next()) {
            count++;
        }

        int idx = 0;
        String fmt = "%0" + Integer.toString(count).length() + "d %s";
        for (BinwalkPart part : analysis) {
            fsIndexHelper.storeFile(String.format(fmt, ++idx, part.getType()), fsIndexHelper.getFileCount(), false, part.getSize(), part);
        }
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
        return Util.toByteProvider(getInputStream(file, monitor), file);
    }

    @Override
    public FSRLRoot getFSRL() {
        return root;
    }

    @Override
    public void close() {
        refManager.onClose();
        fsIndexHelper.clear();
    }

    @Override
    public int getFileCount() {
        return fsIndexHelper.getFileCount();
    }

    @Override
    public String getName() {
		return root.getContainer().getName();
    }

    @Override
    public InputStream getInputStream(GFile file, TaskMonitor monitor) throws IOException {
        BinwalkPart part = this.fsIndexHelper.getMetadata(file);
        return part == null ? null : new ByteArrayInputStream(part.getContent());
    }

    @Override
    public List<GFile> getListing(GFile file) {
        return this.fsIndexHelper.getListing(file);
    }

    @Override
    public FileSystemRefManager getRefManager() {
        return refManager;
    }

    @Override
    public boolean isClosed() {
        return this.fsIndexHelper.getFileCount() == 0;
    }

    @Override
    public boolean isStatic() {
        return true;
    }

    @Override
    public GFile lookup(String path) {
        return this.fsIndexHelper.lookup(path);
    }
}
