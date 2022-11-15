package firmware.ghidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import firmware.fs.*;

abstract class SimpleFSFileSystem implements GFileSystem {
	private FileSystemRefManager refManager;
    private FSRLRoot root;
    private FileSystemIndexHelper<firmware.fs.File> fsIndexHelper;
    private Filesystem fs;

    protected SimpleFSFileSystem(FSRLRoot root, Filesystem fs) {
        this.root = root;
        this.fs = fs;
        this.fsIndexHelper = new FileSystemIndexHelper<>(this, root);
        this.refManager = new FileSystemRefManager(this);

        Directory fsRoot = fs.getRoot();
        populate(fsRoot, null);
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
        return Util.toByteProvider(getInputStream(file, monitor), file);
    }

    private void populate(Directory dir, GFile ghidraDir) {
        GFile created;
        for (firmware.fs.File child : dir) {
            if (ghidraDir == null) {
                created = this.fsIndexHelper.storeFile(child.getName(), this.fsIndexHelper.getFileCount(), true, -1, child);

            } else {
                File resolved = child instanceof Symlink ? ((Symlink)child).resolveDeep() : null;
                created = this.fsIndexHelper.storeFileWithParent(child.getName(), ghidraDir, this.fsIndexHelper.getFileCount(), child instanceof Directory, child instanceof Regular ? ((Regular)child).getSize() : resolved instanceof Regular ? ((Regular)resolved).getSize() : -1, child);
            }
            if (child instanceof Directory) {
                populate((Directory)child, created);
            }
        }
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
        firmware.fs.File f = this.fsIndexHelper.getMetadata(file);
        if (f != null && f instanceof Symlink) {
            f = fs.resolveDeep((Symlink)f);
        }
        return f == null || (f instanceof Regular == false) ? null : getInputStream((Regular)f, monitor);
    }

    protected abstract InputStream getInputStream(Regular file, TaskMonitor monitor) throws IOException;

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
