package firmware.elf;

import java.io.InputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.LinkedList;
import java.util.Calendar;

import firmware.fs.Filesystem;
import firmware.fs.Directory;
import firmware.fs.File;
import firmware.fs.Regular;
import firmware.fs.FileMode;

import firmware.elf.impl.Elf64_Ehdr;
import firmware.elf.impl.Elf32_Ehdr;

import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import ghidra.formats.gfilesystem.LocalFileSystem;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.FSRL;
import generic.continues.RethrowContinuesFactory;

public class CoreDump {
    private final static int PT_LOAD = 1;
    private final static int PT_NOTE = 4;

    private enum ElfClass {
        CLASSNONE, CLASS32, CLASS64
    };

    private class ElfNote {
        public final static int NT_PRSTATUS = 1;
        public final static int NT_PRPSINFO	= 3;
        public final static int NT_SIGINFO = 0x53494749;
        public final static int NT_AUXV = 6;
        public final static int NT_FILE = 0x46494c45;
        public final static int NT_FPREGSET	= 2;
        public final static int NT_X86_XSTATE = 0x202;

        private String name;
        private long descsz;

        public ElfNote(String name, long descsz) {
            this.name = name;
            this.descsz = descsz;
        }

        public String toString() {
            return String.format("Name: %s  Desc len: %d - %s", name, descsz, getClass().getSimpleName());
        }
    }

    private class PrStatusElfNote  extends ElfNote {
        public PrStatusElfNote (String name, long descsz, BinaryReader reader) {
            super(name, descsz);
            reader.setPointerIndex(reader.getPointerIndex() + descsz);
        }
    }

    private class PrPsInfoElfNote  extends ElfNote {
        public PrPsInfoElfNote (String name, long descsz, BinaryReader reader) {
            super(name, descsz);
            reader.setPointerIndex(reader.getPointerIndex() + descsz);
        }
    }

    private class SigInfoElfNote  extends ElfNote {
        public SigInfoElfNote (String name, long descsz, BinaryReader reader) {
            super(name, descsz);
            reader.setPointerIndex(reader.getPointerIndex() + descsz);
        }
    }

    private class AuxvElfNote  extends ElfNote {
        public AuxvElfNote (String name, long descsz, BinaryReader reader) {
            super(name, descsz);
            reader.setPointerIndex(reader.getPointerIndex() + descsz);
        }
    }

    private class FileMapping {
        private String path;
        private long start;
        private long end;
        private long offset;

        public FileMapping(String path, long start, long end, long offset) {
            this.path = path;
            this.start = start;
            this.end = end;
            this.offset = offset;
        }

        public String getPath() {
            return path;
        }

        public long getStart() {
            return start;
        }

        public long getEnd() {
            return end;
        }

        public long getSize() {
            return end - start;
        }

        public long getOffset() {
            return offset;
        }

        public String toString() {
            return String.format("0x%x - 0x%x Offset: 0x%x", start, end, offset);
        }
    }

    private class FileMappingIterator implements Iterator<FileMapping> {
        private BinaryReader reader;
        private long count;
        private long pageSize;
        private long mappingIdx;
        private long stringIdx;
        private long i;

        public FileMappingIterator(BinaryReader reader, long count, long pageSize, long mappingIdx, long stringIdx) {
            i = 0;
            this.reader = reader;
            this.count = count;
            this.pageSize = pageSize;
            this.mappingIdx = mappingIdx;
            this.stringIdx = stringIdx;
        }

        public boolean hasNext() {
            return i < count;
        }

        public FileMapping next() {
            FileMapping mapping = null;
            try {
                reader.setPointerIndex(mappingIdx);
                long start = reader.readNextLong(),
                     end = reader.readNextLong(),
                     offset = reader.readNextLong();
                mappingIdx = reader.getPointerIndex();

                reader.setPointerIndex(stringIdx);
                String path = reader.readNextAsciiString();
                stringIdx = reader.getPointerIndex();
                i++;
                mapping = new FileMapping(path, start, end, offset * pageSize);
            } catch (IOException e) {
            }

            return mapping;
        }
    }

    private class FilePart {
        private FileMapping mapping;
        private ElfProgramHeader load;

        public FilePart(FileMapping mapping, ElfProgramHeader load) {
            this.mapping = mapping;
            this.load = load;
        }

        public FileMapping getMapping() {
            return mapping;
        }

        public ElfProgramHeader getLoad() {
            return load;
        }
    }

    private class FileElfNote extends ElfNote implements Iterable<FileMapping> {
        private long count;
        private long pageSize;
        private long stringStartIdx;
        private long mappingStartIdx;
        private BinaryReader reader;

        public FileElfNote(String name, long descsz, BinaryReader reader) {
            super(name, descsz);
            try {
                this.reader = reader;
                long currentIdx = reader.getPointerIndex();
                count = reader.readNextLong();
                pageSize = reader.readNextLong();

                stringStartIdx = reader.getPointerIndex() + count * 24;
                mappingStartIdx = reader.getPointerIndex();
                reader.setPointerIndex(currentIdx + descsz);
            } catch (IOException e) {
            }
        }

        public Iterator<FileMapping> iterator() {
            return new FileMappingIterator(reader, count, pageSize, mappingStartIdx, stringStartIdx);
        }
    }

    private class FPRegSetElfNote  extends ElfNote {
        public FPRegSetElfNote (String name, long descsz, BinaryReader reader) {
            super(name, descsz);
            reader.setPointerIndex(reader.getPointerIndex() + descsz);
        }
    }

    private class X86XStateElfNote  extends ElfNote {
        public X86XStateElfNote (String name, long descsz, BinaryReader reader) {
            super(name, descsz);
            reader.setPointerIndex(reader.getPointerIndex() + descsz);
        }
    }

    private class ElfNoteSection implements Iterator<ElfNote> {
        private ElfProgramHeader header;
        private long end;
        private BinaryReader reader;
        private ElfNote note;

        public ElfNoteSection(ElfProgramHeader header) {
            this.header = header;
            long offset = header.getOffset(),
                 size = header.getFileSize();

            end = offset + size;
            reader = this.header.getReader();
            reader.setPointerIndex(offset);
            note = null;
        }

        public boolean hasNext() {
            return reader.getPointerIndex() < end && (note = readNext()) != null;
        }

        private ElfNote readNote(long namesz, long descsz, long type) throws IOException {
            ElfNote res = null;
            String name = namesz > 0 ? reader.readNextAsciiString((int)namesz) : "";
            reader.setPointerIndex((reader.getPointerIndex() + 3) & ~3);
            reader.setPointerIndex((reader.getPointerIndex() + 3) & ~3);
            switch ((int)type) {
                case ElfNote.NT_PRSTATUS:
                    res = new PrStatusElfNote(name, descsz, reader);
                    break;
                case ElfNote.NT_PRPSINFO:
                    res = new PrPsInfoElfNote(name, descsz, reader);
                    break;
                case ElfNote.NT_SIGINFO:
                    res = new SigInfoElfNote(name, descsz, reader);
                    break;
                case ElfNote.NT_AUXV:
                    res = new AuxvElfNote(name, descsz, reader);
                    break;
                case ElfNote.NT_FILE:
                    res = new FileElfNote(name, descsz, reader);
                    break;
                case ElfNote.NT_FPREGSET:
                    res = new FPRegSetElfNote(name, descsz, reader);
                    break;
                case ElfNote.NT_X86_XSTATE:
                    res = new X86XStateElfNote(name, descsz, reader);
                    break;
                default:
                    reader.setPointerIndex(reader.getPointerIndex() + ((descsz + 3) & ~3));
                    res = new ElfNote(name, descsz);
                    break;
            }
            reader.setPointerIndex((reader.getPointerIndex() + 3) & ~3);

            return res;
        }

        public ElfNote readNext() {
            ElfNote n = null;
            try {
                n = readNote(reader.readNextUnsignedInt(), reader.readNextUnsignedInt(), reader.readNextUnsignedInt());
            } catch (IOException e) {}
            return n;
        }

        public ElfNote next() {
            return note;
        }
    }

    private interface Matcher<T> {
        public boolean matches(T obj);
    }

    private class ElfProgramHeaderIterator implements Iterator<ElfProgramHeader> {
        private Matcher<ElfProgramHeader> matcher;
        private ElfProgramHeader headers[];
        private int index;
        public ElfProgramHeaderIterator(ElfHeader ehdr, Matcher<ElfProgramHeader> matcher) {
            this.headers = ehdr.getProgramHeaders();
            this.matcher = matcher;
            this.index = -1;
            this.findNext();
        }

        private void findNext() {
            while ((++this.index) < headers.length) {
                if (matcher.matches(this.headers[this.index])) {
                    break;
                }
            }
        }

        public boolean hasNext() {
            return this.index < this.headers.length;
        }

        public ElfProgramHeader next() {
            ElfProgramHeader h = null;
            if (hasNext()) {
                h = this.headers[this.index];
                findNext();
            }
            return h;
        }
    }

    private ElfHeader ehdr;
    private Filesystem filesystem;
    private Map<String,List<FilePart>> files;

    public CoreDump(ByteProvider provider, TaskMonitor monitor) throws IOException, CancelledException, ElfException  {
        set(provider, monitor);
    }

    public CoreDump(ByteProvider provider) throws IOException, CancelledException, ElfException  {
        this(provider, TaskMonitor.dummyIfNull(null));
    }

    public CoreDump(java.io.File file, TaskMonitor monitor) throws IOException, CancelledException, ElfException  {
        String abs = file.getAbsolutePath();
        GFile gfile = LocalFileSystem.makeGlobalRootFS().lookup(abs);
        if (gfile == null) {
            throw new FileNotFoundException(abs);
        }
        this.set(gfile, monitor);
    }

    public CoreDump(java.io.File file) throws IOException, CancelledException, ElfException  {
        this(file, TaskMonitor.dummyIfNull(null));
    }

    public CoreDump(String path, TaskMonitor monitor) throws IOException, CancelledException, ElfException  {
        this(new java.io.File(path), monitor);
    }

    public CoreDump(String path) throws IOException, CancelledException, ElfException  {
        this(path, TaskMonitor.dummyIfNull(null));
    }

    private void set(GFile file, TaskMonitor monitor) throws IOException, CancelledException, ElfException  {
        set(file.getFilesystem().getByteProvider(file, monitor), monitor);
    }

    private void set(ByteProvider provider, TaskMonitor monitor) throws IOException, ElfException {
        this.ehdr = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
        if (this.ehdr.e_type() != ElfConstants.ET_CORE) {
            throw new ElfException("Wrong ELF type: " + this.ehdr.e_type());
        }
        this.ehdr.parse();
        this.filesystem = null;
        this.files = null;
    }

    private ElfNoteSection getNoteSection() {
        for (ElfProgramHeader hdr : ehdr.getProgramHeaders()) {
            // PT_NOTE = 4
            if (hdr.getType() == PT_NOTE) {
                return new ElfNoteSection(hdr);
            }
        }
        return null;
    }

    public Filesystem getFilesystem() {
        if (this.filesystem == null) {
            files = new HashMap<>();
            Map<Long,ElfProgramHeader> loads = new HashMap<>();

            // First find all PT_LOAD headers
            for (ElfProgramHeader h : ehdr.getProgramHeaders()) {
                if (h.getType() == PT_LOAD) {
                    loads.put(h.getVirtualAddress(), h);
                }
            }

            // Find file note
            FileElfNote fileNote = null;
            for (Iterator<ElfNote> i = getNoteSection(); i.hasNext(); ) {
                ElfNote note = i.next();
                if (note instanceof FileElfNote) {
                    fileNote = (FileElfNote)note;
                }
            }

            // Now find all file mappings
            if (fileNote != null) {
                for (FileMapping mapping : fileNote) {
                    ElfProgramHeader load = loads.get(mapping.getStart());
                    if (load != null) {
                        if (files.containsKey(mapping.getPath()) == false) {
                            files.put(mapping.getPath(), new LinkedList<>());
                        }
                        files.get(mapping.getPath()).add(new FilePart(mapping, load));
                    }
                }
            }

            Calendar now = Calendar.getInstance();
            filesystem = new Filesystem(new Directory("", new FileMode(0777), "root", "root", now, 0));

            for (Map.Entry<String,List<FilePart>> entry : files.entrySet()) {
                add(now, entry.getKey(), entry.getValue());
            }

        }
        return filesystem;
    }

    private void fixElf(BytesView view, long base) {
        ElfClass elfClass = (view.getByteAt(4) == 1 ? ElfClass.CLASS32 : ElfClass.CLASS64);
        view.setEndian(view.getByteAt(5) == 1 ? BytesView.Endian.LITTLE : BytesView.Endian.BIG);
        Elf_Ehdr ehdr = elfClass == ElfClass.CLASS32 ? new Elf32_Ehdr(view) : new Elf64_Ehdr(view);
        ehdr.read(0);
        ehdr.e_shoff(0);
        ehdr.e_shnum(0);
        ehdr.e_shentsize(0);
        ehdr.e_shstrndx(0);

        for (Elf_Dyn dyn : ehdr.getDynamic()) {
            switch ((int)dyn.d_tag()) {
                case Elf_Dyn.DT_GNU_HASH:
                case Elf_Dyn.DT_STRTAB:
                case Elf_Dyn.DT_SYMTAB:
                case Elf_Dyn.DT_PLTGOT:
                case Elf_Dyn.DT_JMPREL:
                case Elf_Dyn.DT_RELA:
                case Elf_Dyn.DT_VERSYM:
                    dyn.d_val(dyn.d_val() - base);
                    break;
            }
        }
    }

    private long lowestVirtualAddress(List<FilePart> content) {
        long addr = Long.MAX_VALUE;
        for (FilePart part : content) {
            addr = Math.min(addr, part.getLoad().getVirtualAddress());
        }
        return addr;
    }

    public byte[] getBytes(Regular file) throws IOException {
        byte bytes[] = null;
        BinaryReader reader = ehdr.getReader();

        List<FilePart> content = files.get(file.getAbsolutePath());
        if (content != null) {
            bytes = new byte[(int)fileSize(content)];
            long base = Long.MAX_VALUE;
            for (FilePart part : content) {
                ElfProgramHeader phdr = part.getLoad();
                base = Math.min(base, phdr.getVirtualAddress());
                System.out.println(String.format("V addr: 0x%x  Off: 0x%x  File size: 0x%x Mem size: 0x%x - %s", phdr.getVirtualAddress(), phdr.getOffset(), phdr.getFileSize(), phdr.getMemorySize(), part.getMapping().toString()));
                byte data[] = reader.readByteArray((int)phdr.getOffset(), (int)phdr.getMemorySize());
                System.arraycopy(data, 0, bytes, (int)part.getMapping().getOffset(), (int)part.getMapping().getSize());
            }
            BytesView view = new BytesView(bytes, BytesView.Endian.BIG);


            if (view.getUnsignedIntAt(0) == 0x7f454c46) {
                // Likely an elf. Fix it!
                try {
                    fixElf(view, lowestVirtualAddress(content));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            new FileOutputStream("/home/user/code/GhidraFirmwareToolkit/" + file.getName()).write(bytes);
        }

        return bytes;
    }

    private void add(Calendar c, String path, List<FilePart> content) {
        Directory d = ensure(c, Filesystem.dirname(path));
        d.add(new Regular(d, Filesystem.basename(path), new FileMode(0777), "root", "root", c, fileSize(content)));
    }

    private long fileSize(List<FilePart> content) {
        long size = 0;
        for (FilePart part : content) {
            FileMapping m = part.getMapping();
            size = Math.max(size, m.getSize() + m.getOffset());
        }
        return size;
    }

    private Directory ensure(Calendar c, String path) {
        String parentPath = Filesystem.dirname(path),
               basename = Filesystem.basename(path);
        Directory dir = null;

        if (parentPath == null) {
            dir = filesystem.getRoot();
        } else {
            Directory parent = ensure(c, parentPath);
            dir = (Directory)parent.get(basename);
            if (dir == null) {
                dir = new Directory(parent, basename, new FileMode(0777), "root", "root", c, 0);
                parent.add(dir);
            }
        }

        return dir;
    }

    public String toString() {
        return ehdr.toString();
    }

    public static void main(String args[]) throws IOException, CancelledException, ElfException  {
        LocalFileSystem fs = LocalFileSystem.makeGlobalRootFS();
        for (String path : args) {
            CoreDump dump = new CoreDump(path);
            recurse(dump, dump.getFilesystem().getRoot());
        }
    }

    private static void recurse(CoreDump dump, Directory d) {
        for (File f : d) {
            if (f instanceof Directory) {
                recurse(dump, (Directory)f);
            } else {
                if (f.getName().equals("analyze.cpython-310-x86_64-linux-gnu.so"))
                try {
                    dump.getBytes((Regular)f);
                } catch (Exception e) {}
            }
        }
    }
}
