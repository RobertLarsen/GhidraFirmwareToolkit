package firmware.binwalk;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class Binwalk {
    private ExecutableWrapper binwalk;

    public Binwalk(File binwalkPath) throws FileNotFoundException {
        this.binwalk = new ExecutableWrapper(binwalkPath);
    }

    public Binwalk(String binwalkPath) throws FileNotFoundException {
        this(new File(binwalkPath));
    }

    public Binwalk() throws FileNotFoundException {
        this("/usr/bin/binwalk");
    }

    private static BinwalkAnalysis fixZipArchives(BinwalkAnalysis in) {
        BinwalkAnalysis out = new BinwalkAnalysis(in.getOwner(), in.getFirmware());
        Iterator<BinwalkPart> ite = in.iterator();
        while (ite.hasNext()) {
            BinwalkPart part = ite.next();
            if (part.getType().equals("Zip archive data")) {
                while (ite.hasNext()) {
                    BinwalkPart end = ite.next();
                    if (end.getType().equals("End of Zip archive")) {
                        out.add(part.getOffset(), end.getOffset() + end.getSize() - part.getOffset(), "Zip archive", "");
                        break;
                    }
                }
            } else {
                out.add(part);
            }
        }
        return out;
    }

    public BinwalkAnalysis analyze(File firmware) throws FileNotFoundException, IOException {
        if (!firmware.exists()) {
            throw new FileNotFoundException(firmware.getPath());
        }

        BinwalkAnalysis analysis = new BinwalkAnalysis(this, firmware);
        Pattern regex = Pattern.compile("^(\\d+)\\s+([0-9A-Fx]+)\\s+([^,]+), (.+)$");
        long offset = -1;
        String type = null;
        String additional = null;
        for (String line : binwalk.execute(firmware.getPath())) {
            Matcher m = regex.matcher(line);
            if (m.matches()) {
                long nextOffset = Long.parseLong(m.group(1));
                if (type != null) {
                    analysis.add(offset, nextOffset - offset, type, additional);
                }
                offset = nextOffset;
                type = m.group(3);
                additional = m.group(4);
            }
        }

        if (type != null) {
            analysis.add(offset, firmware.length() - offset, type, additional);
        }

        return fixZipArchives(analysis);
     }

    public BinwalkAnalysis analyze(String firmware) throws FileNotFoundException, IOException {
        return analyze(new File(firmware));
    }

    public static void main(String args[]) throws Exception {
        Binwalk b = new Binwalk();
        BinwalkAnalysis a = b.analyze(args.length == 0 ? "./firmwares/firmware.bin" : args[0]);
        for (BinwalkPart part : a) {
            System.out.println(part);
            if (part instanceof SquashFSBinwalkPart) {
                for (firmware.fs.File file : ((SquashFSBinwalkPart)part).extractFilesystem().getRoot()) {
                    System.out.println(file);
                }
            }
        }
    }
}
