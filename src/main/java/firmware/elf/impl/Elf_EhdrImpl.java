package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.StructField;
import firmware.elf.Elf_Ehdr;
import firmware.elf.Elf_Phdr;
import firmware.elf.Elf_Dyn;

import java.util.List;
import java.util.LinkedList;

public abstract class Elf_EhdrImpl extends StructImpl implements Elf_Ehdr {
    private final static int PT_DYNAMIC = 2;

    public Elf_EhdrImpl(BytesView view, StructField ... fields) {
        super(view, fields);
    }

    protected abstract Elf_Phdr createPhdr(BytesView view);
    protected abstract Elf_Dyn createDyn(BytesView view);

    public Elf_Phdr[] getPhdrs() {
        Elf_Phdr phdrs[] = new Elf_Phdr[e_phnum()];
        long phoff = e_phoff();

        for (int i = 0; i < phdrs.length; i++) {
            phdrs[i] = createPhdr(getView());
            phdrs[i].read((int)phoff);
            phoff += phdrs[i].getSize();
        }

        return phdrs;
    }

    public Elf_Dyn[] getDynamic() {
        Elf_Dyn res[] = null;
        List<Elf_Dyn> lst;

        for (Elf_Phdr phdr : getPhdrs()) {
            if (phdr.p_type() == PT_DYNAMIC) {
                lst = new LinkedList<>();
                long offset = phdr.p_offset();

                while (true) {
                    Elf_Dyn dyn = createDyn(getView());
                    lst.add(dyn);
                    dyn.read((int)offset);
                    offset += dyn.getSize();
                    if (dyn.d_tag() == Elf_Dyn.DT_NULL) {
                        break;
                    }
                }

                res = new Elf_Dyn[lst.size()];
                int i = 0;
                for (Elf_Dyn d : lst) {
                    res[i++] = d;
                }
                break;
            }
        }

        return res == null ? new Elf_Dyn[0] : res;
    }
}
