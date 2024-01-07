import idautils
import idc

# UNFINISHED! DO NOT RUN IN IDA!

def getInitList():
    # SegmentAdd
    initListAddress = -1
    initList = "Unknown:" + idaapi.get_file_type_name() + " , contact author!"
    for s in idautils.Segments():
        ####
        format = idaapi.get_file_type_name()
        formatShort = "File Format Probably not supported , contact author!"
        if format == "ELF64 for ARM64 (Shared object)":
            formatShort = "ELF"
        if format == "ELF for ARM (Shared object)":
            formatShort = "ELF"
        if format == "ELF for Intel 386 (Shared object)":  # movzx instead of pc ?
            formatShort = "ELF"
        if format == "Fat Mach-O file, 2. ARM64":
            formatShort = "Mach-O"
        if format == "Fat Mach-O file, 1. ARMv7":
            formatShort = "Mach-O"
        if format == "Mach-O file (EXECUTE). ARM64":
            formatShort = "Mach-O"
        # is there another , shorter way ?
        # print(ida.get_basic_file_type(ida.get_linput(0)))
        # print(format)
        ####
        # print idc.get_segm_name(s)
        #     ----Mach-O <-> ELF----
        #         HEADER <=> __ETC__PII2
        #         __data <=> .data
        # __mod_init_func <=> .init_array   => Initialization Function Table
        #                                     function to initialize the memory array
        # initList = "Unknown , contact author!"
        if formatShort == "ELF":
            initList = ".init_array"
        if formatShort == "Mach-O":
            initList = "__mod_init_func"
        ####
        if idc.get_segm_name(s) == initList:
            initListAddress = s
    # print('end')
    return initList, initListAddress


def main():
    initList, initListAddress = getInitList()
    if (initListAddress < 0):
        print(initList + ' not found!')
    else:
        # start magic search work!
        print(idc.get_segm_name(initListAddress))
        # hex
        print('%x-%x' % (idc.get_segm_start(initListAddress), idc.get_segm_end(initListAddress)))
        seg = initListAddress  # idc.SegByName('.init_array')
        addr = idc.get_segm_start(seg)  # idc.SegByBase(seg)
        # idc.GetSegmentAttr(addr, idc.SEGATTR_START)
        seg_st = idc.get_segm_start(seg)
        seg_en = idc.get_segm_end(seg)  # idc.GetSegmentAttr(addr, idc.SEGATTR_END)
        print('  ' + initList + ' = %08X - %08X' % (seg_st, seg_en))
        print(addr)
        count = 0
        stop = 0
        while addr < seg_en and stop == 0:
            funcaddr = idc.get_qword(addr)  # 64bit
            # funcaddr = idc.get_wide_dword(addr)#32bit
            # if funcaddr > 0:
            #    name = idc.Name(funcaddr) #idc.get_func_name(funcaddr)
            # 002CEAD2: sub_2CEA48 ??? = InitFunc_0
            print('    %08X: %s' % (funcaddr, idc.get_func_name(funcaddr)))
            # print('test',count)
            if count == 0:
                # print('count==0')
                printFunc(funcaddr)
                stop = 1
            count += 1
            addr += 4


def printFunc(cursor):
    functionName = idc.get_func_name(cursor)
    allowedToFindRef = 0
    for (startea, endea) in idautils.Chunks(cursor):
        # print("chunk")
        for head in idautils.Heads(startea, endea):
            # print("head")
            newcursor = head
            # print('%x' % newcursor, "-ono-:", '%s' % idc.GetDisasm(newcursor))
            mnem = idc.print_insn_mnem(newcursor)
            if mnem.lower() == "and":  # loc jump
                arg_to = idc.print_operand(newcursor, 0)  # X9
                arg_from = idc.print_operand(newcursor, 1)  # X8
                arg_2 = idc.print_operand(newcursor, 2)  ##0x7f
                if arg_2.lower() == "#0x7f":
                    print('%x' % newcursor, "-ono-:", '%s' % idc.GetDisasm(newcursor))
                    allowedToFindRef = 1
            if allowedToFindRef:
                if sum(1 for _ in idautils.DataRefsFrom(newcursor)) == 1:
                    for ref in idautils.DataRefsFrom(newcursor):
                        disasmLine = idc.GetDisasm(newcursor)
                        # if disasmLine.find("unk_") > -1: # also dword_
                        key_bytes: bytes = idc.get_bytes(ref, 127)  # 127 = 0x7f
                        string = str(key_bytes.hex())
                        print("data(for xor key) found on adress: (dec)", ref, "/(hex)", hex(ref))
                        print(string)
                        allowedToFindRef = 0
                        return string


if __name__ == '__main__':
    main()
