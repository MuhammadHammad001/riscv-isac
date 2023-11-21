import re
import riscv_isac.plugins as plugins
import riscv_isac.plugins. specification as spec
from riscv_isac.InstructionObject import instructionObject
from riscv_isac.log import logger

class c_sail(spec.ParserSpec):

    @plugins.parserHookImpl
    def setup(self, trace, arch):
        self.trace = trace
        self.arch = arch
        if arch[1] == 32:
            logger.warn('FLEN is set to 32. Commit values in the log will be terminated to 32 bits \
irrespective of their original size.')

    instr_pattern_c_sail= re.compile(
        '\[\d*\]\s\[(?P<mode>.*?)\]:\s(?P<addr>[0-9xABCDEF]+)\s\((?P<instr>[0-9xABCDEF]+)\)\s*(?P<mnemonic>.*)')
    instr_pattern_c_sail_regt_reg_val = re.compile('(?P<regt>[xf])(?P<reg>[\d]+)\s<-\s(?P<val>[0-9xABCDEF]+)')
    instr_pattern_c_sail_csr_reg_val = re.compile('(?P<CSR>CSR|clint::tick)\s(?P<reg>[a-z0-9]+)\s(.*?)\s(?P<val>[0-9xABCDEF]+)(?:\s\(input:\s(?P<input_val>[0-9xABCDEF]+)\))?')
    instr_pattern_c_sail_mem_val = re.compile('mem\[(?P<addr>[0-9xABCDEF]+)\]\s<-\s(?P<val>[0-9xABCDEF]+)')
    def extractInstruction(self, line):
        instr_pattern = self.instr_pattern_c_sail
        re_search = instr_pattern.search(line)
        if re_search is not None:
            return int(re_search.group('instr'), 16),re_search.group('mnemonic'),re_search.group('mode')
        else:
            return None, None, None

    def extractAddress(self, line):
        instr_pattern = self.instr_pattern_c_sail
        re_search = instr_pattern.search(line)
        if re_search is not None:
            return int(re_search.group('addr'), 16)
        else:
            return 0

    def extractRegisterCommitVal(self, line):
        instr_pattern = self.instr_pattern_c_sail_regt_reg_val
        re_search = instr_pattern.search(line)
        if re_search is not None:
            rtype = re_search.group('regt')
            cval = re_search.group('val')
            if rtype =='f' and self.arch[1] == 32:
                cval = cval[0:2]+cval[-8:]
            return (rtype, re_search.group('reg'), cval)
        else:
            return None

    def extractCsrCommitVal(self, line):
        instr_pattern = self.instr_pattern_c_sail_csr_reg_val
        csr_commit = re.findall(instr_pattern,line)
        if (len(csr_commit)==0):
            return None
        else:
            return csr_commit

    def extractMemVal(self, line):
        instr_pattern = self.instr_pattern_c_sail_mem_val
        mem_val = re.findall(instr_pattern, line)
        if(len(mem_val) == 0):
            return None
        else:
            return mem_val
    def extractVirtualMemory(self, line):
        mem_r_pattern = re.compile(r'mem\[R,([0-9xABCDEF]+)\] -> 0x([0-9xABCDEF]+)')
        mem_x_pattern = re.compile(r'mem\[X,([0-9xABCDEF]+)\] -> 0x([0-9xABCDEF]+)')
        mem_depa_pattern = re.compile(r'mem\[([0-9xABCDEF]+)\]')
        instr_pattern_c_sail = self.instr_pattern_c_sail
        match = instr_pattern_c_sail.search(line)
        iptw_level_4, iptw_level_3, iptw_level_2, iptw_level_1, iptw_level_0 = (None, ) * 5
        dptw_level_4, dptw_level_3, dptw_level_2, dptw_level_1, dptw_level_0 = (None, ) * 5
        depa=None
        ieva=None
        ieva_align=None
        depa_align=None
        iepa=None
        iepa_align=None
        if match:
            # Split the line based on the match
            line_part1, line_part2 = line.split(match.group(0), 1)
            iptw=(mem_r_pattern.findall(line_part1))
            dptw=(mem_r_pattern.findall(line_part2))
            iepa_list=(mem_x_pattern.findall(line_part1))
            ieva = int(match.group('addr'),16)
            iepa_align, ieva_align = 0,0
            if iptw is not None:
                size_iptw=len(iptw)
                len_iptw =size_iptw
                for i in range(len_iptw):
                    globals()[f"iptw_level_{i}"] = int(iptw[size_iptw-1][0],16)
                    size_iptw = size_iptw -1
            if dptw is not None:
                if "lw" in match.group('mnemonic'):
                    depa=dptw.pop()
                    depa=int(depa[0],16)
                else:
                    depa_list=mem_depa_pattern.findall(line_part2)
                    if len(depa_list) != 0:
                        depa=int(depa_list[0],16)
                size_dptw=len(dptw)
                len_dptw =size_dptw
                for i in range(len_dptw):
                    globals()[f"dptw_level_{i}"] = int(dptw[size_dptw-1][0],16)
                    size_dptw = size_dptw -1
            if len(iepa_list) != 0:
                iepa = int(iepa_list[0][0], 16)
            if ieva is not None:
                if ieva & 0b11 == 0:
                    ieva_align =1
            if iepa is not None:
                if iepa & 0b11 == 0:
                    iepa_align =1
            if depa is not None:
                if depa & 0b11 == 0:
                    depa_align =1
        return (iptw_level_4, iptw_level_3, iptw_level_2, iptw_level_1, iptw_level_0,
                dptw_level_4, dptw_level_3, dptw_level_2, dptw_level_1, dptw_level_0,
                depa,
                ieva,
                iepa,
                ieva_align,
                iepa_align,
                depa_align)

    @plugins.parserHookImpl
    def __iter__(self):
        with open(self.trace) as fp:
            content = fp.read()
        instructions = content.split('\n\n')
        for line in instructions:
            instr, mnemonic, mode = self.extractInstruction(line)
            addr = self.extractAddress(line)
            reg_commit = self.extractRegisterCommitVal(line)
            csr_commit = self.extractCsrCommitVal(line)
            mem_val = self.extractMemVal(line)
            (iptw_level_4, iptw_level_3, iptw_level_2, iptw_level_1, iptw_level_0,
                dptw_level_4, dptw_level_3, dptw_level_2, dptw_level_1, dptw_level_0,
                depa,
                ieva,
                iepa,
                ieva_align,
                iepa_align,
                depa_align ) = self.extractVirtualMemory(line)
            instrObj = instructionObject(instr, 'None', addr, reg_commit = reg_commit, csr_commit = csr_commit, mem_val = mem_val, mnemonic = mnemonic, mode=mode,
                                        iptw_level_4=iptw_level_4, iptw_level_3=iptw_level_3, iptw_level_2=iptw_level_2, iptw_level_1=iptw_level_1, iptw_level_0=iptw_level_0,
                                        dptw_level_4=dptw_level_4, dptw_level_3=dptw_level_3, dptw_level_2=dptw_level_2, dptw_level_1=dptw_level_1, dptw_level_0=dptw_level_0,
                                        depa=depa, ieva=ieva, iepa=iepa, ieva_align=ieva_align, iepa_align=iepa_align, depa_align=depa_align)
            yield instrObj
