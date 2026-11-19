from dataclasses import dataclass,field
from sympy import symbols, simplify, solve, Lt, Eq, Gt
import sys
import struct
from utils import *
import time 
from structures import *

class Emulator:
    def __init__(self, arch, mode, debugFile=None, debug=True, datalogpath=None):
        self.debugFile = debugFile
        f = open(debugFile,'w')
        f.close()
        self.debug = debug
        self.arch = arch
        self.mem = {} #memory of interest
        self.reg = {} #register
        self.fp_regs = {} # single-precision VFP registers (s0, s1, ...)
        self.first_push = True
        self.symbolic_count = 0
        self.mode = mode
        print(f"======== mode = {mode} ========")
        # whether the binary being emulated contains a heap 'free' function.
        self.hasFree = True
        self.logFile = open('./logs/Emulator.log', 'w')
        conditional_print('---- Emulator.log ----', file=self.debugFile, flag=self.debug)
        self.logFile.close()
        conditional_print(f"Setting up emulator of arch={self.arch.type} exploit={mode}", flag=self.debug)
        self.mem_accesses = 0
        self.sr = {'N':0, 'Z':0, 'C':0, 'V':0}
        self.total_instrs = 0
        self.datalog = None
        self.datalog_idx = 0
        self.datalog_exhausted = False
        self.datalog_bytes = b''
        self.datalog_byte_idx = 0
        self.pending_log = False
        self.nonstack_log_seen = False
        self.stack_log_enabled = False
        self.stack_log_seen = False
        self.it_state = []
        self.stack_limit = None
        ### for datalog
        self.read_from_data_log = False
        if self.arch.type == 'elf32-msp430':
            if mode == 'ret-exploit':
                #voi is stack pointer
                self.base= 'x-2' #variable of interest
                self.type = 1 # type --> 1:mem, 0:reg
                self.size = 2
                self.reg['r1'] = self.base    
            elif mode == 'rda':
                # set stack pointer
                f = open("./objs/.sp", "r")
                sp_val = f.read()[:-1]
                f.close()
                if len(sp_val) > 0:
                    self.reg['r1'] = str(int(sp_val,16))
                
            elif mode == 'call-exploit':
                #voi is the call reg
                self.base= 'x' #
                self.type = 1 # type --> 1:mem, 0:reg
                self.size = 2
                self.reg['r1'] = self.base  # start off with sp as base... this will change
            else:
                # others?
                conditional_print("todo", flag=self.debug)
        else: #arm mode
            if mode == 'rda':
                # set sp/lr init values
                f = open("./objs/.sp", "r")
                sp_val = f.read()[:-1]
                f.close()
                if len(sp_val) > 0:
                    self.reg['sp'] = str(int(sp_val,16))
                # print(f"Set SP as {self.reg['sp']}")
                else:
                    #voi is stack pointer
                    self.base= 'x' 
                    self.type = 1 # type --> 1:mem, 0:reg
                    self.size = 4
                    self.reg['sp'] = self.base 
                self.reg['lr'] = '0xfeffffff';
            elif mode == 'data-log':
                with open(datalogpath, 'r') as file:
                    self.datalog = [line.strip() for line in file if line.strip()]

                # Each .cflog line is a hex dump of the bytes that were
                # logged, in memory order (little-endian on this target).
                # Lines are usually one 32-bit word, but the final line can
                # be shorter when the log ends mid-word.
                self.datalog_bytes = b''.join(
                    bytes.fromhex(line) for line in self.datalog
                )
                self.datalog_byte_idx = 0
                self.datalog_idx = 0

                print(f"datalog lines: {len(self.datalog)} "
                      f"({len(self.datalog_bytes)} bytes)")

                # set sp/lr init values
                f = open("./objs/.sp", "r")
                sp_val = f.read().strip()
                f.close()

                ### arm has both initialized to the same value
                self.reg['sp'] = str(int(sp_val,16))
                self.reg['r7'] = str(int(sp_val,16))

                # Instrumentation uses _estack - 8 as the upper stack bound.
                self.stack_limit = int(sp_val, 16) - 8

                ### used by instrumentor... need to init to something
                self.reg['r0'] = 0
                self.reg['r1'] = 0

                ### for pop from pc comparisons
                self.reg['pc'] = ''

                self.reg['lr'] = '0xfeffffff';

                 #read .data.objs to get the sizes of data objects
                # iterate through .data to assign objects
                f = open('./objs/.data.objs', 'r')
                objs = []
                for line in f:
                    objs.append(line[:-1].split(' ')) #[addr, size(in hex)]
                f.close()

                f = open('./objs/.data', 'r')
                data_bytes = f.read().replace('\n', '')
                f.close()
                # print(data_bytes)

                # print(f"from '.data'...")
                for base,size in objs:
                    base = int(base,16)
                    size = int(size,16)
                    b = ''
                    for i in range(0, 2*size):
                        b += data_bytes[i]
                    if len(b) > 8:
                        for k in range(0, len(b), 8):
                            word = b[k:k+8]
                            word =  ''.join(reversed([word[j:j+2] for j in range(0, len(word), 2)]))
                            # print(f"setting {hex(base+int(k/2))} to {word} ({len(word)})")
                            self.mem[str(base+int(k/2))] = str(int(word,16))
                    else:
                        # print(f"setting {hex(base)} to {b} ({size})")
                        self.mem[str(base)] = str(int(b,16))
                    data_bytes = data_bytes[size:]    
                # a = input()

                f = open('./objs/.rodata.start')
                rodata_start = f.read().replace('\n', '')
                f.close()

                f = open('./objs/.rodata', 'r')
                # conditional_print(f"from '.rodata'...", flag=self.debug)
                rodata_hex = f.read().replace('\n', '')
                f.close()
                b = ''
                if len(rodata_start) > 0:
                    rodata_addr = int(rodata_start,16)
                    for i in range(0, len(rodata_hex)):
                        b += rodata_hex[i]
                        if i % 8 == 7:
                            self.mem[str(rodata_addr)] = b
                            # conditional_print(f"setting {hex(rodata_addr)} to {self.mem[str(rodata_addr)]}", file=self.debugFile, flag=self.debug)
                            rodata_addr += 4
                            b = ''
                    if b != '':
                        # conditional_print(f"setting {hex(rodata_addr)} to {b}", file=self.debugFile, flag=self.debug)
                        self.mem[str(rodata_addr)] = b

            else: #if mode == 'ret-exploit':
                # for now the inputs are in the global data...

                #read .data.objs to get the sizes of data objects
                # iterate through .data to assign objects
                f = open('./objs/.data.objs', 'r')
                objs = []
                for line in f:
                    objs.append(line[:-1].split(' ')) #[addr, size(in hex)]
                f.close()

                f = open('./objs/.data', 'r')
                data_bytes = f.read().replace('\n', '')
                f.close()
                # print(data_bytes)

                # print(f"from '.data'...")
                for base,size in objs:
                    base = int(base,16)
                    size = int(size,16)
                    b = ''
                    for i in range(0, 2*size):
                        b += data_bytes[i]
                    if len(b) > 8:
                        for k in range(0, len(b), 8):
                            word = b[k:k+8]
                            word =  ''.join(reversed([word[j:j+2] for j in range(0, len(word), 2)]))
                            # print(f"setting {hex(base+int(k/2))} to {word} ({len(word)})")
                            self.mem[str(base+int(k/2))] = str(int(word,16))
                    else:
                        # print(f"setting {hex(base)} to {b} ({size})")
                        self.mem[str(base)] = str(int(b,16))
                    data_bytes = data_bytes[size:]    
                # a = input()

                f = open('./objs/.rodata.start')
                rodata_start = f.read().replace('\n', '')
                f.close()

                f = open('./objs/.rodata', 'r')
                conditional_print(f"from '.rodata'...", flag=self.debug)
                rodata_hex = f.read().replace('\n', '')
                f.close()
                b = ''
                if len(rodata_start) > 0:
                    rodata_addr = int(rodata_start,16)
                    for i in range(0, len(rodata_hex)):
                        b += rodata_hex[i]
                        if i % 8 == 7:
                            self.mem[str(rodata_addr)] = b
                            # conditional_print(f"setting {hex(rodata_addr)} to {self.mem[str(rodata_addr)]}", file=self.debugFile, flag=self.debug)
                            rodata_addr += 4
                            b = ''
                    if b != '':
                        # conditional_print(f"setting {hex(rodata_addr)} to {b}", file=self.debugFile, flag=self.debug)
                        self.mem[str(rodata_addr)] = b

                #voi is stack pointer
                self.base= 'x' 
                self.type = 1 # type --> 1:mem, 0:reg
                self.size = 4
                self.reg['sp'] = self.base 
                # print(f"Set sp as {self.base}")
                # a = input()

            # store .words into mem
            f = open("./objs/.words", "r")
            for line in f:
                addr, val = line.split(',')
                self.mem[str(int(addr, 16))] = str(int(val, 16))
            f.close()
            # a = input()

            #read .bss.objs to determine memory addresses to init as 0
            #set as many 0's as specified size
            f = open('./objs/.bss.objs', 'r')
            # print(f"from '.bss'...")
            bss_objs = []
            for line in f:
                bss_objs.append(line[:-1].split(' '))
            f.close()
            for base,size in bss_objs:
                base = int(base,16)
                size = int(size,16)
                # print(f"base: {base}, size: {size}")
                b = '00'*size
                if len(b) > 8:
                    for k in range(0, len(b), 8):
                        word = b[k:k+8]
                        # print(f"setting {hex(base+int(k/2))} to {word} ({len(word)})")
                        self.mem[str(base+int(k/2))] = int(word,16)    
                else:
                    self.mem[str(base)] = str(int(b,16))
                    # print(f"setting {hex(base)} : {self.mem[str(base)]}")
            # a = input()   

    def __repr__(self)-> str:
        string = ''
        #'''
        string += 'Memory of Interest:\n'
        for key in self.mem.keys():
            try:
                string += f"{hex(int(key))} ({key}) : "
            except ValueError:
                string += f"{key} : "
            try:
                string += f"{hex(int(self.mem[key]))} ({self.mem[key]})\n"
            except ValueError:
                string += f"{self.mem[key]}\n"
        #'''
        string += 'Regs of Interest:\n'
        for key in self.reg.keys():
            try:
                string += f"{key} : {hex(int(self.reg[key]))} ({self.reg[key]})\n"
            except ValueError:
                string += f"{key} : {self.reg[key]}\n"

        return string+'\n\n'

    COND_CODES = {'eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl',
                  'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al'}

    CONDITIONAL_OPS = ['ldrb', 'ldrh', 'ldrsh', 'ldrsb', 'ldr', 'strb',
                       'strh', 'str', 'movs', 'mov', 'adds', 'add',
                       'subs', 'sub', 'ands', 'and', 'orrs', 'orr',
                       'eors', 'eor', 'bics', 'bic', 'negs', 'neg',
                       'muls', 'mul', 'uxtb', 'uxth', 'sxtb', 'sxth',
                       'lsls', 'lsl', 'lsrs', 'lsr', 'asrs', 'asr',
                       'udiv', 'cmp', 'cmn']

    @classmethod
    def _u32(cls, value):
        return int(value) & 0xFFFFFFFF

    @classmethod
    def _s32(cls, value):
        value = cls._u32(value)
        return value - 0x100000000 if value & 0x80000000 else value

    def _strip_cond_suffix(self, instr):
        #extract condition suffixes only from non-branch instructions.
        if instr in self.arch.all_br_insts:
            return instr, None
        base = instr.split('.')[0]
        if base.startswith('b') and base[1:] in self.COND_CODES:
            return instr, None
        for op in self.CONDITIONAL_OPS:
            if instr == op:
                return instr, None
            if instr.startswith(op) and instr[len(op):] in self.COND_CODES:
                return op, instr[len(op):]
        return instr, None

    @staticmethod
    def _is_it_instr(instr):
        return instr.startswith('it') and all(c in 'te' for c in instr[2:])

    def _setup_it_state(self, instr, arg):
        cond = arg.strip().lower().split()[0] if arg.strip() else 'al'
        cond_true = bool(self.eval_cond(cond))
        # 'it' -> t, 'ite' -> te, 'itt' -> tt, 'ittt' -> ttt, ...
        mask = 't' + instr[2:]
        self.it_state = [cond_true if c == 't' else not cond_true for c in mask]
        conditional_print(f"IT block {instr} {arg} -> {self.it_state}",
                          file=self.debugFile, flag=self.debug)

    def eval_cond(self, cond):
        ##evaluate an ARM condition code using the current status flags
        cond = cond.lower()
        n = self.sr.get('N', 0)
        z = self.sr.get('Z', 0)
        c = self.sr.get('C', 0)
        v = self.sr.get('V', 0)
        if cond in ('eq',):
            return z == 1
        if cond in ('ne',):
            return z == 0
        if cond in ('cs', 'hs'):
            return c == 1
        if cond in ('cc', 'lo'):
            return c == 0
        if cond in ('mi',):
            return n == 1
        if cond in ('pl',):
            return n == 0
        if cond in ('vs',):
            return v == 1
        if cond in ('vc',):
            return v == 0
        if cond in ('hi',):
            return c == 1 and z == 0
        if cond in ('ls',):
            return c == 0 or z == 1
        if cond in ('ge',):
            return n == v
        if cond in ('lt',):
            return n != v
        if cond in ('gt',):
            return z == 0 and n == v
        if cond in ('le',):
            return z == 1 or n != v
        if cond in ('al',):
            return True
        conditional_print(f"Unknown condition code: {cond}",
                          file=self.debugFile, flag=self.debug)
        return False

    def update_sr_cmp(self, x, y):
        # set N/Z/C/V for a 32-bit subtraction (x - y)
        x = self._u32(x)
        y = self._u32(y)
        result = (x - y) & 0xFFFFFFFF
        self.sr['N'] = (result >> 31) & 1
        self.sr['Z'] = int(result == 0)
        self.sr['C'] = int(x >= y)
        self.sr['V'] = int(bool((x ^ y) & (x ^ result) & 0x80000000))

    def update_sr_add(self, x, y):
        #set N/Z/C/V for a 32-bit addition (x + y)
        x = self._u32(x)
        y = self._u32(y)
        total = x + y
        result = total & 0xFFFFFFFF
        self.sr['N'] = (result >> 31) & 1
        self.sr['Z'] = int(result == 0)
        self.sr['C'] = int(total > 0xFFFFFFFF)
        self.sr['V'] = int(bool(((~x & 0xFFFFFFFF) ^ y) & (x ^ result) & 0x80000000))

    def _mask_reg(self, reg):
        # keep data-log registers as 32-bit unsigned values
        if self.mode != 'data-log' or reg not in self.reg:
            return
        try:
            self.reg[reg] = str(self._u32(int(self.reg[reg])))
        except (ValueError, TypeError):
            pass

    def set_base(self, base_reg, offset, isWrite):
        if isWrite: # if its a write, base_reg is the input register
            reg_val = self.get_reg(base_reg)
            expr = reg_val
        else:
            #need to set the reg value
            #for ex, if the base is -4(r4), then x = r4-4, offset = -4 and base = r4
            #need to set equiv of this in reg, r4 = x+4
            # print("setting base")
            reg_val = self.get_reg(base_reg)
            if int(offset) > 0:
                # if positive, need to make negative
                # print(f"Evaluating '{reg_val+'+'+offset}'")
                expr = self.evaluate_expression(reg_val+'+'+offset)
            else:
                #need to make positive
                # print(f"Evaluating '{reg_val+offset}'")
                expr = self.evaluate_expression(reg_val+offset)
            #set this mem_addr as the base
        self.base = expr
        # if 'x' in expr:
            # print(f"INITIALIZED BASE: {expr}")
        # else:
            # print(f"INITIALIZED BASE: {hex(int(expr))}")
        # a = input()
        conditional_print(f"INITIALIZED BASE: {base_reg} = {reg_val}", file=self.debugFile, flag=self.debug)

    def get_reg(self, reg):
        if self.arch.type == 'elf32-msp430':
            #renaming for msp430 r10-15
            if reg == 'r10':
                reg_val =  self.reg['ra']
            elif reg == 'r11':
                reg_val = self.reg['rb']
            if reg == 'r12':
                reg_val = self.reg['rc']
            elif reg == 'r13':
                reg_val = self.reg['rd']
            if reg == 'r14':
                reg_val = self.reg['re']
            elif reg == 'r15':
                reg_val = self.reg['rf']
            else:
                reg_val = self.reg[reg]
        else:
            # print(f"Trying to get reg: {reg}")
            reg_val = self.reg[reg]

        if 'x' in reg_val:
            return reg_val

        if '-' in reg_val:
            #take two's compliment
            reg_val =   reg_val.replace('-', '')
            reg_val = str((0xffff ^ int(reg_val)) + 0x1)

        return reg_val

    def get_mem(self, addr):
        try:
            return self.mem[addr]
        except KeyError:
            return None

    def compare_to_base(self, mem_addr):
        if self.mode == 'ret-exploit' or self.mode == 'call-exploit':
            # OVF-class workloads (no 'free' in the binary) use the OVF MSP430
            # authority: a write is valid while accessed_addr <= base.
            if not self.hasFree and self.arch.type == 'elf32-msp430':
                if 'x' in mem_addr:
                    accessed_addr = simplify(mem_addr)
                    base_addr = simplify(self.base)
                    sol = solve(accessed_addr <= base_addr)
                else:
                    sol = True
                return sol
            if 'y' not in mem_addr:
                if 'x' in mem_addr:
                    if self.arch.type == "armv8-m33":
                        accessed_addr = simplify(mem_addr)
                        base_upper = simplify(self.base+"-"+str(self.size)+' + 1') # plus one bc overlap
                        base_lower = simplify(self.base)
                        # print(f"Evluating: {accessed_addr} <= {base_addr}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_lower}",file=self.debugFile, flag=self.debug)
                        eq_sol = accessed_addr == base_lower
                        conditional_print(eq_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} > {base_upper}",file=self.debugFile, flag=self.debug)
                        u_sol = solve(accessed_addr > base_upper)
                        conditional_print(u_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} < {base_lower}",file=self.debugFile, flag=self.debug)
                        l_sol = solve(accessed_addr < base_lower)
                        conditional_print(l_sol,file=self.debugFile, flag=self.debug)
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
                        # print(f'Result: {accessed_addr} <= {base_addr} == {sol}')
                    else:
                        accessed_addr = simplify(mem_addr)
                        base_lower = simplify(self.base) # in msp430 its back the "Upper" has a smaller addr
                        base_upper = simplify(self.base+"-"+str(self.size)+' + 1')
                        # print(f"Evluating: {accessed_addr} <= {base_addr}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_lower}",file=self.debugFile, flag=self.debug)
                        eq_sol = accessed_addr == base_lower
                        conditional_print(eq_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} > {base_lower}",file=self.debugFile, flag=self.debug)
                        u_sol = solve(accessed_addr > base_lower)
                        conditional_print(u_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} < {base_upper}",file=self.debugFile, flag=self.debug)
                        l_sol = solve(accessed_addr < base_upper)
                        conditional_print(l_sol,file=self.debugFile, flag=self.debug)
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
                else:
                    conditional_print("Reached the 'x not in mem_addr' case",file=self.debugFile, flag=self.debug)
                    accessed_addr = simplify(mem_addr)
                    if 'x' in self.base:
                        base_lower = simplify(self.base) # in msp430 its back the "Upper" has a smaller addr
                        base_upper = simplify(self.base+"-"+str(self.size)+' + 1')
                        # print(f"Evluating: {accessed_addr} <= {base_addr}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_lower}",file=self.debugFile, flag=self.debug)
                        eq_sol = accessed_addr == base_lower
                        conditional_print(eq_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} > {base_lower}",file=self.debugFile, flag=self.debug)
                        u_sol = solve(accessed_addr > base_lower)
                        conditional_print(u_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} < {base_upper}",file=self.debugFile, flag=self.debug)
                        l_sol = solve(accessed_addr < base_upper)
                        conditional_print(l_sol,file=self.debugFile, flag=self.debug)
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
                    else: 
                        # we can treat everything as ints
                        accessed_addr = int(mem_addr)
                        base_upper = int(self.base)
                        base_lower = int(self.base)-self.size+1
                        # print(f"base_upper : {base_upper}, base_lower : {base_lower}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_upper}",file=self.debugFile, flag=self.debug)
                        eq_sol =  accessed_addr == base_upper
                        conditional_print(f"Evluating: {accessed_addr} > {base_lower}",file=self.debugFile, flag=self.debug)
                        u_sol =  accessed_addr > base_lower
                        conditional_print(f"Evluating: {accessed_addr} < {base_upper}",file=self.debugFile, flag=self.debug)
                        l_sol =  accessed_addr < base_upper
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = u_sol and (l_sol or eq_sol) = {u_sol} and ({l_sol} or {eq_sol}) = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
            else:
                sol = True
        else:
            sol = True
        return sol

    def update_sr(self, expr):
        # print("Updating SR")
        try:
            #Symbol is a true int
            # print(f"expr: {expr} {type(expr)}")#, file=self.debugFile, flag=self.debug)
            symb = int(expr)
            # print(f"symb: {symb} {type(expr)}")#, file=self.debugFile, flag=self.debug)
            lt_expr = Lt(symb, 0)
            # print(f"lt_expr: {lt_expr} {type(lt_expr)}")#, file=self.debugFile, flag=self.debug)
            self.sr['N'] = int(bool(lt_expr))
            eq_expr = Eq(symb, 0)
            # print(f"eq_expr: {eq_expr} {type(eq_expr)}")#, file=self.debugFile, flag=self.debug)
            self.sr['Z'] = int(bool(eq_expr))
            # 
            gt_expr = Gt(symb, 0)
            self.sr['C'] = int(bool(gt_expr) or bool(eq_expr))
        except ValueError:
            #Symobl is an expression
            conditional_print(f'Symbol is an expression: {expr}', file=self.debugFile, flag=self.debug)

    @staticmethod
    def _fp_bits_to_float(bits):
        return struct.unpack('<f', struct.pack('<I', int(bits) & 0xFFFFFFFF))[0]

    @staticmethod
    def _fp_float_to_bits(value):
        return struct.unpack('<I', struct.pack('<f', float(value)))[0]

    def _fp_get(self, reg):
        # VFP registers hold the raw 32-bit pattern, like ARM integer regs.
        return self.fp_regs.get(reg, 0)

    def _fp_set(self, reg, bits):
        self.fp_regs[reg] = int(bits) & 0xFFFFFFFF

    def read_from_mem(self, addr, size=4, signed=False):
        # used logged memory bytes while keeping the data log synchronized with emulated memory.
        addr_i = int(addr)
        addr_key = str(addr_i)

        if self.mode == 'data-log' and self.pending_log:
            self.pending_log = False
            self.nonstack_log_seen = True
            if self.datalog_byte_idx + size > len(self.datalog_bytes):
                self.datalog_exhausted = True
                conditional_print(f"[read_from_mem] LOG exhausted at "
                                  f"{self.datalog_byte_idx} for "
                                  f"addr={hex(addr_i)}",
                                  file=self.debugFile, flag=self.debug)
            else:
                chunk = self.datalog_bytes[self.datalog_byte_idx:
                                           self.datalog_byte_idx + size]
                self.datalog_byte_idx += size
                self.datalog_idx = self.datalog_byte_idx // 4

                val = self._decode_log_chunk(chunk, size, signed)
                conditional_print(f"[read_from_mem] LOG addr={hex(addr_i)} "
                                  f"size={size} bytes={chunk.hex()} -> {hex(val)} "
                                  f"({self.datalog_byte_idx}/{len(self.datalog_bytes)} bytes)",
                                  file=self.debugFile, flag=self.debug)
                return str(val)

        if self.mode == 'data-log' and size < 4:
            #get the correct bytes
            raw_val = 0
            for i in range(size):
                cur = addr_i + i
                if str(cur) in self.mem:
                    byte = self._u32(self.mem[str(cur)]) & 0xFF
                else:
                    lane = cur % 4
                    word = self._u32(self.mem[str(cur - lane)])
                    byte = (word >> (8 * lane)) & 0xFF
                raw_val |= byte << (8 * i)
            if signed and size == 2 and raw_val & 0x8000:
                raw_val -= 0x10000
            val = str(raw_val)
        else:
            val = self.mem[addr_key]

        if self.mode == 'data-log':
            self._consume_matching_stack_log(addr_i, size, signed, val)

        conditional_print(f"[read_from_mem] Read {hex(int(val))} ({val}) "
                          f"from addr {hex(addr_i)} ({addr_key}) size={size}",
                          file=self.debugFile, flag=self.debug)
        return val

    @staticmethod
    def _decode_log_chunk(chunk, size, signed=False):
        raw = int.from_bytes(chunk, 'little')
        if size == 1:
            return raw & 0xFF
        if size == 2:
            val = raw & 0xFFFF
            return val - 0x10000 if signed and val & 0x8000 else val
        val = raw & 0xFFFFFFFF
        return val - 0x100000000 if signed and val & 0x80000000 else val

    def _consume_matching_stack_log(self, addr_i, size, signed, mem_val):
        if not self.stack_log_enabled or not self.nonstack_log_seen:
            return
        if self.stack_limit is None or 'sp' not in self.reg:
            return
        try:
            sp = int(self.reg['sp'])
            expected = int(mem_val)
        except (TypeError, ValueError):
            return
        if not (sp <= addr_i <= self.stack_limit):
            return
        if self.datalog_byte_idx + size > len(self.datalog_bytes):
            return

        chunk = self.datalog_bytes[self.datalog_byte_idx:
                                   self.datalog_byte_idx + size]
        decoded = self._decode_log_chunk(chunk, size, signed)
        adjusted = False
        if decoded == expected:
            self.stack_log_seen = True
        else:
            raw = int.from_bytes(chunk, 'little')
            remaining = len(self.datalog_bytes) - self.datalog_byte_idx
            plausible = (size == 4 and
                         (sp - 0x2000 <= raw <= self.stack_limit + 0x100 or
                          (remaining == size and self.stack_log_seen and
                           (raw & 0xFFFF) >= 0xFF00)))
            if not plausible:
                conditional_print(f"[read_from_mem] stack log mismatch "
                                  f"addr={hex(addr_i)} size={size} "
                                  f"mem={hex(expected)} log={hex(decoded)} "
                                  f"bytes={chunk.hex()} idx={self.datalog_byte_idx}",
                                  file=self.debugFile, flag=self.debug)
                return
            adjusted = True

        self.datalog_byte_idx += size
        self.datalog_idx = self.datalog_byte_idx // 4
        label = "LOG (stack, adjusted)" if adjusted else "LOG (stack)"
        conditional_print(f"[read_from_mem] {label} addr={hex(addr_i)} "
                          f"size={size} bytes={chunk.hex()} -> {hex(expected)} "
                          f"({self.datalog_byte_idx}/{len(self.datalog_bytes)} bytes)",
                          file=self.debugFile, flag=self.debug)

    def step(self, asm_inst):
        self.total_instrs += 1
        valid = True
        addr = asm_inst.addr
        instr = asm_inst.instr
        aarg = asm_inst.arg
        #if 'sp' in aarg or 'push' in instr or 'pop' in instr:
        conditional_print(f"Instruction ({addr}): {instr} {aarg}",file=self.debugFile, flag=self.debug)

        reg_change = False
        mem_change = False

        # it blocks/conditional instruction suffixes
        base_instr, cond_suffix = self._strip_cond_suffix(instr)
        in_it = bool(self.it_state)
        it_execute = self.it_state.pop(0) if in_it else True

        if self.arch.type == 'armv8-m33':
            if self._is_it_instr(base_instr):
                self._setup_it_state(base_instr, aarg)
                return valid
            if not it_execute:
                conditional_print(f"Skipping {instr} {aarg} (IT block)",
                                  file=self.debugFile, flag=self.debug)
                return valid
            if not in_it and cond_suffix and not self.eval_cond(cond_suffix):
                conditional_print(f"Skipping {instr} {aarg} (cond {cond_suffix})",
                                  file=self.debugFile, flag=self.debug)
                return valid
            instr = base_instr

        if instr in ('nop', 'nop.w'):
            return valid

        if self.arch.type == 'armv8-m33':
            if 'cmp' in instr or 'cmn' in instr:
                #determine if cmp to reg or imm
                x, y = aarg.split(', ')
                x = x.strip()
                y = y.strip()
                if '@' in y:
                    y_old = y
                    y, _ = y.split('@')
                    print(f'changed {y_old} --> {y}')
                y = y.strip()

                if self.mode == 'data-log':
                    x_val = self._u32(int(self.reg.get(x, 0)))
                    if y.startswith('r') or y in ('sp', 'lr', 'pc'):
                        y_val = self._u32(int(self.reg.get(y, 0)))
                    else:
                        y_val = self._u32(int(y.replace('#', '')))
                    # stack load logging only for builds that store the address in r6
                    if (self.arch.type == 'armv8-m33' and
                            x == 'sp' and y == 'r6'):
                        self.stack_log_enabled = True

                    if 'cmn' in instr:
                        self.update_sr_add(x_val, y_val)
                    else:
                        self.update_sr_cmp(x_val, y_val)
                else:
                    if y.startswith('r') or y in ('sp', 'lr', 'pc'):
                        for q in (x, y):
                            if q not in self.reg:
                                self.reg[q] = 'y'+str(self.symbolic_count)
                                self.symbolic_count += 1
                        diff = self.evaluate_expression(self.reg[x]+' - '+self.reg[y])
                    else:
                        y = y.replace('#','')
                        if x not in self.reg:
                            self.reg[x] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                        diff = self.evaluate_expression(self.reg[x]+' - '+y)
                    self.update_sr(diff)

                conditional_print(f"flags after {instr}: {self.sr}",
                                  file=self.debugFile, flag=self.debug)
                #comparison
                return valid

            if 'bl' == instr and self.arch.instrumentation_handle not in aarg:                
                #update lr
                conditional_print(f"hit BL instruction with arg={aarg}... incrementing lr", file=self.debugFile, flag=self.debug)
                self.reg['lr'] = self.evaluate_expression(addr+'+ 4')
                reg_change = True

            if 'bl' == instr and self.arch.data_logging_handle in aarg:
                # marker that the following load was logged.
                self.pending_log = True
                conditional_print(f"BL {aarg}: pending data log read",
                                  file=self.debugFile, flag=self.debug)

            elif instr in self.arch.return_instrs or instr in self.arch.indr_calls or instr in self.arch.call_instrs or instr in self.arch.unconditional_br_instrs or instr in self.arch.conditional_br_instrs:
                # branch instruction so continue
                return valid

            elif instr.startswith('vldr') or instr.startswith('vstr'):
                reg_change = True
                self.mem_accesses += 1
                fp_reg, mem_spec = [a.strip() for a in aarg.split(', ', 1)]
                parts = [a.strip() for a in mem_spec.strip('[]').split(',')]
                base = parts[0]
                if base == 'pc':
                    off = int(parts[1].replace('#', ''), 0)
                    mem_addr = str((int(addr, 16) + off + 4) & -4)
                    bits = int(self.mem[mem_addr])
                else:
                    if len(parts) > 1:
                        off = parts[1].replace('#', '').strip()
                        off = int(off, 0) if off.lstrip('-').isdigit() else int(self.reg[off])
                        mem_addr = int(self.reg[base]) + off
                    else:
                        mem_addr = int(self.reg[base])
                    if instr.startswith('vldr'):
                        bits = int(self.read_from_mem(mem_addr, size=4))
                    else:
                        self.mem[str(mem_addr)] = str(self._fp_get(fp_reg))

                if instr.startswith('vldr'):
                    self._fp_set(fp_reg, bits)
                    conditional_print(f"{fp_reg} = vldr bits {hex(bits)} "
                                      f"({self._fp_bits_to_float(bits)})",
                                      file=self.debugFile, flag=self.debug)

            elif 'vmov' in instr:
                reg_change = True
                dest, src = [a.strip() for a in aarg.split(',')]
                if dest.startswith('s'):
                    if src.startswith('s'):
                        self._fp_set(dest, self._fp_get(src))
                    else:
                        self._fp_set(dest, int(self.reg[src]))
                elif src.startswith('s'):
                    self.reg[dest] = str(self._fp_get(src))

            elif 'vcvt' in instr:
                reg_change = True
                parts = instr.split('.')
                # vcvt.<dst_type>.<src_type>
                dst_type, src_type = parts[1], parts[2]
                dest, src = [a.strip() for a in aarg.split(',')]
                src_bits = self._fp_get(src)
                if dst_type == 'f32' and src_type == 's32':
                    result = self._fp_float_to_bits(float(self._s32(src_bits)))
                elif dst_type == 'f32' and src_type == 'u32':
                    result = self._fp_float_to_bits(float(src_bits & 0xFFFFFFFF))
                elif dst_type == 's32' and src_type == 'f32':
                    value = self._fp_bits_to_float(src_bits)
                    result = self._u32(int(value))
                else:
                    result = src_bits
                self._fp_set(dest, result)

            elif instr.startswith(('vadd', 'vsub', 'vmul', 'vdiv')):
                reg_change = True
                dest, lhs, rhs = [a.strip() for a in aarg.split(',')]
                a = self._fp_bits_to_float(self._fp_get(lhs))
                b = self._fp_bits_to_float(self._fp_get(rhs))
                if instr.startswith('vadd'):
                    result = a + b
                elif instr.startswith('vsub'):
                    result = a - b
                elif instr.startswith('vmul'):
                    result = a * b
                else:
                    result = a / b if b else 0.0
                self._fp_set(dest, self._fp_float_to_bits(result))

            elif 'ldr' in instr:
                reg_change = True
                self.mem_accesses += 1

                load_size = 4
                load_signed = False
                if 'ldrsb' in instr:
                    load_size = 1
                    load_signed = True
                elif 'ldrsh' in instr:
                    load_size = 2
                    load_signed = True
                elif 'ldrb' in instr:
                    load_size = 1
                elif 'ldrh' in instr:
                    load_size = 2

                if 'lsl' in aarg:
                    # special variant of form ldr Rt, [Rn, Rm, LSL #imm]
                    # imm is a shift value on Rm
                    # Rt = mem[Rn + (Rm << imm)]
                    # Shift(x, imm) = x * (2**imm)
                    dest,args = aarg.split(', [')
                    # dest = Rt, args = 'Rn, Rm, LSL #imm]'
                    base, shift_base, shift_val  = args.split(', ')
                    # base = Rn, shift_base = Rm, shift_val = 'LSL #imm]''
                    shift_val =  shift_val.replace('lsl ', '').replace(']', '').replace('#', '').strip()
                    # shift_val == imm
                    offset = self.evaluate_expression(self.reg[shift_base]+' * '+str(2**int(shift_val)))
                    post_incr = False
                else:
                    b_start = aarg.index('[')
                    b_end = aarg.index(']')

                    dest,src = aarg.split(', [')
                    src = src.replace(']','')
                    # print(f"loading value from {src} into {dest}")
                    base,offset = src.split(',')
                    if '#' in offset:
                        #offset is a imm, remove the #
                        offset = offset.replace('#','')
                    else:
                        #offset is a reg. replace with its val
                        offset = offset.replace(' ','')
                        offset = self.reg[offset]
                    
                    post_incr = False
                    if b_end != len(aarg)-1:
                    # print(f"This is NOT a post increment ldr:\n\t{aarg}\n\t{len(aarg)}\n\t{b_end}")
                    # else:
                        post_incr = True
                        pop_arg = '{'+f"{aarg.split(',')[0]}"+'}'
                        # print(f'pop_arg: {pop_arg}')
                        return self.step(AssemblyInstruction(addr=asm_inst.addr,instr="pop",arg=pop_arg))
                        # print(f"This is post increment ldr:\n\t{aarg}\n\t{len(aarg)}\n\t{b_end}")

                    # print(f"dest={dest}, src={src}, base={base}, offset={offset}")

                if 'pc' in base:
                    base = addr
                    # for pc-relative addressing, need to add 4 and clear bit[1] because .... arm
                    # https://stackoverflow.com/questions/70491482/understanding-cortex-m-assembly-ldr-with-pc-offset
                    mem_addr = self.evaluate_expression(str(int(base,16))+'+'+offset+'+4')
                    # print(f"trying access ... ({hex(int(mem_addr))}) ({type(mem_addr)})")
                    try:
                        mem_addr = str(int(mem_addr)&(-4))
                    except ValueError:
                        conditional_print(f"ValueError on mem_addr={mem_addr}", file=self.debugFile, flag=self.debug)
                        if '@' in mem_addr:
                            mem_addr, _ = mem_addr.split('@')
                            mem_addr = self.evaluate_expression(mem_addr)
                        conditional_print(f"ValueError fixed: mem_addr={mem_addr}", file=self.debugFile, flag=self.debug)
                        # a = input()
                    
                    try:
                        #self.reg[dest] = self.mem[mem_addr]
                        self.reg[dest] = self.mem[mem_addr]
                    except KeyError:
                        if self.mode == 'data-log':
                            print(f"THIS SHOULDN'T EVER HAPPEN [emulator line 581]")
                            sys.exit(1)
                        else:
                            self.mem[mem_addr] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            self.reg[dest] = self.mem[mem_addr]
                else:
                    try:
                        base_reg = base
                        conditional_print(f'base={base}', file=self.debugFile, flag=self.debug)
                        if not post_incr:
                            base = self.reg[base]
                            conditional_print(f'base={base}', file=self.debugFile, flag=self.debug)
                        else:
                            base_reg = base
                            base_val = self.reg[base]
                            print(f"base_reg={base_reg}")
                            print(f"base_val={hex(int(base_val))}")
                            self.reg[base_reg] = self.evaluate_expression(self.reg[base_reg]+'+'+offset)
                            print(f"self.reg[{base_reg}]={self.reg[base_reg]}")
                            base = base_val
                    except KeyError:
                        print("We should never reach here now.... (ldr->pc not in base)")
                        self.reg[base] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        base = self.reg[base]
                        sys.exit(1)

                    # print(f"base: {base} {type(base)}")
                    if not post_incr:
                        conditional_print(f'not post incr! base={base} offest={offset}', file=self.debugFile, flag=self.debug)
                        mem_addr = self.evaluate_expression(base+'+'+offset)
                    else:
                        mem_addr = self.evaluate_expression(base)
                        
                    try:
                        if self.mode == 'data-log':
                            if 'sp' in base_reg:
                                if self.pending_log:
                                    print("\nDATA-LOG ERROR: pending log call on a stack-based load "
                                          f"at {addr}: {instr} {aarg}")
                                    sys.exit(1)
                                mem_val = self.mem[mem_addr]
                            else:
                                mem_val = self.read_from_mem(
                                    mem_addr, size=load_size, signed=load_signed)
                            self.reg[dest] = mem_val
                        elif 'ldrb' in instr:
                            if 'x' not in mem_addr and 'y' not in mem_addr:
                                byte = int(mem_addr)%4
                                # print(f'byte = {byte};  [2*byte:2*(byte+1)] = [{2*byte}:{2*(byte+1)}]', file=self.debugFile)
                                mem_addr = str(int(mem_addr)-byte)
                                # print(f'mem_addr = {mem_addr}; mem[{mem_addr}] = {(hex(int(self.mem[mem_addr]))[2:])}', file=self.debugFile)
                                #val = self.mem[mem_addr]
                                val = self.read_from_mem(mem_addr)
                                if isinstance(val,int):
                                    hex_val = hex(int(val))[2:]
                                    if len(hex_val) < 8:
                                        # need all 32 bits to do byte access
                                        hex_val = '0'*(8-len(hex_val))+hex_val
                                    byte_val = str(int(hex_val[2*byte:2*(byte+1)],16))
                                    try:
                                        val_str = hex(int(byte_val))
                                    except ValueError:
                                        val_str = byte_val
                                    conditional_print(f"writing {val_str} to {dest}", file=self.debugFile, flag=self.debug)
                                    self.reg[dest] = byte_val
                                else:
                                    self.reg[dest] = val
                                # a = input()
                            else:                                
                                #self.reg[dest] = self.mem[mem_addr]
                                self.reg[dest] = self.read_from_mem(mem_addr)
                                conditional_print(f"writing val_str into {dest}", file=self.debugFile, flag=self.debug)
                        else:
                            #self.reg[dest] = self.mem[mem_addr]
                            if 'sp' in base_reg:
                                mem_val = self.mem[mem_addr]
                            else:
                                mem_val = self.read_from_mem(mem_addr)
                            # print(f"Reading {mem_val} from {mem_addr} writing to {dest}")
                            self.reg[dest] = mem_val
                    except KeyError:
                        # if key error, it is a mem value not defined by .word in the asm file
                        # so we need to add to .mem as symbolic value, then assign value to .reg[dest]
                        # print(f"keyerror at ldr: {addr} --> Dont have mem[{mem_addr}]", file=self.debugFile)
                        # self.mem[mem_addr] = 'y_'+mem_addr+'_'+addr
                        # self.mem[mem_addr] = 'y'+str(self.symbolic_count)
                        # self.symbolic_count += 1
                        #self.reg[dest] = self.mem[mem_addr]
                        # self.reg[dest] = self.read_from_mem(mem_addr)
                        print(f"Should never happen... '{dest}' not a reg or '{hex(int(mem_addr))}' ({mem_addr}) not in mem")
                        sys.exit(1)

                    # print(f"base: {base} {type(base)}")
                    # print(f"offset: {offset}")
                    # print(f"mem_addr: {hex(int(mem_addr))}")
            
            elif 'movw' in instr:
                # move 16-bit imm into the top half of the reg
                reg_change = True
                dest,src = aarg.split(', ')
                ## get reg's current val in hex
                if dest not in self.reg.keys():
                    # default to zero -- check with liam
                    self.reg[dest] = '0'
                current_val_hex = hex(int(self.reg[dest]))
                imm_hex = hex(int(src.replace('#','')))
                current_val_hex = current_val_hex[2:]
                if len(current_val_hex) == 4: #already 16 bits
                    dest_hex_val = imm_hex # overwritten completely
                else: # 32 bits e.g., 00001111
                    dest_hex_val = '0x' + current_val_hex[:4] + imm_hex[2:]
                # print(f"{dest} : {current_val_hex} {type(current_val_hex)}")
                # print(f"Changing to: {imm_hex}<->{current_val_hex} : {dest_hex_val}")
                self.reg[dest] = str(int(dest_hex_val,16))
                # print(f"self.reg[{dest}] = {str(int(dest_hex_val,16))}")

            elif 'movt' in instr:
                # move 16-bit imm into the bottom half of the reg
                reg_change = True
                dest,src = aarg.split(', ')
                ## get reg's current val in hex
                current_val_hex = hex(int(self.reg[dest]))
                imm_hex = hex(int(src.replace('#','')))
                current_val_hex = current_val_hex[2:]
                if len(current_val_hex) == 4: #already 16 bits
                    dest_hex_val = imm_hex + current_val_hex
                else: # 32 bits e.g., 00001111
                    dest_hex_val = imm_hex + current_val_hex[4:]
                # print(f"{dest} : {current_val_hex} {type(current_val_hex)}")
                # print(f"Changing to: {imm_hex}<->{current_val_hex} : {dest_hex_val}")
                self.reg[dest] = str(int(dest_hex_val,16))
                # print(f"self.reg[{dest}] = {str(int(dest_hex_val,16))}")  

            elif 'mov' in instr:
                reg_change = True
                #dest is always register
                #src could be imm or reg, optionally followed by a shift
                parts = [p.strip() for p in aarg.split(',')]
                dest, src = parts[0], parts[1]

                if '#' in src:
                    # src is imm
                    val = src.replace('#','')
                    if '@' in val:
                        self.reg[dest], _ = val.split('@')
                    else:
                        self.reg[dest] = val
                else:
                    #src is another reg
                    try:
                        self.reg[dest] = self.reg[src]
                    except KeyError:
                        print("Shouldn't get here in this mode...")
                        sys.exit(1)
                        self.reg[src] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1

                if len(parts) > 2:
                    # e.g. mov.w r5, r3, lsl #2
                    shift = parts[2].lower().replace(' ', '')
                    try:
                        kind, amount = shift.split('#')
                        amount = int(amount)
                        val = int(self.reg[dest])
                        if kind == 'lsl':
                            self.reg[dest] = str(self._u32(val << amount))
                        elif kind == 'lsr':
                            self.reg[dest] = str(val >> amount)
                        elif kind == 'asr':
                            self.reg[dest] = str(self._s32(val) >> amount)
                    except (ValueError, KeyError):
                        pass
                        self.reg[dest] = self.reg[src]

            elif 'str' in instr:
                self.mem_accesses += 1
                mem_change = True
                if 'lsl' in aarg:
                    # e.g. str Rt, [Rn, Rm, LSL #imm]
                    src,args = aarg.split(', [')
                    base, shift_base, shift_val = args.split(', ')
                    shift_val = shift_val.replace('lsl ', '').replace(']', '').replace('#', '').strip()
                    offset = self.evaluate_expression(self.reg[shift_base]+' * '+str(2**int(shift_val)))
                else:
                    src,dest = aarg.split(', [')
                    dest = dest.replace(']','')
                    base,offset = dest.split(',')
                    if '#' in offset:
                        #offset is a imm, remove the #
                        offset = offset.replace('#','')
                    else:
                        #offset is a reg. replace with its val
                        offset = offset.replace(' ','')
                        offset = self.reg[offset]

                try:
                    base = self.reg[base]
                except KeyError:
                    self.reg[base] = 'y'+str(self.symbolic_count)
                    self.symbolic_count += 1
                    base = self.reg[base]

                # print(f"base: {base} {type(base)}")
                mem_addr = self.evaluate_expression(base+'+'+offset)

                byte_width = 1 if 'strb' in instr else (2 if 'strh' in instr else 0)
                if byte_width and 'x' not in mem_addr and 'y' not in mem_addr:
                    try:
                        addr_i = int(mem_addr)
                        src_int = self._u32(int(self.reg[src]))
                        word_keys = []
                        for j in range(byte_width):
                            cur = addr_i + j
                            lane = cur % 4
                            key = str(cur - lane)
                            word = self._u32(int(self.mem.get(key, 0)))
                            b = (src_int >> (8 * j)) & 0xFF
                            word = (word & ~(0xFF << (8 * lane)) & 0xFFFFFFFF) | (b << (8 * lane))
                            self.mem[key] = str(word)
                            if key not in word_keys:
                                word_keys.append(key)
                        conditional_print(
                            f"STORING {hex(src_int)} width={byte_width} to "
                            f"{hex(addr_i)} (words {[hex(int(k)) for k in word_keys]})",
                            file=self.debugFile, flag=self.debug)
                        # update_mem()/compare_to_base() need the aligned word keys
                        mem_addr = word_keys[0] if len(word_keys) == 1 else word_keys
                    except (ValueError, TypeError):
                        self.mem[mem_addr] = self.reg[src]
                elif 'strb' in instr:
                    if 'x' not in mem_addr and 'y' not in mem_addr and 'y' not in self.reg[src]:
                        byte = int(mem_addr)%4
                        # print(f'byte = {byte}')
                        mem_addr = str(int(mem_addr)-byte)
                        src_val = hex(int(self.reg[src]))[2:]
                        try:
                            mem_val = hex(int(self.mem[mem_addr]))[2:]
                            if len(mem_val) < 8:
                                # need all 32 bits to do byte access
                                mem_val = '0'*(8-len(mem_val))+mem_val
                            if byte == 0:
                                new_val = src_val + mem_val[2:]
                            elif byte == 4:
                                new_val = mem_val[:6] + src_val
                            else:
                                new_val = mem_val[:2*byte] + src_val + mem_val[2*byte+1:]
                            # convert to int first since in hex form
                            self.mem[mem_addr] = str(int(new_val, 16))
                        except KeyError:
                            self.mem[mem_addr] = self.reg[src]
                            new_val = self.reg[src]
                        try:
                            val_str = hex(int(new_val))
                        except ValueError:
                            val_str = new_val
                        try:
                            mem_addr_str = hex(int(mem_addr))
                        except ValueError:
                            mem_addr_str = mem_addr
                        conditional_print(f'STORING {val_str} to {hex(int(mem_addr_str,16))} ({mem_addr_str})', file=self.debugFile, flag=self.debug)
                    else:
                        try:
                            val_str = hex(int(self.reg[src]))
                        except ValueError:
                            val_str = self.reg[src]
                        try:
                            mem_addr_str = hex(int(mem_addr))
                        except ValueError:
                            mem_addr_str = mem_addr
                        # might need to fix
                        self.mem[mem_addr] = self.reg[src]
                        conditional_print(f"STORING {val_str} in {mem_addr_str}", file=self.debugFile, flag=self.debug)
                elif 'strh' in instr:
                    try:
                        self.mem[mem_addr] = str(self._u32(int(self.reg[src])) & 0xFFFF)
                    except (ValueError, TypeError):
                        self.mem[mem_addr] = self.reg[src]
                    conditional_print(f"STORING halfword {self.mem[mem_addr]} in {mem_addr}", file=self.debugFile, flag=self.debug)
                else:
                    try:
                        self.mem[mem_addr] = self.reg[src]
                    except KeyError:
                        self.reg[src] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.mem[mem_addr] = self.reg[src]

                    conditional_print(f"STORING {self.reg[src]} in {mem_addr}", file=self.debugFile, flag=self.debug)

                valid = self.compare_to_base(mem_addr)

            elif 'sub' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                if len(args) == 2:
                    # of the form sub src, imm
                    dest = src1 = args[0]
                    src2 = args[1]
                else:
                    #of the form sub r3, r1, r2 --> r3 = r1-r2
                    dest, src1, src2 = args

                try:
                    x_val = int(self.reg[src1])
                    y_val = (int(src2.replace('#', '')) if '#' in src2
                             else int(self.reg[src2]))
                    self.reg[dest] = str((x_val - y_val) & 0xFFFFFFFF)
                    if instr.startswith('subs'):
                        self.update_sr_cmp(x_val, y_val)
                except (KeyError, ValueError, TypeError):
                    if len(args) == 2:
                        self.reg[dest] = self.reg.get(dest, '0') + '-' + src2.replace('#', '')
                    else:
                        if src1 not in self.reg:
                            self.reg[src1] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                        if src2 not in self.reg:
                            self.reg[src2] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                        self.reg[dest] = self.evaluate_expression(
                            self.reg[src1]+' - ('+self.reg[src2]+')')

            elif 'add' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                if len(args) == 2:
                    # of the form add src, imm
                    dest = src1 = args[0]
                    src2 = args[1]
                else:
                    dest, src1, src2 = args

                try:
                    x_val = int(self.reg[src1])
                    y_val = (int(src2.replace('#', '')) if '#' in src2
                             else int(self.reg[src2]))
                    self.reg[dest] = str((x_val + y_val) & 0xFFFFFFFF)
                    if instr.startswith('adds'):
                        self.update_sr_add(x_val, y_val)
                except (KeyError, ValueError, TypeError):
                    if len(args) == 2:
                        self.reg[dest] = self.reg.get(dest, '0') + '+' + src2.replace('#', '')
                    else:
                        if src1 not in self.reg:
                            self.reg[src1] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                        if src2 not in self.reg:
                            self.reg[src2] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                        self.reg[dest] = self.evaluate_expression(
                            self.reg[src1]+' + ('+self.reg[src2]+')')

            elif 'push' in instr or ('stmdb' in instr and 'sp!' in aarg):
                reg_change = True
                mem_change = True
                #push is pseudo_instr. of stmdb.w sp!, {regs}
                #so can be written as both

                # of the format push {r1, r2, ..., r8}
                # is pushed onto the stack like:
                # ------------
                # |    r1    |
                # ------------
                # |    r2    |
                # ------------
                # ...
                # ------------
                # |    r8    |
                # ------------
                args = (aarg.replace('{','')).replace('}','')
                args = args.split(', ')
                args.reverse()

                # print(f"First push: {self.first_push}")
                if self.first_push and self.mode != 'rda' and self.mode != 'data-log':
                    # offset = 4*(len(args)-1)
                    self.reg['sp'] = self.base
                    self.first_push = False

                # print(args, self.debugFile)
                mem_addr = []
                for i in range(0, len(args)):
                    self.reg['sp'] = self.evaluate_expression(self.reg['sp']+'- 4')
                    
                    a = args[i]
                    # print(f'trying reg[{a}]')
                    try:
                        reg_val = self.reg[a]
                    except KeyError:
                        # reg_val = 'y_'+a+'_'+addr
                        reg_val = 'y'+str(self.symbolic_count)
                        self.reg[a] = reg_val
                        self.symbolic_count += 1
                        conditional_print(f"keyerror at push handled:", file=self.debugFile, flag=self.debug)
                    
                    # print(f"pushing {reg_val} onto mem[{self.reg['sp']}]")
                    self.mem[self.reg['sp']] = reg_val
                    self.mem_accesses += 1
                    mem_addr.append(self.reg['sp'])
                    valid |= self.compare_to_base(self.reg['sp'])
                    

                # a = input()

            elif 'pop' in instr or ('ldmia' in instr and 'sp!' in aarg):
                reg_change = True
                #pop is pseudo_instr. or ldmia.w sp!, {regs}
                #so can be written as both
                args = (aarg.replace('{','')).replace('}','')
                args = args.split(', ')
                if 'ldmia' in instr:
                    args = args[1:]
                conditional_print(f"ldmia args: {args}", file=self.debugFile, flag=self.debug)
                for a in args:
                    #conditional_print(f"trying {a}={self.reg[a]}", file=self.debugFile, flag=self.debug)1
                    self.mem_accesses += 1
                    sp_val = self.reg['sp']
                    try:
                        #mem_val = self.mem[sp_val]
                        mem_val = self.mem[sp_val]
                    except KeyError:
                        # mem_val = 'y_'+sp_val+'_'+addr
                        mem_val = 'y'+str(sp_val)
                        self.symbolic_count += 1
                        self.mem[sp_val] = mem_val
                        print(f"keyerror at pop: {hex(int(sp_val))} ({sp_val}) not in mem")
                        # a = input()
                        if self.mode == 'data-log':
                            sys.exit(1)

                    self.reg[a] = mem_val
                    sp_val = self.evaluate_expression(self.reg['sp']+'+ 4')
                    conditional_print(f"sp = {hex(int(sp_val))}", self.debugFile, self.debug)
                    self.reg['sp'] = sp_val
                    #print(f"mem_val = {mem_val}")
                    #print(f"sp_val = {sp_val}")
                    try:
                        popped_str = hex(int(mem_val))
                    except (ValueError, TypeError):
                        popped_str = str(mem_val)
                    conditional_print(f"popping {popped_str} from mem[{hex(int(self.reg['sp']))}] into {a}", file=self.debugFile, flag=self.debug)
                # a = input()

            elif 'ldm' in instr:
                # ldm = load multiple
                reg_change = True
                if 'ia' in instr:
                    #increase after
                    base,args = aarg.split(', {')
                    args = args.replace('}','')
                    args = args.split(', ')
                    # print(f"base: {base} : {hex(int(self.reg[base]))}")
                    # print(f"args: {args}")
                    for i in range(0, len(args)):
                        self.mem_accesses += 1
                        try:
                            mem_addr = self.evaluate_expression(self.reg[base]+'+'+str(4*i))
                            #self.reg[args[i]] = self.mem[mem_addr]
                            self.reg[args[i]] = self.read_from_mem(mem_addr)
                        except KeyError:
                            # self.mem[mem_addr] = 'y_'+mem_addr+'_'+addr
                            if self.mode == 'data-log':
                                print("THIS SHOULD NOT BE REACHED (ldm->ia->except)")
                                sys.exit(1)
                            self.mem[mem_addr] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            self.reg[args[i]] = self.mem[mem_addr]

            elif 'stm' in instr:
                mem_change = True
                # stm = store multiple
                if 'ia' in instr:
                    #increase after
                    base,args = aarg.split(', {')
                    args = args.replace('}','')
                    args = args.split(', ')
                    # print(f"base: {base} : {self.reg[base]  }")
                    # print(f"args: {args}")
                    for i in range(0, len(args)):
                        self.mem_accesses += 1
                        mem_addr = self.evaluate_expression(self.reg[base]+'+'+str(4*i))
                        # print(f"storing {args[i]}={self.reg[args[i]]} into {mem_addr}")
                        self.mem[mem_addr] = self.reg[args[i]]
                        valid |= self.compare_to_base(mem_addr)
            
            elif 'lsl' in instr:
                reg_change = True
                parts = [a.strip() for a in aarg.split(',')]
                if len(parts) == 2:
                    # lsl(s) Rd, Rs  =>  Rd = Rd << Rs
                    dest, src, shift = parts[0], parts[0], parts[1]
                else:
                    dest, src, shift = parts
                if 'y' not in self.reg[src]:
                    old_val = self._u32(int(self.reg[src]))
                    if '#' in shift:
                        amount = int(shift.replace('#', ''))
                    elif 'y' in self.reg[shift]:
                        amount = None
                    else:
                        amount = int(self.reg[shift])

                    if amount is None:
                        self.reg[dest] = self.evaluate_expression(
                            str(old_val) + '*(2 ** ' + self.reg[shift] + ')')
                    else:
                        new_val = (old_val << amount) & 0xFFFFFFFF
                        if instr.startswith('lsls'):
                            self.sr['N'] = (new_val >> 31) & 1
                            self.sr['Z'] = int(new_val == 0)
                            if 0 < amount <= 32:
                                self.sr['C'] = (old_val >> (32 - amount)) & 1
                        conditional_print(f"{dest} = {src} << {amount} = {hex(new_val)}",
                                          file=self.debugFile, flag=self.debug)
                        self.reg[dest] = str(new_val)
                else:
                    self.reg[dest] = self.evaluate_expression(self.reg[src]+'*(2 ** '+str(shift)+')')

            elif 'orr' in instr:
                reg_change = True
                aarg_split = aarg.split(', ')

                if len(aarg_split) == 2:
                    dest = aarg_split[0]
                    src = aarg_split[1]
                    conditional_print(f"dest = {self.reg[dest]} {'y' in self.reg[dest]}", flag=self.debug)
                    conditional_print(f"src = {self.reg[src]} {'y' in self.reg[src]}", flag=self.debug)

                    # start = time.perf_counter()
                    if 'y' not in self.reg[dest] and 'y' not in self.reg[src]:
                        result = int(self.reg[dest]) | int(self.reg[src])
                        conditional_print(f'{hex(result)} = {hex(int(self.reg[dest]))} | {hex(int(self.reg[src]))}', file=self.debugFile, flag=self.debug)
                        self.reg[dest] = str(result)
                        # print("if")
                    else:
                        # print("else")
                        # or using add and mult
                        # self.reg[dest] = self.evaluate_expression('('+self.reg[dest]+'+'+self.reg[src]+')'+'+ ('+self.reg[dest]+'*'+self.reg[src]+')')
                        # might need to do another thing
                        self.reg[dest] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                    stop = time.perf_counter()
                    # print(self.reg[dest])
                    # print(f"if-else time: {1000*(stop-start)}")
                    # a = input()

                elif len(aarg_split) == 3:
                    rd = aarg_split[0].replace(' ','')
                    rs = aarg_split[1].replace(' ','')
                    imm = int(aarg_split[2].replace('#',''))
                    rs_val = int(self.reg[rs])
                    rd_val = rs_val | imm
                    self.reg[rd] = str(rd_val)
                    reg_change = True

            elif 'mvn' in instr:
                reg_change = True
                dest,src = aarg.split(', ')
                src = src.strip()
                if src.startswith('#'):
                    src_val = int(src[1:], 0) & 0xFFFFFFFF
                else:
                    src_val = int(self.reg[src])
                result = self._u32(~src_val)
                self.reg[dest] = str(result)
                if instr.startswith('mvns'):
                    self.sr['N'] = (result >> 31) & 1
                    self.sr['Z'] = int(result == 0)
                    self.sr['C'] = 1  # MVN with immediate typically sets C

            elif 'uxtb' in instr:
                reg_change = True
                dest, src = aarg.split(', ')

                src_val = int(self.reg[src]) & 0xFFFFFFFF
                result = src_val & 0xFF
                conditional_print(f'{dest} = {hex(result)} <-- uxtb of {hex(src_val)}',
                                file=self.debugFile, flag=self.debug)
                self.reg[dest] = str(result)

            elif 'lsr' in instr:
                reg_change = True
                rd, rs, imm = aarg.split(',')
                rs = rs.replace(' ','')
                rd = rd.replace(' ','')
                rs_val = int(self.reg[rs])
                imm = int(imm.replace('#',''))
                # print(f"{rs}={hex(rs_val)}, {imm}")
                rd_val = rs_val >> imm
                # print(f"assigning {rd} <-- {hex(rd_val)}")
                self.reg[rd] = str(rd_val)
                
                if 'lsrs' in instr:
                    ### also need to update status flags
                    self.sr['N'] = int(rd_val >> 31 & 1)
                    self.sr['Z'] = int(rd_val == 0)
                    if imm > 0:
                        self.sr['C'] = int(rs_val >> (imm-1) & 1)
                    else:
                        self.sr['C'] = 0
                # a = input()

            elif 'asr' in instr:
                reg_change = True
                rd, rs, imm = aarg.split(',')
                rs = rs.replace(' ','')
                rd = rd.replace(' ','')
                rs_val = int(self.reg[rs])
                imm = int(imm.replace('#',''))
                ## check the sign bit, and subtract if signed
                if rs_val & (1 << 31):
                    rs_val -= (1 << 32)
                rd_val = rs_val >> imm
                if 'asrs' in instr: 
                    ##same N and Z as lsrs
                    self.sr['N'] = int(rd_val >> 31 & 1)
                    self.sr['Z'] = int(rd_val == 0)
                    ## first case for all imm
                    self.sr['C'] = int(rs_val >> (imm-1) & 1)
                self.reg[rd] = str(rd_val)

            elif 'and' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                if len(args) == 2:
                    rd = rs1 = args[0]
                    rs2 = args[1]
                else:
                    rd, rs1, rs2 = args

                if '#' in rs2:
                    rs2_val = int(rs2.replace('#',''))
                else:
                    rs2_val = int(self.reg[rs2.replace(' ','')])

                rs1_val = int(self.reg[rs1.replace(' ','')])
                rd_val = (rs1_val & rs2_val) & 0xFFFFFFFF
                self.reg[rd] = str(rd_val)
                if instr.startswith('ands'):
                    self.sr['N'] = (rd_val >> 31) & 1
                    self.sr['Z'] = int(rd_val == 0)

            elif 'eor' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                if len(args) == 2:
                    rd = rs1 = args[0]
                    rs2 = args[1]
                else:
                    rd, rs1, rs2 = args
                rs2_val = (int(rs2.replace('#','')) if '#' in rs2
                           else int(self.reg[rs2]))
                rs1_val = int(self.reg[rs1])
                rd_val = (rs1_val ^ rs2_val) & 0xFFFFFFFF
                self.reg[rd] = str(rd_val)
                if instr.startswith('eors'):
                    self.sr['N'] = (rd_val >> 31) & 1
                    self.sr['Z'] = int(rd_val == 0)

            elif 'bic' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                if len(args) == 2:
                    rd = rs1 = args[0]
                    rs2 = args[1]
                else:
                    rd, rs1, rs2 = args
                rs2_val = (int(rs2.replace('#','')) if '#' in rs2
                           else int(self.reg[rs2]))
                rs1_val = int(self.reg[rs1])
                rd_val = (rs1_val & (~rs2_val & 0xFFFFFFFF)) & 0xFFFFFFFF
                self.reg[rd] = str(rd_val)
                if instr.startswith('bics'):
                    self.sr['N'] = (rd_val >> 31) & 1
                    self.sr['Z'] = int(rd_val == 0)

            elif 'neg' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                if len(args) == 2:
                    rd, rs = args
                else:
                    rd = rs = args[0]
                rs_val = int(self.reg[rs])
                rd_val = (-rs_val) & 0xFFFFFFFF
                self.reg[rd] = str(rd_val)
                if instr.startswith('negs'):
                    self.sr['N'] = (rd_val >> 31) & 1
                    self.sr['Z'] = int(rd_val == 0)
                    # neg is 0 - rs
                    self.sr['C'] = int(self._u32(0) >= self._u32(rs_val))
                    self.sr['V'] = int(rs_val == 0x80000000)

            elif 'sxth' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                rd = args[0]
                rs = args[1] if len(args) > 1 else args[0]
                val = self._u32(int(self.reg[rs])) & 0xFFFF
                self.reg[rd] = str(self._u32(val - 0x10000 if val & 0x8000 else val))

            elif 'sxtb' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                rd = args[0]
                rs = args[1] if len(args) > 1 else args[0]
                val = self._u32(int(self.reg[rs])) & 0xFF
                self.reg[rd] = str(self._u32(val - 0x100 if val & 0x80 else val))

            elif 'uxth' in instr:
                reg_change = True
                args = [a.strip() for a in aarg.split(',')]
                rd = args[0]
                rs = args[1] if len(args) > 1 else args[0]
                self.reg[rd] = str(self._u32(int(self.reg[rs])) & 0xFFFF)

            elif 'cpsid' in instr or 'cpsie' in instr:
                # Interrupt masking has no effect on emulation.
                pass

            elif instr.startswith(('umull', 'smull')):
                reg_change = True
                rd_lo, rd_hi, rs1, rs2 = [a.strip() for a in aarg.split(',')]
                if instr.startswith('umull'):
                    a = int(self.reg[rs1]) & 0xFFFFFFFF
                    b = int(self.reg[rs2]) & 0xFFFFFFFF
                else:
                    a = self._s32(int(self.reg[rs1]))
                    b = self._s32(int(self.reg[rs2]))
                product = a * b
                self.reg[rd_lo] = str(self._u32(product))
                self.reg[rd_hi] = str(self._u32(product >> 32))

            elif 'mul' in instr:
                reg_change = True
                rd, rs1, rs2 = aarg.split(',')
                rs1 = rs1.replace(' ','')
                rs2 = rs2.replace(' ','')
                rd = rd.replace(' ','')
                rs1_val = int(self.reg[rs1])
                rs2_val = int(self.reg[rs2])
                rd_val = (rs1_val * rs2_val) & 0xFFFFFFFF
                self.reg[rd] = str(rd_val)
            
            elif 'sdiv' in instr:
                reg_change = True
                rd, rs1, rs2 = [a.strip() for a in aarg.split(',')]
                rs1_val = self._s32(int(self.reg[rs1]))
                rs2_val = self._s32(int(self.reg[rs2]))
                if rs2_val == 0:
                    rd_val = 0
                else:
                    q = abs(rs1_val) // abs(rs2_val)
                    if (rs1_val < 0) != (rs2_val < 0):
                        q = -q
                    rd_val = self._u32(q)
                self.reg[rd] = str(rd_val)

            elif 'udiv' in instr:
                reg_change = True
                rd, rs1, rs2 = aarg.split(',')
                rs1 = rs1.replace(' ','')
                rs2 = rs2.replace(' ','')
                rd = rd.replace(' ','')
                rs1_val = int(self.reg[rs1]) & 0xFFFFFFFF
                rs2_val = int(self.reg[rs2]) & 0xFFFFFFFF
                if rs2_val == 0:
                    # Default (SCB->CCR.DIV_0_TRP = 0): result is 0, no fault
                    rd_val = 0
                else:
                    rd_val = rs1_val // rs2_val
                self.reg[rd] = str(rd_val)
            
            else:
                self.logFile = open('./logs/Emulator.log', 'a')
                print(f"\nINSTRUCTION NOT SUPPORTED --({addr}): {instr} {aarg}")
                self.logFile.close()
                # a = input()
                sys.exit(1)

        elif self.arch.type == 'elf32-msp430':
            arg = aarg.replace('r10', 'ra')
            arg = arg.replace('r11', 'rb')
            arg = arg.replace('r12', 'rc')
            arg = arg.replace('r13', 'rd')
            arg = arg.replace('r14', 're')
            arg = arg.replace('r15', 'rf')

            if 'clr' in instr:
                new_instr = AssemblyInstruction(addr,'mov',f'#0,{aarg}')
                # print(f"remapping {asm_inst} --> {new_instr}")
                # a = input()
                valid = self.step(new_instr)

            if 'rla' in instr:
                new_instr = AssemblyInstruction(addr,'add',f'{aarg},{aarg}')
                # print(f"remapping {asm_inst} --> {new_instr}")
                # a = input()
                valid = self.step(new_instr)

            elif 'call' in instr:
                #call moves sp up the stack
                sp_val = self.evaluate_expression(self.reg['r1']+'- 2')
                self.reg['r1'] = sp_val
                reg_change = True

            elif 'ret' in instr:
                #call moves sp down the stack
                sp_val = self.evaluate_expression(self.reg['r1']+'+ 2')
                self.reg['r1'] = sp_val
                reg_change = True

            elif 'cmp' in instr:
                #determine if cmp to reg or imm
                y,x = arg.split(',')
                conditional_print(f"x: {x}",file=self.debugFile, flag=self.debug)
                conditional_print(f"y: {y}",file=self.debugFile, flag=self.debug)
                # print(f"x : {x}")
                # print(f"y : {y}")
                try:
                    reg_val_1 = self.reg[x]
                except KeyError:
                    reg_val_1 = f'y{self.symbolic_count}'
                    self.reg[x] = reg_val_1
                    self.symbolic_count+=1

                if 'r' in y:
                    # y is reg
                    try:
                        reg_val_2 = self.reg[y]
                    except KeyError:
                        reg_val_2 = f'y{self.symbolic_count}'
                        self.reg[y] = reg_val_2
                        self.symbolic_count+=1

                    diff = self.evaluate_expression(reg_val_1+' - '+reg_val_2)           
                else:
                    # y is imm
                    y = y.replace('#','')
                    diff = self.evaluate_expression(reg_val_1+' - '+y)
            
                conditional_print(f"diff: {diff}",file=self.debugFile, flag=self.debug)
                self.update_sr(diff)
                conditional_print(self.sr, file=self.debugFile, flag=self.debug)
                #comparison
                # return valid

            elif 'mov' in instr:
                src,dest = arg.split(",")
                if '@' in src or '(' in src:
                    self.mem_accesses += 1
                    # src is mem ref
                    conditional_print("src from reg mem ref", file=self.debugFile, flag=self.debug)
                    if '@' in src:
                        idx = '0'
                        b = src.replace('@', '')
                    else:
                        idx,b = src[:-1].split('(')
                        if '-' not in idx:
                            idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    conditional_print(f"trying to lookup {mem_addr} in mem[]", file=self.debugFile, flag=self.debug)
                    if '.b' in instr:
                        # source is a byte
                        try:
                            #src_val = self.mem[mem_addr]
                            src_val = self.read_from_mem(mem_addr)
                        except KeyError:
                            conditional_print(f"cant find {mem_addr} in mem[]", file=self.debugFile, flag=self.debug)
                            src_val = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            self.mem[mem_addr] = src_val
                        conditional_print(f"byte src_val = {src_val}", file=self.debugFile, flag=self.debug)
                    else:
                        # source is a word 
                        mem_addr_upper = self.evaluate_expression(self.reg[b]+idx+'- 1')
                        mem_addr_lower = self.evaluate_expression(self.reg[b]+idx)
                        conditional_print(f"word mem_addr_upper = {mem_addr_upper}", file=self.debugFile, flag=self.debug)
                        conditional_print(f"word mem_addr_lower = {mem_addr_lower}", file=self.debugFile, flag=self.debug)
                        if mem_addr_lower in self.mem.keys() and mem_addr_upper in self.mem.keys():
                            #src_val_upper = self.mem[mem_addr_upper]
                            src_val_upper = self.read_from_mem(mem_addr)
                            #src_val_lower = self.mem[mem_addr_lower]
                            src_val_lower = self.read_from_mem(mem_addr)
                            if 'y' not in src_val_lower and 'y' not in src_val_upper:
                                src_val = int(src_val_upper) | int(src_val_lower)
                                conditional_print(f"word src_val = {hex(src_val)}", file=self.debugFile, flag=self.debug)
                                src_val = str(src_val)
                            else:
                                src_val = 'y'+str(self.symbolic_count)
                                self.symbolic_count += 1 
                        else:
                            src_val = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1 

                elif 'r' in src:
                    #reg that isn't a mem ref
                    conditional_print("src from reg", file=self.debugFile, flag=self.debug)
                    try:
                        src_val = self.reg[src]
                    except KeyError:
                        src_val = "y"+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.reg[src] = src_val
                elif '#' in src:
                    conditional_print("src from imm", file=self.debugFile, flag=self.debug)
                    src_val = src.replace("#", '')
                    if '-' in src_val:
                        src_val = int(src_val) % (2**16)
                        conditional_print(f"src_val = {hex(src_val)}", file=self.debugFile, flag=self.debug)
                        src_val = str(src_val)
                    conditional_print(f"src_val = {src_val}", file=self.debugFile, flag=self.debug)
                elif '&' in src:
                    self.mem_accesses += 1
                    conditional_print("src from fixed mem ref", file=self.debugFile, flag=self.debug)
                    # fixed mem_addr reference --> also in hex
                    mem_addr = str(int(src.replace('&', ' '), 16))
                    try:
                        #src_val = self.mem[mem_addr]
                        src_val = self.read_from_mem(mem_addr)
                    except KeyError:
                        src_val = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.mem[mem_addr] = src_val

                if '@' in dest or '(' in dest:
                    self.mem_accesses += 1
                    # src is mem ref
                    conditional_print("dest is reg mem ref", file=self.debugFile, flag=self.debug)
                    if '@' in dest:
                        idx = '0'
                        b = dest.replace('@', '')
                    else:
                        idx,b = dest[:-1].split('(')
                        if '-' not in idx:
                            idx = '+'+idx
                        if b not in self.reg.keys():
                            self.reg[b] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                    conditional_print(f"idx = {idx}, b={self.reg[b]}", file=self.debugFile, flag=self.debug)
                    mem_change = True
                    if '.b' in instr or 'x' in src_val: 
                        # byte operation
                        mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                        self.mem[mem_addr] = src_val
                        conditional_print(f"wrote mem[{mem_addr}] = {src_val}", file=self.debugFile, flag=self.debug)
                        # need to check validity of val is not static 
                        # if 'r' in src:
                        valid = self.compare_to_base(mem_addr)
                    else:
                        # word operation
                        mem_addr_lower = self.evaluate_expression(self.reg[b]+idx)
                        mem_addr_upper = self.evaluate_expression(self.reg[b]+idx+'- 1') # minus is "up" for msp430
                        if 'y' in src_val:
                            src_val_upper = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            src_val_lower = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            src_val_uppper_str = src_val_upper
                            src_val_lower_str = src_val_lower
                        else:
                            src_val_upper = str(int(src_val) & 0xff00)
                            src_val_lower = str(int(src_val) & 0x00ff)
                            src_val_uppper_str = hex(int(src_val_upper))
                            src_val_lower_str = hex(int(src_val_lower))
                        
                        self.mem[mem_addr_lower] = src_val_lower
                        self.mem[mem_addr_upper] = src_val_upper
                        
                        conditional_print(f"wrote mem[{mem_addr_lower}] = {src_val_uppper_str}", file=self.debugFile, flag=self.debug)
                        conditional_print(f"wrote mem[{mem_addr_upper}] = {src_val_lower_str}", file=self.debugFile, flag=self.debug)
                        # need to check validity of val is not static 
                        if 'r' in src:
                            valid_lower = self.compare_to_base(mem_addr_lower)
                            valid_upper = self.compare_to_base(mem_addr_upper)
                            valid = (valid_lower and valid_upper)

                        mem_addr = [mem_addr_lower, mem_addr_upper]

                elif 'r' in dest:
                    conditional_print("dest is reg", file=self.debugFile, flag=self.debug)
                    self.reg[dest] = src_val
                    reg_change = True
                    conditional_print(f"wrote {dest} = {src_val}", file=self.debugFile, flag=self.debug)

                elif '&' in dest:
                    self.mem_accesses += 1
                    conditional_print("dest is fixed mem ref", file=self.debugFile, flag=self.debug)
                    mem_addr = str(int(dest.replace('&', ' '), 16))
                    if '.b' in instr:
                        self.mem[mem_addr] = src_val
                        mem_change = True
                        conditional_print(f"wrote mem[{mem_addr}] = {src_val}", file=self.debugFile, flag=self.debug)
                        # need to check validity of val is not static 
                        if 'r' in src:
                            valid = self.compare_to_base(mem_addr)

            elif 'incd' in instr:
                if '(' in arg:
                    idx,b = arg[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    try:
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 2"
                    except:
                        self.mem[mem_addr] = f'y{self.symbolic_count}'
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 2"
                        self.symbolic_count += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                    self.mem_accesses += 1
                else:
                    self.reg[arg] += '+ 2' 
                    reg_change = True
            
            elif 'decd' in instr:
                if '(' in arg:
                    idx,b = arg[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    try:
                        self.mem[mem_addr] = self.mem[mem_addr] + " - 2"
                    except:
                        self.mem[mem_addr] = f'y{self.symbolic_count}'
                        self.mem[mem_addr] = self.mem[mem_addr] + " - 2"
                        self.symbolic_count += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                    self.mem_accesses += 1
                else:
                    self.reg[arg] += '- 2' 
                    reg_change = True

            elif 'inc' in instr:
                if '(' in arg:
                    idx,b = arg[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    try:
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 1"
                    except:
                        self.mem[mem_addr] = f'y{self.symbolic_count}'
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 1"
                        self.symbolic_count += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                    self.mem_accesses += 1
                else:
                    self.reg[arg] += '+1' 
                    reg_change = True

            elif 'add' in instr:
                src,dest = arg.split(",")

                ## parse src to get add value
                if '#' in src: #add imm
                    src = src.replace('#', '')
                    if '-' not in src:
                        src = '+ '+src
                    add_val = src
                    # self.reg[dest] += src

                elif '(' in src: #add from mem
                    idx,b = src[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    add_val = '+ ('+self.mem[mem_addr]+')'
                    self.mem_accesses += 1
                    # self.reg[dest] += '+ ('+self.mem[mem_addr]+')'

                elif 'r' in src:
                    add_val = '+ '+self.reg[src]

                ## parse dest to get destination
                if '(' in dest:
                    idx,b = dest[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    self.mem[mem_addr] += add_val
                    self.mem_accesses += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                
                elif 'r' in dest:
                    self.reg[dest] += add_val
                    reg_change = True

            elif 'sub' in instr:
                src,dest = arg.split(",")
                if '#' in src:
                    src = src.replace('#', '')
                elif '(' in src: # sub from mem
                    idx,b = src[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    #src = self.mem[mem_addr]
                    src = self.read_from_mem(mem_addr)
                    self.mem_accesses += 1
                else: # src is a reg
                    src = self.reg[src]
                self.reg[dest] += '-('+src+')'
                reg_change = True

            elif 'push' in instr:
                if self.mode == 'ret-exploit' and self.first_push:
                    self.first_push = False
                else:
                    # in msp430, push to mem @ sp
                    try:
                        self.mem[self.reg['r1']] = self.reg[arg]
                    except KeyError:
                        self.mem[self.reg['r1']] = arg
                    self.mem_accesses += 1
                    mem_addr = self.reg['r1']
                    # valid = self.compare_to_base(self.reg['r1'])
                    sp_val = self.evaluate_expression(self.reg['r1']+'- 2')
                    self.reg['r1'] = sp_val
                    conditional_print(f"self.reg['r1'] = {self.reg['r1']}", file=self.debugFile, flag=self.debug)
                    mem_change = True
                    reg_change = True

            elif 'pop' in instr:    
                # in msp430, push to mem @ sp
                #reverse of push, so incr r1 first
                sp_val = self.evaluate_expression(self.reg['r1']+'+ 2')
                self.reg['r1'] = sp_val
                #then fetch val from mem
                try:
                    #self.reg[arg] = self.mem[self.reg['r1']]
                    self.reg[arg] = self.read_from_mem(self.reg['r1'])
                except KeyError:
                    if self.mode == 'data-log':
                        print("SHOULD NOT HAVE REACHED HERE: pop")
                    conditional_print(f"No result for mem[{self.reg['r1']}]", file=self.debugFile, flag=self.debug)
                    self.mem[self.reg['r1']] = 'y'+str(self.symbolic_count)
                    self.reg[arg] = self.mem[self.reg['r1']]
                    self.symbolic_count += 1
                reg_change = True
                self.mem_accesses += 1

        string = ''
        if reg_change:
            self.update_regs()
            string += 'Regs of Interest:\n'
            for key in self.reg.keys():
                try:
                    string += f"{key} : {hex(int(self.reg[key]))} ({self.reg[key]})\n"
                except ValueError:
                    string += f"{key} : {self.reg[key]}\n"
            #'''
        if mem_change:
            if isinstance(mem_addr, str):
                mem_addr = [mem_addr]
            # print(len(mem_addr))
            string += 'Memory of Interest:\n'
            for key in self.mem.keys():
                try:
                    string += f"{hex(int(key))} ({key}) : "
                except ValueError:
                    string += f"{key} : "
                try:
                    string += f"{hex(int(self.mem[key]))} ({self.mem[key]})\n"
                except ValueError:
                    string += f"{self.mem[key]}\n"

            self.update_mem(mem_addr)
        
        # conditional_print(self, file=self.debugFile, flag=self.debug)
        # if 'sp' in aarg or 'push' in instr or 'pop' in instr:
        #     conditional_print(f"sp: {hex(int(self.reg['sp']))} ({self.reg['sp']})", file=self.debugFile, flag=self.debug)
        # conditional_print(self, file=self.debugFile, flag=self.debug)
        if reg_change or mem_change:
            conditional_print(string, file=self.debugFile, flag=self.debug)
            conditional_print('\n', file=self.debugFile, flag=self.debug)
        return valid

    def update_regs(self):
        # start = time.perf_counter()
        conditional_print("updating regs...", file=self.debugFile)
        #print(self.reg.keys())
        for key in self.reg.keys():
            for k in self.reg.keys():
                if key == k:
                    continue

                if isinstance(self.reg[k], int):
                    self.reg[k] = str(self.reg[k])

                if key in self.reg[k]:
                    conditional_print(f"\treplace {key} with {self.reg[key]} in self.reg[{k}]", file=self.debugFile, flag=self.debug)
                    self.reg[k] = self.reg[k].replace(key, self.reg[key])

            # print(f"trying {key} = simplify({self.reg[key]})", file=self.debugFile)
        for key in self.reg.keys():    
            self.reg[key] = self.evaluate_expression(self.reg[key])

        if self.mode == 'data-log':
            # Keep every register as a 32-bit unsigned value in this mode.
            for key in self.reg:
                try:
                    self.reg[key] = str(self._u32(int(self.reg[key])))
                except (ValueError, TypeError):
                    pass
        # self.reg = dict(sorted(self.reg.items()))
        # stop = time.perf_counter()
        # print(f"Update reg time: {1000*(stop-start)}")

    def update_mem(self, mem_addrs):
        # start = time.perf_counter()
        conditional_print("updating mem...", file=self.debugFile, flag=self.debug)
        # mk_list = list(self.mem.keys())
        for mk in mem_addrs:
            if 'r' in mk:
                for rk in self.reg.keys():
                    if rk in mk:
                        new_mk = mk.replace(rk, self.reg[rk])
                        new_mk = self.evaluate_expression(new_mk)
                        self.mem[new_mk] = self.mem.pop(mk)
            elif 'sp' in mk:
                rk = 'sp'
                new_mk = mk.replace(rk, self.reg[rk])
                new_mk = self.evaluate_expression(new_mk)
                self.mem[new_mk] = self.mem.pop(mk)
            else:
                self.mem[mk] = self.evaluate_expression(self.mem[mk])
            try:
                val_str = hex(int(self.mem[mk]))
            except (ValueError, TypeError):
                val_str = str(self.mem[mk])
            conditional_print(f"{hex(int(mk))} changed to {val_str} ({self.mem[mk]})", self.debugFile, self.debug)
        self.mem = dict(sorted(self.mem.items()))
        # stop = time.perf_counter()
        # print(f"Update mem time: {1000*(stop-start)}")

    def evaluate_expression(self, expr):
        # start = time.perf_counter()
        x = symbols('x')
        
        try:
            simplified = simplify(expr)
            # stop = time.perf_counter()
            # print(f"Evalute time: {1000*(stop-start)}")
            # print(f"{expr} --> {str(simplified)}")
            return str(simplified)
        except Exception as e:
            # print(f'Exception: {e}', file=self.debugFile)
            # print(f'\texpr: {expr}', file=self.debugFile)
            # a = input()
            return expr

    def get_cond_branch_dest(self, asm_inst):
        ## Should return 0 for not taken, 1 for taken

        addr = asm_inst.addr
        instr = asm_inst.instr
        aarg = asm_inst.arg
        conditional_print(f"Getting dest from ({addr}): {instr} {aarg}\n",file=self.debugFile, flag=self.debug)
        if self.arch.type == 'armv8-m33':
            base = instr.split('.')[0]
            if base.startswith('cb'):
                reg = aarg.split(',')[0].strip()
                val = self._u32(int(self.reg.get(reg, 0)))
                if base.startswith('cbz'):
                    return int(val == 0)
                if base.startswith('cbnz'):
                    return int(val != 0)
            if base == 'b':
                return 1
            if base.startswith('b') and base[1:] in self.COND_CODES:
                return int(self.eval_cond(base[1:]))
            conditional_print(f'Support for {instr} not in get_cond_branch_dest()',
                              file=self.debugFile, flag=self.debug)
            return 0

        elif self.arch.type == 'elf32-msp430':
            if 'jeq' in instr or 'jz' in instr:
                return self.sr['Z']
            elif 'jne' in instr or 'jnz' in instr:
                return self.sr['Z'] ^ 1
            elif 'jge' in instr:
                return (self.sr['N'] ^ 1) | self.sr['Z']
            elif 'jl' in instr:
                return self.sr['N']
            else:
                conditional_print(f'Support for {instr} not in get_cond_branch_dest()', file=self.debugFile, flag=self.debug)
                return 0

