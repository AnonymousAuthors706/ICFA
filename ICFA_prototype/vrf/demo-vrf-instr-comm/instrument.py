import re
import argparse

INFILE = "application.s"  # Default filenames for convience... except another part of the pre_process script needs them specified so uh yeah
OUTFILE = "instrument.s"
STACKBASE_TOP = "#0x2003"  # Base of the Stack per sample runs, split in two to be laoded to registers properly
STACKBASE_BOTTOM = "#0xFFF8"
LOADS = 0
GENERAL_PURPOSE_REGS = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","r13","r14","r15"]  # Reg list for later comparisons

"""
This file implements ICFA's intrumentation engine. The file loads the uninstrumented binary and first identifies unused system registers to use
  for the stack base, load source address, load size, and load type. It then iterates through the file to instrument any load instructions
  that may load external inputs
"""


def arg_parser():
    '''
    Parse the arguments of the program
    Return:
        object containing the arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('--infile', type=str, required=True,
                        help='input assembly file name (.s)')
    parser.add_argument('--dir', type=str, default='./',
                        help='directory of input/output files')
    parser.add_argument('--outfile', type=str, default='instrumented_app',
                        help='output file name (.s)')
    
    args = parser.parse_args()
    return args


def get_register_count(arguments):
    """
    determines the number of registers loaded for multi-load instructions
    args:
        arguments (str) - The assembly lines arguments
    returns:
        (int, int) The count of registers loaded and whether the registers are double floating point (aka double word) registers
    """
    count = 0
    doubleword = 0
    sentinel = 1
    reg_list = re.search("{(.*?)}", arguments)
    reg_list = reg_list.group().split(",")
    for reg in reg_list:
        if sentinel:
            if reg.strip().lower()[0] == "d":
                doubleword = 1
            sentinel = 0
            
        if "-" in reg: # if using '-' shorthand, we must do a little more processing
            reg = reg.strip().split("-")
            count += int(re.search("[0-9]+", reg[1]).group()) - int(re.search("[0-9]+", reg[0]).group()) + 1
            
        else:
            count += 1    
    return count, doubleword
    

def get_addr(arguments):
    """
    Determines the base address used in a load
    args:
        arguments (str) - The arguments for the assembly instruction
    returns:
        (str) The address used by the load
    """
    if "]" in arguments:
        addr = re.search("\[(.*?)\]", arguments).group()
    else:
        addr = arguments.split(",")[-1].strip()
    return addr
    
    
def build_nsc(addr, size, options, regs):
    """
    Build the associated instrumentation for each load instruction
    args:
        addr (str) - The source address/parameters that become the source address of the load
        size (int) - The size of the read
        options (int) - An int to signal which load type should be used
        regs (list(str)) - The registers that we are free to use
    returns:
        The instrumentation to use for the current load instruction
    """
    global STACKBASE
    global LOADS
    
    # If the source is the stack pointer, then the data is on the stack and thus does not need to be checked
    if addr == "[sp]" or addr == "sp":
        return  ""
    
    # for trampoline to work, must assume we have 4 registers to fix    
    nsc_regs = regs[1:4]
    nsc = ""
        
    # remove the surrounding brackets for simpler parsing
    if "]" in addr:
        addr = addr[1:-1]
     
    addr_tokens = addr.split(",")
    if len(addr_tokens) == 3:  # [R_source, R_shift, Shift] - In prior docs there were multiple shift options, but it may have been reduced to LSL only recently
        shift_tokens = addr_tokens[2].strip().split(" ")
        if shift_tokens[0].lower() == "asr":
            nsc += f"\tasr\t{nsc_regs[0]}, {addr_tokens[1].strip()}, {shift_tokens[1].strip()}\n"
        elif shift_tokens[0].lower() == "lsl":
            nsc += f"\tlsl\t{nsc_regs[0]}, {addr_tokens[1].strip()}, {shift_tokens[1].strip()}\n"
        elif shift_tokens[0].lower() == "lsr":
            nsc += f"\tlsr\t{nsc_regs[0]}, {addr_tokens[1].strip()}, {shift_tokens[1].strip()}\n"
        elif shift_tokens[0].lower() == "ror":
            nsc += f"\tror\t{nsc_regs[0]}, {addr_tokens[1].strip()}, {shift_tokens[1].strip()}\n"
        elif shift_tokens[0].lower() == "rrx":
            nsc += f"\trrx\t{nsc_regs[0]}, {addr_tokens[1].strip()}\n"
        nsc += f"\tadd\t{nsc_regs[0]}, {addr_tokens[0].strip()}\n"             
    elif len(addr_tokens) == 2:  
        if addr_tokens[1].strip()[0] == "#":  # [R_source, #offset]
            nsc += f"\tmov\t{nsc_regs[0]}, {addr_tokens[0].strip()}\n\tadd\t{nsc_regs[0]}, {addr_tokens[1].strip()}\n"
        elif "#" in addr_tokens[1] or "rrx" in addr_tokens[1]:  # [R_source, Shift] - Not technically in the documentation, but the examples in the docs often controdict themselves so safety check
            shift_tokens = addr_tokens[1].strip().split(" ")
            if shift_tokens[0].lower() == "asr":
                nsc += f"\tasr\t{nsc_regs[0]}.], {addr_tokens[0].strip()}, {shift_tokens[1].strip()}\n"
            elif shift_tokens[0].lower() == "lsl":
                nsc += f"\tlsl\t{nsc_regs[0]}, {addr_tokens[0].strip()}, {shift_tokens[1].strip()}\n"
            elif shift_tokens[0].lower() == "lsr":
                nsc += f"\tlsr\t{nsc_regs[0]}, {addr_tokens[0].strip()}, {shift_tokens[1].strip()}\n"
            elif shift_tokens[0].lower() == "ror":
                nsc += f"\tror\t{nsc_regs[0]}, {addr_tokens[0].strip()}, {shift_tokens[1].strip()}\n"
            elif shift_tokens[0].lower() == "rrx":
                nsc += f"\trrx\t{nsc_regs[0]}, {addr_tokens[0].strip()}\n"
        else:  # [R_source, R_offset]
            nsc += f"\tmov\t{nsc_regs[0]}, {addr_tokens[0].strip()}\n\tadd\t{nsc_regs[0]}, {addr_tokens[1].strip()}\n"
    elif addr.strip() not in GENERAL_PURPOSE_REGS:  # [label] - If its a label then its based on PC and in program memory so we ignore it
        return ""
    else:  # [R_source]
        nsc += f"\tmov\t{nsc_regs[0]}, {addr}\n"
    
    #  Call the trampoline
    nsc += f"\tmov\t{nsc_regs[1]}, #{size}\n\tmov\t{nsc_regs[2]}, #{options}\n\tbl\t.L{LOADS}\n"
    
    return nsc
    

def main():
    """
    The main method. Responsible for loading the binary and identifying the load instructions in it before outputing the instrumented binary
    """
    global INFILE
    global OUTFILE
    global LOADS
    global GENERAL_PURPOSE_REGS
    
    
    arguments = arg_parser()
    
    # main assembly processing    
    instrumented_assembly = ""   
    with open(INFILE, "r") as ifp:
        assembly = ifp.read()
    
    # Steal the spice trade
    registers_to_claim = []
    registers = re.findall("r[0-9]+", assembly)
    registers = set(registers)
    registers.add("r13")  # Add the special registers (i.e., SP, PC, LR)
    registers.add("r14")
    registers.add("r15")
    print(f"Registers already used: {registers}")
    for register in GENERAL_PURPOSE_REGS:
        if register not in registers:
            registers_to_claim.append(register)
    reserved_regs = registers_to_claim[0:4]
    print(f"ICFA selected registers: {reserved_regs}")
            
    # Figure out the label we can use for the trampoline
    labels = re.findall(".L[0-9]+", assembly)
    for label in labels:
        temp = int(label.strip()[2:])
        if temp > LOADS:
            LOADS = temp
    LOADS = LOADS + 1
    
    section_start = 0    
    application = 0    
    need_pop = 0
    # instrument the binary    
    for inst in assembly.split("\n"):
        inst_copy = inst.strip()
        inst_copy = inst_copy.split("\t")
        command = inst_copy[0].lower().strip()
        command_len = len(command)
        
        # Check if line is a function label
        if ":" in command and command[0] != ".":  
            section_start = 1  # Start of a function
            if command == "application:":
                application = 1  # main function (at least in these test files)
            instrumented_assembly += inst + "\n"
            continue
            
        # If the start of a section and first instruction is a push    
        if section_start and command[0:4] == "push":
            if "lr" not in inst:  # is the link register already handled?
                inst = inst.replace("}", ",lr}")
                need_pop = 1
            instrumented_assembly += inst + "\n"
            section_start = 0  
            if application:  # If start of application, add stack base setup
                instrumented_assembly += f"\tmovw\t{reserved_regs[0]}, {STACKBASE_BOTTOM}\n\tmovt\t{reserved_regs[0]}, {STACKBASE_TOP}\n"
                application = 0
            continue
        
        # If end of function is found and the function requires a pop to lr
        if need_pop and inst == "\tldr\tr7, [sp], #4":
           instrumented_assembly += inst + "\n"
           instrumented_assembly += "\tpop\t{lr}\n"
           need_pop = 0
           continue
        
        # Manual instrumentation for testing purposes
        """   
        if command == "pre":
           instrumented_assembly += "\tmov\tr5, sp\n\tsub\tr5, #500\n\tmov\tr6, #25\n"
           continue
        elif command == "here":
           instrumented_assembly += "\tlsl\tr4, r6, #3\n\tadd\tr4, r5\n\tmov\tr5, #1\n\tmov\tr6, #0\n\tbl\t.L6\n"
           continue
        """
        
        # Load instruction intrumentation
        # LDR
        if command[:3] == "ldr":
            addr = get_addr(inst_copy[1])
            if command_len >= 4:
                if command[3] == "d":
                    instrumented_assembly += build_nsc(addr, 8, 0, reserved_regs)
                elif command[3] == "b":
                    instrumented_assembly += build_nsc(addr, 1, 0, reserved_regs)
                elif command[3:5] == "sb":
                    instrumented_assembly += build_nsc(addr, 1, 1, reserved_regs)
                elif command[3] == "h":
                    instrumented_assembly += build_nsc(addr, 2, 0, reserved_regs)
                elif command[3:5] == "sh":
                    instrumented_assembly += build_nsc(addr, 2, 1, reserved_regs)
                elif command[3:5] == "ex":
                    if command_len >= 6 and command[5] == "b":
                        instrumented_assembly += build_nsc(addr, 1, 0, reserved_regs)
                    elif command_len >= 6 and command[5] == "h":
                        instrumented_assembly += build_nsc(addr, 2, 0, reserved_regs)
                    else:
                        instrumented_assembly += build_nsc(addr, 4, 0, reserved_regs)
                else: # LDRT and conditional LDRs
                    instrumented_assembly += build_nsc(addr, 4, 0, reserved_regs)
            else: # LDR
                instrumented_assembly += build_nsc(addr, 4, 0, reserved_regs)
        #LDA
        elif command[:3] == "lda":
            addr = get_addr(inst_copy[1])
            if command_len >= 4:
                if command[3] == "b": 
                    instrumented_assembly += build_nsc(addr, 1, 0, reserved_regs)
                elif command[3] == "h":
                    instrumented_assembly += build_nsc(addr, 2, 0, reserved_regs)
                elif command[3:5] == "ex":
                    if command_len >= 6 and command[5] == "b":
                        instrumented_assembly += build_nsc(addr, 1, 0, reserved_regs)
                    elif command_len >= 6 and command[5] == "h":
                        instrumented_assembly += build_nsc(addr, 2, 0, reserved_regs)
                    else:
                        instrumented_assembly += build_nsc(addr, 4, 0, reserved_regs)
                else:
                    instrumented_assembly += build_nsc(addr, 4, 0, reserved_regs)
            else:
                instrumented_assembly += build_nsc(addr, 4, 0, reserved_regs)
            
        #LDM
        elif command[:3] == "ldm":
            reg_count, temp = get_register_count(inst_copy[1])
            addr = inst_copy[1].split(",")[0].strip().replace("!", "")
            if command[3:5] == "db" or command[3:5] == "ea":
                instrumented_assembly += build_nsc(addr, (4*reg_count), 2, reserved_regs)
            else:
                instrumented_assembly += build_nsc(addr, (4*reg_count), 0, reserved_regs)
                    
        #VLDM
        elif command[:4] == "vldm":
            reg_count, double = get_register_count(inst_copy[1])
            addr = inst_copy[1].split(",")[0].strip().replace("!", "")
            size = 4
            if "64" in command or double:
                size = 8
            if command[3:5] == "db":
                instrumented_assembly += build_nsc(addr, (size*reg_count), 2, reserved_regs)
            else:
                instrumented_assembly += build_nsc(addr, (size*reg_count), 0, reserved_regs)
            
        #VLDR
        elif command[:4] == "vldr":
            addr = get_addr(inst_copy[1])
            #print("AAAAAA: ", inst_copy[1][0])
            if "64" in command or inst_copy[1][0].strip().lower() == "d":
                instrumented_assembly += build_nsc(addr, 8, 0, reserved_regs)
            else:
                instrumented_assembly += build_nsc(addr, 4, 0, reserved_regs)
        
        # Always remember to reattach the actual instruction regardless of type   
        instrumented_assembly += inst + "\n"

    # Add the trampoline to the bottom of the binary
    instrumented_assembly += f".L{LOADS}:\n\tcmp\t{reserved_regs[1]}, {reserved_regs[0]}\n\tbgt\t.L{LOADS+1}\n\tcmp\tsp, {reserved_regs[1]}\n\tble\t.L{LOADS+2}\n.L{LOADS+1}:\n"
    instrumented_assembly += "\tpush\t{lr}\n\tbl\tSECURE_log_data\n\tpop\t{lr}\n"
    instrumented_assembly += f".L{LOADS+2}:\n\tbx\t lr\n"
    
    
    # save instrumented binary
    with open(OUTFILE, "w") as ofp:
        ofp.write(instrumented_assembly)
            
    # automatically buid the proper NSC call for the ICFA registers selected
    nsc_insert = f'uint32_t read_addr;\n\tasm("mov %0, {reserved_regs[1]}" : "=r"(read_addr));\n'
    nsc_insert += f'\tint size;\n\tasm("mov %0, {reserved_regs[2]}" : "=r"(size));\n'
    nsc_insert += f'\tint options;\n\tasm("mov %0, {reserved_regs[3]}" : "=r"(options));\n'
    nsc_insert += "\tCFA_ENGINE_new_log_data(read_addr, size, options);\n"
               
    # Load the template file
    with open("secure_nsc_template.c", "r") as ifp:
        nsc_file = ifp.read()
    
    # Overwrite hooks
    nsc_file = nsc_file.replace("REGISTER_DATA_SHUFFLING", nsc_insert)
    
    if reserved_regs[0] not in ["r0", "r1", "r2", "r3", "r4", "r7", "r12"]:
        nsc_file = nsc_file.replace("REGISTER_PUSH", ", " + reserved_regs[0])
        nsc_file = nsc_file.replace("REGISTER_POP", ", " + reserved_regs[0])
    else:
        nsc_file = nsc_file.replace("REGISTER_PUSH", "")
        nsc_file = nsc_file.replace("REGISTER_POP", "")
    
    # Save out to the actual implementation
    with open("../../prv/TRACES/Secure/Core/Src/secure_nsc.c", "w") as ofp:
        ofp.write(nsc_file) 
                

if __name__ == '__main__':
	main()
