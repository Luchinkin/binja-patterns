from binaryninja import *
from capstone import *
from capstone.x86 import *
import struct
import re
import pyperclip

MAX_PROCESS_INSTRUCTIONS = 128

ASM_OPCODE_CALL = 0xE8
ASM_OPCODE_JMP = 0xE9

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def to_unsigned(val, size):
    if size == 1:
        format_str = 'B'
    elif size == 2:
        format_str = 'H'
    elif size == 4:
        format_str = 'I'
    elif size == 8:
        format_str = 'Q'
    else:
        print(f'Unsupported size: {size}')
        raise ValueError("Unsupported size")

    packed = struct.pack(format_str, val & (2**(size*8)-1))
    return struct.unpack(format_str, packed)[0]


class PatternInstruction:
    def __init__(self, bv: binaryninja.BinaryView, addr):
        self.bv = bv
        self.address = addr

        data = self.bv.read(addr, self.bv.arch.max_instr_length)
        self.instruction = self.bv.arch.get_instruction_info(data, addr)

        if not self.instruction:
            self.bytes = []
            self.mask = []
            return

        self.bytes = data[0:self.instruction.length]
        self.mask = [True] * len(self.bytes)

        self.analyze()

    def size(self):
        return self.instruction.length

    def get(self, idx):
        return self.bytes[idx]

    def mask(self):
        return self.mask

    def analyze(self):
        opcode_size = self.instruction.length

        if self.bytes[0] == ASM_OPCODE_CALL or self.bytes[0] == ASM_OPCODE_JMP:
            self.mask = [True] + [False] * (len(self.mask) - 1)
            return

        is_branching = len(self.instruction.branches) > 0
        if is_branching and len(self.mask) > 2:
            self.mask = [True, True] + [False] * (len(self.mask) - 2)
            return
        elif is_branching and len(self.mask) == 2:
            self.mask = [True, False]
            return

        capinst: CsInsn = next(md.disasm(self.bytes, self.address))

        for i in reversed(range(len(capinst.operands))):
            op = capinst.operands[i]
            if op.type == X86_OP_MEM:
                disp = op.mem.disp
                if disp == 0:
                    continue
                self.apply_mask_by_search(to_unsigned(
                    disp, capinst.disp_size), capinst.disp_size)
            elif op.type == X86_OP_IMM:
                imm = op.imm
                self.apply_mask_by_search(to_unsigned(
                    imm, capinst.imm_size), capinst.imm_size)
            elif op.type not in [X86_OP_REG, X86_OP_MEM]:
                self.mask = self.mask[:opcode_size] + \
                    [False] * (len(self.mask) - opcode_size)
                break
            opcode_size += op.size
            self.mask[0] = True

    def apply_mask_by_search(self, val, size):
        for i in range(len(self.bytes) - size + 1):
            if int.from_bytes(self.bytes[i:i+size], byteorder='little') == val:
                self.mask = self.mask[:i] + [False] * (len(self.mask) - i)
                break


def generate_pattern_str(bytes, mask, double_wildcard):
    pattern = []
    for byte, mask_bit in zip(bytes, mask):
        if mask_bit:
            pattern.append(f'{byte:02X}')
        else:
            if double_wildcard:
                pattern.append('??')
            else:
                pattern.append('?')
    return ' '.join(pattern)


def find_pattern_executable_optimized(bv, ignore_addr, pattern):
    pattern_bytes = [None if b in ["??", "?"] else int(
        b, 16) for b in re.split(r'\s+', pattern.strip())]
    pattern_length = len(pattern_bytes)

    first_non_wildcard_byte = next(
        (b for b in pattern_bytes if b is not None), None)

    for seg in bv.segments:
        if not seg.executable:
            continue

        segment_data = bv.read(seg.start, seg.end - seg.start)
        if not segment_data:
            continue

        if first_non_wildcard_byte is not None:
            first_byte_positions = [i for i in range(len(
                segment_data) - pattern_length + 1) if segment_data[i] == first_non_wildcard_byte]
            for start_pos in first_byte_positions:
                addr = seg.start + start_pos
                if addr == ignore_addr:
                    continue

                found = all(pattern_byte is None or segment_data[start_pos + i]
                            == pattern_byte for i, pattern_byte in enumerate(pattern_bytes))

                if found:
                    return addr
        else:
            for addr in range(seg.start, seg.end - pattern_length + 1):
                if addr != ignore_addr:
                    return addr

    return None


class PatternFinder(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__("Searching for pattern...", True)
        self.bv = bv

    def run(self):
        pattern_bytes = get_text_line_input("Find", "Patterns")
        if not pattern_bytes:
            show_message_box("Patterns", "Empty pattern!",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        pattern_str = pattern_bytes.decode('utf-8')
        print(pattern_str)

        addr = find_pattern_executable_optimized(self.bv, None, pattern_str)
        if addr:
            print(f"Pattern found at: 0x{addr:x}")
        else:
            show_message_box("Pattern", "Pattern not found",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


class PatternGenerator(BackgroundTaskThread):
    def __init__(self, bv, addr):
        super().__init__("Generating pattern...", True)
        self.bv = bv
        self.addr = addr

    def run(self):
        gbytes, gmask, offset = [], [], 0
        found = False

        if not self.bv.allocated_ranges:
            show_message_box("Patterns", "Couldn't find allocated ranges!",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        if not self.bv.segments:
            show_message_box("Patterns", "Couldn't find segments!",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return

        pattern = None

        for _ in range(MAX_PROCESS_INSTRUCTIONS):
            cur_addr = self.addr + offset
            inst = PatternInstruction(self.bv, cur_addr)
            gbytes.extend(inst.bytes)
            gmask.extend(inst.mask)
            pattern = generate_pattern_str(gbytes, gmask, False)
            offset += inst.size()

            if not find_pattern_executable_optimized(self.bv, self.addr, pattern):
                found = True
                break

        if found:
            print(f'Found pattern for 0x{self.addr:x}: {pattern}')
            pyperclip.copy(pattern)
            show_message_box("Pattern", "Pattern found and copied to clipboard!",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        else:
            show_message_box("Patterns", f'Couldn\'t find pattern for 0x{self.addr:x}!',
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


def find_pattern_act(bv: binaryninja.BinaryView):
    worker = PatternFinder(bv)
    worker.start()


def generate_pattern_act(bv: binaryninja.BinaryView, addr: int):
    worker = PatternGenerator(bv, addr)
    worker.start()


def is_supported_arch(bv: binaryninja.BinaryView, addr=0):
    return bv.arch.name == 'x86_64'


PluginCommand.register("Find pattern", "", find_pattern_act, is_supported_arch)
PluginCommand.register_for_address(
    "Generate pattern", "", generate_pattern_act, is_supported_arch)
