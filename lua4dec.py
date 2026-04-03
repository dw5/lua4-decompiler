#!/usr/bin/env python3
"""lua4dec - Lua 4.0 bytecode decompiler.

Rewritten in Python from CFLuaDC (VB6) with fixes for:
- String literals incorrectly used as function calls
- Variable name mismatches from stack misalignment
- Malformed expressions from missing bounds checks
- Better control flow reconstruction
"""

import struct
import sys
import argparse
from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ============================================================
# Lua 4 Opcodes
# ============================================================

class Op(IntEnum):
    END = 0
    RETURN = 1
    CALL = 2
    TAILCALL = 3
    PUSHNIL = 4
    POP = 5
    PUSHINT = 6
    PUSHSTRING = 7
    PUSHNUM = 8
    PUSHNEGNUM = 9
    PUSHUPVALUE = 10
    GETLOCAL = 11
    GETGLOBAL = 12
    GETTABLE = 13
    GETDOTTED = 14
    GETINDEXED = 15
    PUSHSELF = 16
    CREATETABLE = 17
    SETLOCAL = 18
    SETGLOBAL = 19
    SETTABLE = 20
    SETLIST = 21
    SETMAP = 22
    ADD = 23
    ADDI = 24
    SUB = 25
    MULT = 26
    DIV = 27
    POW = 28
    CONCAT = 29
    MINUS = 30
    NOT = 31
    JMPNE = 32
    JMPEQ = 33
    JMPLT = 34
    JMPLE = 35
    JMPGT = 36
    JMPGE = 37
    JMPT = 38
    JMPF = 39
    JMPONT = 40
    JMPONF = 41
    JMP = 42
    PUSHNILJMP = 43
    FORPREP = 44
    FORLOOP = 45
    LFORPREP = 46
    LFORLOOP = 47
    CLOSURE = 48

# ============================================================
# Instruction decoding (32-bit: 6-bit op, 9-bit B, 17-bit A)
# ============================================================

_SIZE_OP = 6
_SIZE_B = 9
_SIZE_A = 17
_MASK_OP = (1 << _SIZE_OP) - 1      # 63
_MASK_B = (1 << _SIZE_B) - 1        # 511
_MASK_U = (1 << (32 - _SIZE_OP)) - 1
_S_ZERO = (1 << (32 - _SIZE_OP - 1)) - 1  # 33554431

def get_op(ins):  return Op(ins & _MASK_OP)
def get_u(ins):   return (ins >> _SIZE_OP) & _MASK_U
def get_s(ins):   return ((ins >> _SIZE_OP) & _MASK_U) - _S_ZERO
def get_a(ins):   return ins >> (_SIZE_OP + _SIZE_B)
def get_b(ins):   return (ins >> _SIZE_OP) & _MASK_B

# Comparison operators
CMP_OPS = {
    Op.JMPNE: '~=', Op.JMPEQ: '==',
    Op.JMPLT: '<',  Op.JMPLE: '<=',
    Op.JMPGT: '>',  Op.JMPGE: '>=',
}
CMP_REVERSE = {
    '~=': '==', '==': '~=',
    '<': '>=',  '>=': '<',
    '>': '<=',  '<=': '>',
}

# ============================================================
# Data structures
# ============================================================

@dataclass
class Local:
    name: str
    startpc: int  # 0-based PC in binary
    endpc: int

@dataclass
class Chunk:
    source: str
    line_defined: int
    num_params: int
    is_vararg: int
    max_stack_size: int
    locals: List[Local]
    line_info: List[int]
    strings: List[str]
    numbers: List[float]
    functions: List['Chunk']
    instructions: List[int]

class VKind(IntEnum):
    NIL = 0
    INT = 1
    FLOAT = 2
    STRING = 3   # quoted string literal
    NAME = 4     # variable/function name (unquoted)
    EXPR = 5     # compound expression
    TABLE = 6
    CLOSURE = 7

@dataclass
class SVal:
    text: str
    kind: int = VKind.NIL
    local_name: str = ''
    is_local: bool = False
    is_func_ret: bool = False
    func_ret_count: int = 0

# ============================================================
# Binary parser
# ============================================================

_LUA_SIGNATURE = b'\x1bLua'
_LUA_VERSION = 0x40
_TEST_NUMBER = 3.14159265358979e+08

def _read_string(data, pos):
    """Read a length-prefixed string. Returns (string, new_pos)."""
    slen = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    if slen == 0:
        return '', pos
    s = data[pos:pos + slen - 1].decode('latin-1')  # -1 for null terminator
    pos += slen
    return s, pos

def _read_chunk(data, pos):
    """Read a Lua 4 chunk from binary data. Returns (Chunk, new_pos)."""
    # Source name
    source, pos = _read_string(data, pos)

    # Chunk header
    line_defined = struct.unpack_from('<i', data, pos)[0]; pos += 4
    num_params = struct.unpack_from('<i', data, pos)[0]; pos += 4
    is_vararg = data[pos]; pos += 1
    max_stack_size = struct.unpack_from('<i', data, pos)[0]; pos += 4

    # Locals
    num_locals = struct.unpack_from('<i', data, pos)[0]; pos += 4
    locals_list = []
    for _ in range(num_locals):
        name, pos = _read_string(data, pos)
        startpc, endpc = struct.unpack_from('<ii', data, pos); pos += 8
        locals_list.append(Local(name, startpc, endpc))

    # Line info
    num_line_info = struct.unpack_from('<i', data, pos)[0]; pos += 4
    line_info = []
    if num_line_info > 0:
        for _ in range(num_line_info):
            li = struct.unpack_from('<i', data, pos)[0]; pos += 4
            line_info.append(li)

    # Constants - Strings
    num_strings = struct.unpack_from('<i', data, pos)[0]; pos += 4
    strings = []
    for _ in range(num_strings):
        s, pos = _read_string(data, pos)
        strings.append(s)

    # Constants - Numbers
    num_numbers = struct.unpack_from('<i', data, pos)[0]; pos += 4
    numbers = []
    if num_numbers > 0:
        for _ in range(num_numbers):
            n = struct.unpack_from('<d', data, pos)[0]; pos += 8
            numbers.append(n)

    # Constants - Functions (sub-chunks)
    num_functions = struct.unpack_from('<i', data, pos)[0]; pos += 4
    functions = []
    for _ in range(num_functions):
        sub_chunk, pos = _read_chunk(data, pos)
        functions.append(sub_chunk)

    # Instructions
    num_instructions = struct.unpack_from('<i', data, pos)[0]; pos += 4
    instructions = []
    if num_instructions > 0:
        for _ in range(num_instructions):
            ins = struct.unpack_from('<I', data, pos)[0]; pos += 4
            instructions.append(ins)

    return Chunk(source, line_defined, num_params, is_vararg, max_stack_size,
                 locals_list, line_info, strings, numbers, functions, instructions), pos


def read_lua4_file(filepath):
    """Read a Lua 4 binary file and return the main chunk."""
    with open(filepath, 'rb') as f:
        data = f.read()

    pos = 0
    # Validate signature
    if data[0:4] != _LUA_SIGNATURE:
        raise ValueError("Not a Lua binary file")
    pos = 4

    version = data[pos]; pos += 1
    if version != _LUA_VERSION:
        raise ValueError(f"Expected Lua 4.0 (0x40), got version {version:#x}")

    # Endianness
    endian = data[pos]; pos += 1
    if endian != 1:
        raise ValueError(f"Unsupported endianness: {endian}")

    # Test sizes (6 bytes)
    ts_int, ts_size_t, ts_instruction = data[pos], data[pos+1], data[pos+2]; pos += 3
    ts_size_ins, ts_size_op, ts_size_b = data[pos], data[pos+1], data[pos+2]; pos += 3

    # Number size
    ts_number = data[pos]; pos += 1

    # Test number
    test_num = struct.unpack_from('<d', data, pos)[0]; pos += 8
    if int(test_num) != int(_TEST_NUMBER):
        raise ValueError(f"Test number mismatch: {test_num} vs {_TEST_NUMBER}")

    # Read main chunk
    chunk, pos = _read_chunk(data, pos)
    return chunk

# ============================================================
# Formatting helpers
# ============================================================

def fmt_number(n):
    """Format a number for Lua output."""
    if n == int(n) and abs(n) < 2**53:
        return str(int(n))
    s = f'{n:.14g}'
    return s

def fmt_string(s):
    """Format a string literal for Lua output (with quotes).

    Must escape backslashes because Lua interprets \\a \\b \\f \\n \\r \\t \\v
    as escape sequences. Without escaping, paths like "Music\\action.ogg"
    would have \\a replaced with bell character (0x07).
    """
    if '\n' in s or '\r' in s:
        # Use long string syntax which doesn't process escapes
        # Handle nested ]] by using longer delimiters
        if ']]' not in s:
            return '[[' + s + ']]'
        level = 1
        while f']{"=" * level}]' in s:
            level += 1
        return f'[{"=" * level}[{s}]{"=" * level}]'
    # Escape backslashes and quotes for regular strings
    escaped = s.replace('\\', '\\\\').replace('"', '\\"')
    return '"' + escaped + '"'

def _escape_backslashes(s):
    """Escape backslashes in an output string for Lua."""
    return s.replace('\\', '\\\\')

# ============================================================
# Decompiler
# ============================================================

FIELDS_PER_FLUSH = 64

class Decompiler:
    def __init__(self, debug=False):
        self.debug = debug

    def decompile(self, main_chunk):
        """Decompile a Lua 4 file (main chunk) to source string."""
        lines = self._decompile_chunk(main_chunk, main_chunk, 0)
        return '\n'.join(lines) + '\n'

    # ----------------------------------------------------------
    # Line info lookup (port of VB6's FindLineInfo)
    # ----------------------------------------------------------

    def _get_line_info(self, chunk, pc):
        """Get source line for 0-based instruction pc. Returns -1 if unavailable."""
        ins_1 = pc + 1  # 1-based
        if ins_1 < 1 or ins_1 > len(chunk.instructions) or not chunk.line_info:
            return -1

        li = chunk.line_info
        N = len(li)
        ins_0 = ins_1 - 1  # 0-based for algorithm

        ref_line = 1
        ref_i = 0

        if ref_i < N and li[ref_i] < 0:
            ref_line -= li[ref_i]
            ref_i += 1

        if ref_i >= N:
            return ref_line

        # Walk backward if needed
        while ref_i >= 0 and ref_i < N and li[ref_i] > ins_0:
            ref_line -= 1
            ref_i -= 1
            if ref_i >= 0 and li[ref_i] < 0:
                ref_line += li[ref_i]
                ref_i -= 1

        if ref_i < 0:
            return 1

        # Walk forward
        while True:
            next_line = ref_line + 1
            next_i = ref_i + 1
            if next_i >= N:
                break
            if li[next_i] < 0:
                next_line -= li[next_i]
                next_i += 1
            if next_i >= N or li[next_i] > ins_0:
                break
            ref_line = next_line
            ref_i = next_i

        return ref_line

    def _same_line(self, chunk, pc_a, pc_b):
        """Check if two instructions are on the same source line."""
        la = self._get_line_info(chunk, pc_a)
        lb = self._get_line_info(chunk, pc_b)
        if la < 0 or lb < 0:
            return True  # no line info, assume same line (like VB6)
        return la == lb

    # ----------------------------------------------------------
    # Condition chain helpers
    # ----------------------------------------------------------

    def _is_cond_jump(self, op, include_jmp=False):
        max_op = Op.JMP if include_jmp else Op.JMPONF
        return Op.JMPNE <= op <= max_op

    def _find_next_condition(self, chunk, pc, include_jmp=True):
        """Find next conditional jump in the same compound condition."""
        ins = chunk.instructions
        N = len(ins)
        max_op = Op.JMP if include_jmp else Op.JMPONF

        def is_cond(i):
            if i < 0 or i >= N:
                return False
            op = get_op(ins[i])
            return Op.JMPNE <= op <= max_op

        my_target = pc + 1 + get_s(ins[pc])

        def related_target(other_pc):
            """Check if another conditional jump has a related target (same end or body)."""
            other_target = other_pc + 1 + get_s(ins[other_pc])
            # Same target = and chain
            # One targets the body start (other_pc+1) = or chain
            # My target is the body start (other_pc+1) = or chain
            return (other_target == my_target or
                    other_target == my_target or
                    my_target == other_pc + 1 or
                    other_target == pc + 1)

        # Check pc+2
        if pc + 2 < N and is_cond(pc + 2):
            if self._same_line(chunk, pc + 2, pc) or related_target(pc + 2):
                return pc + 2
        # Check pc+3
        if pc + 3 < N and is_cond(pc + 3):
            if self._same_line(chunk, pc + 3, pc) or related_target(pc + 3):
                return pc + 3
        return -1

    def _find_compound_chain(self, chunk, first_pc):
        """Find compound (A and B) or (C and D) chains that _find_next_condition misses.

        Returns None if the chain starting at first_pc is not a compound pattern.
        Returns a list of (pc, is_or) tuples for the full compound chain if found.

        The compound pattern has AND-failure jumps that go to the start of the
        next OR-group. _find_next_condition can't follow these because the
        target is on a different line and targets don't match.
        """
        ins = chunk.instructions
        N = len(ins)

        def is_cond(i):
            if i < 0 or i >= N:
                return False
            op = get_op(ins[i])
            return Op.JMPNE <= op <= Op.JMPONF

        # First, walk the sequential chain
        seq_chain = [first_pc]
        nxt = self._find_next_condition(chunk, first_pc, include_jmp=False)
        while nxt >= 0 and nxt not in seq_chain:
            seq_chain.append(nxt)
            nxt = self._find_next_condition(chunk, nxt, include_jmp=False)

        # Find the body_start: the most common forward target among seq_chain
        # members that's near the chain end
        last_seq = seq_chain[-1]
        target_counts = {}
        for cpc in seq_chain:
            t = cpc + 1 + get_s(ins[cpc])
            if t > last_seq and t <= last_seq + 20:
                target_counts[t] = target_counts.get(t, 0) + 1
        if target_counts:
            body_start = max(target_counts, key=lambda t: (target_counts[t], t))
        else:
            body_start = last_seq + 1

        # Try to expand: follow AND-failure jump targets that land BEFORE body_start
        chain = list(seq_chain)
        chain_set = set(chain)
        changed = True
        while changed:
            changed = False
            for cpc in list(chain):
                target = cpc + 1 + get_s(ins[cpc])
                if target in chain_set or target < first_pc or target >= body_start:
                    continue
                # Look for a condition at or near the target
                for delta in [0, 2, 3]:
                    tpc = target + delta
                    if tpc >= body_start:
                        break
                    if tpc < N and is_cond(tpc) and tpc not in chain_set:
                        chain.append(tpc)
                        chain_set.add(tpc)
                        changed = True
                        # Walk sequential neighbors before body_start
                        walk = tpc
                        while True:
                            found_next = False
                            for d2 in [2, 3]:
                                npc = walk + d2
                                if (npc < N and npc < body_start and
                                        is_cond(npc) and npc not in chain_set):
                                    chain.append(npc)
                                    chain_set.add(npc)
                                    walk = npc
                                    found_next = True
                                    break
                            if not found_next:
                                break
                        break

        if len(chain) <= len(seq_chain):
            return None  # no expansion found

        # Sort and classify each condition
        chain.sort()
        last_pc = chain[-1]

        # Recompute body_start with the full chain
        all_targets = set()
        for cpc in chain:
            all_targets.add(cpc + 1 + get_s(ins[cpc]))
        # body_start: smallest target past the chain, not in chain
        body_candidates = [t for t in all_targets
                          if t not in chain_set and t > last_pc and t <= last_pc + 20]
        if body_candidates:
            body_start = min(body_candidates)
        else:
            body_start = last_pc + 1

        # Classify: target == body_start → OR-success (is_or=True)
        #           target in chain_set → AND-failure (is_or=False, invert)
        #           else → AND-failure skip (is_or=False, invert)
        result = []
        for cpc in chain:
            t = cpc + 1 + get_s(ins[cpc])
            is_or = (t == body_start)
            result.append((cpc, is_or))

        return result

    def _find_next_condition_pref_jmp(self, chunk, pc):
        """FindNextCondition_PrefJMP: prefers jump target, then pc+2, pc+3."""
        ins = chunk.instructions
        N = len(ins)

        def is_cond(i):
            if i < 0 or i >= N:
                return False
            op = get_op(ins[i])
            return Op.JMPNE <= op <= Op.JMPONF

        # Check jump target first
        target = pc + 1 + get_s(ins[pc])
        if 0 <= target < N and is_cond(target) and self._same_line(chunk, target, pc):
            return target
        # Then pc+2
        if pc + 2 < N and is_cond(pc + 2) and self._same_line(chunk, pc + 2, pc):
            return pc + 2
        # Then pc+3
        if pc + 3 < N and is_cond(pc + 3) and self._same_line(chunk, pc + 3, pc):
            return pc + 3
        return -1

    def _find_end_of_jump(self, chunk, pc):
        """Follow condition chain to find where the block body ends."""
        last = pc
        nxt = self._find_next_condition_pref_jmp(chunk, pc)
        while nxt >= 0:
            if nxt == last:
                break
            last = nxt
            nxt = self._find_next_condition_pref_jmp(chunk, last)
        return last + 1 + get_s(chunk.instructions[last])

    def _is_while_block(self, chunk, pc):
        """Determine if a conditional jump starts a while loop."""
        end_pc = self._find_end_of_jump(chunk, pc)
        if end_pc - 1 < 0 or end_pc - 1 >= len(chunk.instructions):
            return False
        prev_ins = chunk.instructions[end_pc - 1]
        return get_op(prev_ins) == Op.JMP and get_s(prev_ins) < 0

    def _find_or_presence(self, chunk, pc):
        """Determine if 'or' connects this condition to the next."""
        ins = chunk.instructions
        N = len(ins)

        # Collect the condition chain
        chain = [pc]
        nxt = self._find_next_condition(chunk, pc, include_jmp=False)
        while nxt >= 0:
            chain.append(nxt)
            nxt = self._find_next_condition(chunk, nxt, include_jmp=False)

        if len(chain) < 2:
            return False

        # Find our position in the chain
        try:
            idx = chain.index(pc)
        except ValueError:
            return False

        # Body starts right after the last condition's push instructions
        body_start = chain[-1] + 1 + get_s(ins[chain[-1]])

        # This condition's jump target
        my_target = pc + 1 + get_s(ins[pc])

        # If this condition's target is the body start (or close to it),
        # it's an 'or' (jumps to body when true).
        # If target is past body, it's an 'and' (jumps past body when false).
        # The body_start for 'or' chains is approximately the instruction after
        # the last condition.
        last_cond_end = chain[-1] + 1
        if my_target <= last_cond_end:
            return True  # or: jumps to body
        return False  # and: jumps past body

    @staticmethod
    def _parenthesize_compound(cond_text):
        """Add parentheses around AND groups in compound OR-of-AND conditions.

        Input:  '(A) and (B) or (C) and (D)'
        Output: '((A) and (B)) or ((C) and (D))'
        """
        # Split on ' or ' to get groups
        parts = cond_text.split(' or ')
        if len(parts) <= 1:
            return cond_text
        # Wrap groups that contain ' and ' in parens
        wrapped = []
        for part in parts:
            part = part.strip()
            if ' and ' in part:
                wrapped.append('(' + part + ')')
            else:
                wrapped.append(part)
        return ' or '.join(wrapped)

    @staticmethod
    def _add_grouping_parens(cond_text):
        """Add parentheses when condition has mixed and/or without grouping.

        Handles both patterns:
          OR-of-ANDs: '(A) and (B) or (C) and (D)' → '((A) and (B)) or ((C) and (D))'
          AND-of-ORs: '(A) or (B) or (C) and (D) or (E)' → '((A) or (B) or (C)) and ((D) or (E))'
        """
        if ' and ' not in cond_text or ' or ' not in cond_text:
            return cond_text  # no mixing, no grouping needed

        # Determine which pattern: count transitions between and/or
        # Split into tokens, find the connectors
        # Use a simple approach: split on ' or ' first, check if pieces have ' and '
        or_parts = cond_text.split(' or ')
        and_parts = cond_text.split(' and ')

        if len(or_parts) > len(and_parts):
            # More OR segments → AND-of-ORs: group OR segments, join with AND
            # Split on ' and ' to get the AND groups
            groups = cond_text.split(' and ')
            wrapped = []
            for g in groups:
                g = g.strip()
                if ' or ' in g:
                    wrapped.append('(' + g + ')')
                else:
                    wrapped.append(g)
            return ' and '.join(wrapped)
        else:
            # More AND segments → OR-of-ANDs: group AND segments, join with OR
            groups = cond_text.split(' or ')
            wrapped = []
            for g in groups:
                g = g.strip()
                if ' and ' in g:
                    wrapped.append('(' + g + ')')
                else:
                    wrapped.append(g)
            return ' or '.join(wrapped)

    def _find_elseif_presence(self, chunk, pc):
        """Check if this conditional jump is an elseif."""
        ins = chunk.instructions
        N = len(ins)

        jmp_curr = pc + 1 + get_s(ins[pc])

        # Look backward for an unconditional JMP on the previous line
        for i in range(pc - 1, max(0, pc - 10), -1):
            if get_op(ins[i]) == Op.JMP:
                line_i = self._get_line_info(chunk, i)
                line_pc = self._get_line_info(chunk, pc)
                if line_i >= 0 and line_pc >= 0 and line_i == line_pc - 1:
                    jmp_prev = i + 1 + get_s(ins[i])
                    if jmp_curr == jmp_prev:
                        return True
                break
        return False

    def _find_else_requirement(self, chunk, pc):
        """Check if 'else' should be written at this JMP."""
        ins = chunk.instructions
        N = len(ins)

        # Backward jumps don't need else (they're while-end)
        if get_s(ins[pc]) < 0:
            return False

        # Check if there's a conditional jump on the next line
        for i in range(pc + 1, min(N, pc + 10)):
            op = get_op(ins[i])
            if Op.JMPNE <= op <= Op.JMPONF:
                line_i = self._get_line_info(chunk, i)
                line_pc = self._get_line_info(chunk, pc)
                if line_i >= 0 and line_pc >= 0 and line_i - 1 == line_pc:
                    return False  # elseif follows, no else needed here
                break
        return True

    def _find_end_requirement(self, chunk, pc):
        """Check if another 'end' is needed alongside this JMP's block."""
        ins = chunk.instructions
        N = len(ins)

        if pc >= N - 1:
            return pc

        for i in range(pc + 1, N):
            op = get_op(ins[i])
            if Op.JMPNE <= op <= Op.JMPONF and op != Op.JMP:
                return 0  # another condition follows
            if op == Op.JMP:
                target_i = i + 1 + get_s(ins[i])
                target_pc = pc + 1 + get_s(ins[pc])
                if target_i == target_pc:
                    return i
                break
        return 0

    # ----------------------------------------------------------
    # Do-end block analysis
    # ----------------------------------------------------------

    def _find_do_end_blocks(self, chunk):
        """Find do...end blocks from local variable scoping."""
        N = len(chunk.instructions)
        do_pcs = []
        end_pcs_do = []
        seen_ends = set()

        for i in range(len(chunk.locals) - 1):
            loc = chunk.locals[i]
            a = loc.endpc != N  # doesn't end at last instruction
            b = loc.endpc not in seen_ends  # not already tracked
            c = False
            if loc.startpc > 0 and loc.startpc <= N:
                start_op = get_op(chunk.instructions[loc.startpc - 1]) if loc.startpc > 0 else Op.END
                end_op = get_op(chunk.instructions[loc.endpc - 1]) if 0 < loc.endpc <= N else Op.END
                c = (end_op != Op.POP and
                     not (Op.FORPREP <= (get_op(chunk.instructions[loc.startpc - 1])
                          if 0 < loc.startpc <= N else Op.END) <= Op.LFORLOOP))

            if a and b and c and loc.startpc > 0 and loc.endpc > 0:
                do_pcs.append(loc.startpc)
                end_pcs_do.append(loc.endpc)
                seen_ends.add(loc.endpc)

        return do_pcs, end_pcs_do

    # ----------------------------------------------------------
    # Local variable helpers
    # ----------------------------------------------------------

    def _find_locals_at(self, chunk, vb_pc):
        """Find first local index with startpc == vb_pc. Returns -1 if none."""
        for i, loc in enumerate(chunk.locals):
            if loc.startpc == vb_pc:
                return i
        return -1

    def _count_locals_at(self, chunk, vb_pc):
        """Count locals with startpc == vb_pc."""
        return sum(1 for loc in chunk.locals if loc.startpc == vb_pc)

    def _count_locals_ending_at(self, chunk, vb_pc):
        """Count locals with endpc == vb_pc."""
        return sum(1 for loc in chunk.locals if loc.endpc == vb_pc)

    def _compute_local_slots(self, chunk):
        """Compute VM stack slot for each local entry by simulating the compiler."""
        events = []
        for i, loc in enumerate(chunk.locals):
            events.append((loc.startpc, 1, i))   # 1 = start
            events.append((loc.endpc, 0, i))      # 0 = end (sorts before starts at same PC)
        events.sort()

        slots = {}
        nactvar = 0
        for _pc, event_type, idx in events:
            if event_type == 0:
                nactvar -= 1
            else:
                slots[idx] = nactvar
                nactvar += 1
        return slots

    def _resolve_local(self, chunk, slot, vb_pc, local_slots):
        """Find the local variable name occupying 'slot' at 'vb_pc'."""
        for i, loc in enumerate(chunk.locals):
            if local_slots.get(i) == slot and loc.startpc <= vb_pc < loc.endpc:
                return loc.name
        # Fallback: direct index
        if slot < len(chunk.locals):
            return chunk.locals[slot].name
        return f'local_{slot}'

    # ----------------------------------------------------------
    # Stack helpers
    # ----------------------------------------------------------

    def _stack_val(self, text, kind=VKind.EXPR):
        return SVal(text, kind)

    def _format_table_access(self, tbl, key):
        """Format table[key] access."""
        return f'{tbl}[{key}]'

    # ----------------------------------------------------------
    # Main decompilation
    # ----------------------------------------------------------

    def _decompile_chunk(self, chunk, parent_chunk, indent):
        """Decompile a single chunk. Returns list of output lines."""
        ins_list = chunk.instructions
        N = len(ins_list)
        if N == 0:
            return []

        # Pre-compute local variable slot assignments
        local_slots = self._compute_local_slots(chunk)

        # Stack (VM-like, 0-based positions)
        stack = [SVal('nil', VKind.NIL)] * max(chunk.max_stack_size + 16, 256)
        top = 0  # next free slot

        # Output
        lines = []
        level = indent

        def emit(text, semi=True):
            prefix = '\t' * max(0, level)
            t = text.strip()
            if semi and t and not t.startswith('--'):
                t += ';'
            lines.append(prefix + t)

        def emit_blank():
            lines.append('')

        # Track local initialization
        local_init = [False] * len(chunk.locals)

        # Track jump types for nesting: 'c' = conditional, 'w' = while, 'f' = for
        jump_types = []

        # Track where 'end' should be emitted (list of vb_pc values)
        end_positions = []

        # Condition accumulator for compound conditions
        cond_str = ''
        compound_info = None  # list of (pc, is_or) from _find_compound_chain

        # Do-end blocks
        do_pcs, end_pcs_do = self._find_do_end_blocks(chunk)

        # Process locals at pc=0 (function parameters)
        last_local_processed = 0
        def process_locals(vb_pc):
            nonlocal top, last_local_processed
            for j in range(last_local_processed, len(chunk.locals)):
                if chunk.locals[j].startpc == vb_pc:
                    if vb_pc == 0:
                        # Function parameters: push placeholder (no initializing instruction)
                        stack[top] = SVal(chunk.locals[j].name, VKind.NAME,
                                         local_name=chunk.locals[j].name, is_local=True)
                        top += 1
                    # For non-params, DON'T push - push_val handles it
                    last_local_processed = j + 1
                elif chunk.locals[j].startpc > vb_pc:
                    break

        def push_val(val, vb_pc):
            """Push a value, possibly assigning to a local."""
            nonlocal top
            # Check if a local should be initialized at this instruction
            loc_idx = self._find_locals_at(chunk, vb_pc)
            if loc_idx >= 0 and not local_init[loc_idx]:
                local_init[loc_idx] = True
                name = chunk.locals[loc_idx].name
                emit(f'local {name}={val.text}')
                stack[top] = SVal(name, VKind.NAME, local_name=name, is_local=True)
                top += 1
                return True
            else:
                stack[top] = val
                top += 1
                return False

        def pop_val(n=1):
            nonlocal top
            if n <= 0:
                return
            top = max(0, top - n)

        def peek(offset=0):
            """Peek at stack[top - 1 - offset]."""
            idx = top - 1 - offset
            if 0 <= idx < len(stack):
                return stack[idx]
            return SVal('nil', VKind.NIL)

        def stack_at(pos):
            if 0 <= pos < len(stack):
                return stack[pos]
            return SVal('nil', VKind.NIL)

        def process_value_for_output(offset=0):
            """Get formatted value at stack[top - 1 + offset]."""
            idx = top - 1 + offset
            if idx < 0 or idx >= len(stack):
                return 'nil'
            sv = stack[idx]
            if sv.kind == VKind.TABLE:
                if sv.text.isdigit() or (sv.text.startswith('-') and sv.text[1:].isdigit()):
                    n = int(sv.text)
                    if n == 0:
                        return '{}'
                    return '{' + ', '.join(['nil'] * n) + '}'
                return sv.text
            if sv.kind == VKind.NIL:
                return 'nil'
            return sv.text

        # Initialize function params
        process_locals(0)

        # Main instruction loop
        pc = 0
        while pc < N:
            ins = ins_list[pc]
            op = get_op(ins)
            vb_pc = pc + 1  # 1-based PC for local matching

            # Process locals becoming active
            process_locals(vb_pc)

            # Check do-blocks starting here
            for i, dpc in enumerate(do_pcs):
                if dpc == vb_pc:
                    emit('do', semi=False)
                    level += 1

            # Check end statements
            new_end_positions = []
            for epc in end_positions:
                if epc == vb_pc:
                    level -= 1
                    emit('end', semi=False)
                    emit_blank()
                    if jump_types:
                        jump_types.pop()
                else:
                    new_end_positions.append(epc)
            end_positions[:] = new_end_positions

            # Check do-end blocks ending here
            for i, epc in enumerate(end_pcs_do):
                if epc == vb_pc:
                    level -= 1
                    emit('end', semi=False)
                    emit_blank()

            # ---- Process instruction ----

            if op == Op.END:
                # Emit any pending end statements before closing
                for epc in sorted(end_positions):
                    level -= 1
                    emit('end', semi=False)
                    emit_blank()
                end_positions.clear()

                # Safety: emit missing 'end' statements to balance back to function indent
                while level > indent:
                    level -= 1
                    emit('end', semi=False)
                    emit_blank()

                if top != 0 and self.debug:
                    print(f"Warning: stack not empty at END (top={top})", file=sys.stderr)
                break

            elif op == Op.RETURN:
                ret_base = get_u(ins) + 1  # 1-based -> convert to stack index
                ret_base_0 = get_u(ins)  # 0-based stack position

                # Check if next instruction is JMP or END
                is_last = False
                if pc + 1 < N:
                    next_op = get_op(ins_list[pc + 1])
                    is_last = next_op in (Op.JMP, Op.END)

                parts = []
                for j in range(ret_base_0, top):
                    parts.append(stack[j].text)

                ret_str = 'return ' + ', '.join(parts) if parts else 'return'
                if not is_last:
                    ret_str = 'do ' + ret_str + ' end'

                emit(ret_str)
                emit_blank()
                pop_val(top - ret_base_0)

            elif op in (Op.CALL, Op.TAILCALL):
                func_pos = get_a(ins)  # 0-based stack position of function
                num_ret = get_b(ins) if op == Op.CALL else 0

                # Check for locals starting at this instruction (for multi-return)
                loc_start_idx = self._find_locals_at(chunk, vb_pc)
                num_locals_here = self._count_locals_at(chunk, vb_pc)

                # Build call expression
                if func_pos < top:
                    func_val = stack[func_pos]
                else:
                    func_val = SVal('UNKNOWN_FUNC', VKind.NAME)

                args = []
                for j in range(func_pos + 1, top):
                    args.append(stack[j].text)
                arg_str = ', '.join(args)
                call_expr = f'{func_val.text}({arg_str})'

                # Pop everything from func_pos upward
                top = func_pos

                if loc_start_idx >= 0 and num_locals_here > 0:
                    # Local assignment: local a, b = func(args)
                    names = []
                    for j in range(num_ret if num_ret > 0 else num_locals_here):
                        if loc_start_idx + j < len(chunk.locals):
                            name = chunk.locals[loc_start_idx + j].name
                            names.append(name)
                            local_init[loc_start_idx + j] = True

                    if names:
                        emit(f'local {", ".join(names)}={call_expr}')
                        # Push locals onto stack
                        for name in names:
                            stack[top] = SVal(name, VKind.NAME, local_name=name, is_local=True)
                            top += 1
                    else:
                        emit(call_expr)
                elif num_ret == 0:
                    # Statement (no return value)
                    emit(call_expr)
                else:
                    # Push return value as expression
                    sv = SVal(call_expr, VKind.EXPR)
                    sv.is_func_ret = True
                    sv.func_ret_count = num_ret
                    stack[top] = sv
                    top += 1

            elif op == Op.PUSHNIL:
                count = get_u(ins)
                for _ in range(count):
                    push_val(SVal('nil', VKind.NIL), vb_pc)

            elif op == Op.POP:
                pop_val(get_u(ins))

            elif op == Op.PUSHINT:
                val = SVal(str(get_s(ins)), VKind.INT)
                push_val(val, vb_pc)

            elif op == Op.PUSHSTRING:
                idx = get_u(ins)
                if idx < len(chunk.strings):
                    s = chunk.strings[idx]
                    val = SVal(fmt_string(s), VKind.STRING)
                else:
                    val = SVal(f'"<bad_string_{idx}>"', VKind.STRING)
                push_val(val, vb_pc)

            elif op in (Op.PUSHNUM, Op.PUSHNEGNUM):
                idx = get_u(ins)
                if idx < len(chunk.numbers):
                    n = chunk.numbers[idx]
                    if op == Op.PUSHNEGNUM:
                        n = -n
                    val = SVal(fmt_number(n), VKind.FLOAT)
                else:
                    val = SVal(f'<bad_num_{idx}>', VKind.FLOAT)
                push_val(val, vb_pc)

            elif op == Op.PUSHUPVALUE:
                idx = get_u(ins)
                if idx < len(parent_chunk.strings):
                    name = '%' + parent_chunk.strings[idx]
                else:
                    name = f'%upval_{idx}'
                push_val(SVal(name, VKind.NAME), vb_pc)

            elif op == Op.GETLOCAL:
                idx = get_u(ins)
                name = self._resolve_local(chunk, idx, vb_pc, local_slots)
                # Push a copy of the local's name
                stack[top] = SVal(name, VKind.NAME)
                top += 1

            elif op == Op.GETGLOBAL:
                idx = get_u(ins)
                if idx < len(chunk.strings):
                    name = chunk.strings[idx]
                else:
                    name = f'global_{idx}'
                # This is a NAME, not a STRING - critical distinction!
                push_val(SVal(name, VKind.NAME), vb_pc)

            elif op in (Op.GETTABLE, Op.GETDOTTED, Op.GETINDEXED):
                if op == Op.GETDOTTED:
                    idx = get_u(ins)
                    key = fmt_string(chunk.strings[idx]) if idx < len(chunk.strings) else f'"key_{idx}"'
                    tbl = peek(0).text
                    result = self._format_table_access(tbl, key)
                    pop_val(1)
                elif op == Op.GETINDEXED:
                    idx = get_u(ins)
                    key = self._resolve_local(chunk, idx, vb_pc, local_slots)
                    tbl = peek(0).text
                    result = self._format_table_access(tbl, key)
                    pop_val(1)
                else:  # GETTABLE
                    key = peek(0).text
                    tbl = peek(1).text
                    result = self._format_table_access(tbl, key)
                    pop_val(2)

                push_val(SVal(result, VKind.EXPR), vb_pc)

            elif op == Op.PUSHSELF:
                idx = get_u(ins)
                key = chunk.strings[idx] if idx < len(chunk.strings) else f'self_{idx}'
                tbl = peek(0).text
                method = f'{tbl}["{key}"]'
                # PUSHSELF pushes: table, then table.method
                push_val(SVal(method, VKind.NAME), vb_pc)

            elif op == Op.CREATETABLE:
                size = get_u(ins)
                # Push table with size info; searchForLocal only if size==0
                if size == 0:
                    push_val(SVal(str(size), VKind.TABLE), vb_pc)
                else:
                    stack[top] = SVal(str(size), VKind.TABLE)
                    top += 1

            elif op == Op.SETLOCAL:
                idx = get_u(ins)
                name = self._resolve_local(chunk, idx, vb_pc, local_slots)

                val_text = process_value_for_output()

                # Handle multi-return assignment
                sv = peek(0)
                if sv.is_func_ret and sv.func_ret_count > 0:
                    # Multi-return: accumulate names
                    if hasattr(sv, '_accum_names'):
                        sv._accum_names.append(name)
                    else:
                        sv._accum_names = [name]
                    sv.func_ret_count -= 1
                    if sv.func_ret_count == 0:
                        names = ', '.join(sv._accum_names)
                        emit(f'{names}={sv.text}')
                        pop_val(1)
                    else:
                        sv.text = f'{name}, {sv.text}' if not hasattr(sv, '_orig_text') else sv._orig_text
                        if not hasattr(sv, '_orig_text'):
                            sv._orig_text = sv.text
                        stack[top - 1] = sv  # update in place
                else:
                    emit(f'{name}={val_text}')
                    pop_val(1)

            elif op == Op.SETGLOBAL:
                idx = get_u(ins)
                if idx < len(chunk.strings):
                    name = chunk.strings[idx]
                else:
                    name = f'global_{idx}'

                sv = peek(0)

                if sv.kind == VKind.CLOSURE:
                    # Function assignment
                    func_text = sv.text.replace('%n', name)
                    emit(func_text, semi=False)
                    emit_blank()
                    pop_val(1)
                elif sv.is_func_ret and sv.func_ret_count > 0:
                    if not hasattr(sv, '_accum_names'):
                        sv._accum_names = [name]
                    else:
                        sv._accum_names.append(name)
                    sv.func_ret_count -= 1
                    if sv.func_ret_count == 0:
                        names = ', '.join(sv._accum_names)
                        emit(f'{names}={sv.text}')
                        pop_val(1)
                else:
                    val_text = process_value_for_output()
                    emit(f'{name}={val_text}')
                    pop_val(1)

            elif op == Op.SETTABLE:
                a_arg = get_a(ins)
                b_arg = get_b(ins)

                # Stack: [..., table, key, extras..., value]
                # table at top-A, key at top-A+1, value at top-1
                tbl_idx = top - a_arg
                key_idx = top - a_arg + 1
                if 0 <= tbl_idx < len(stack) and 0 <= key_idx < len(stack):
                    tbl = stack[tbl_idx].text
                    key = stack[key_idx].text
                    val_text = process_value_for_output()
                    access = self._format_table_access(tbl, key)

                    sv = peek(0)
                    if sv.kind == VKind.CLOSURE:
                        func_text = sv.text.replace('%n', access)
                        emit(func_text, semi=False)
                        emit_blank()
                    else:
                        emit(f'{access}={val_text}')
                else:
                    emit(f'-- SETTABLE error: stack underflow')

                pop_val(b_arg)

            elif op == Op.SETLIST:
                b_count = get_b(ins)
                a_base = get_a(ins)

                tbl_pos = top - b_count - 1
                if tbl_pos < 0:
                    tbl_pos = 0

                # Check if extending existing table or new
                tbl_val = stack[tbl_pos] if tbl_pos < len(stack) else SVal('{}', VKind.TABLE)
                if tbl_val.text.isdigit() or (tbl_val.kind == VKind.TABLE and tbl_val.text.lstrip('-').isdigit()):
                    result = '{'
                else:
                    # Extending: chop off closing brace
                    result = tbl_val.text
                    if result.endswith('}'):
                        result = result[:-1] + ', '

                parts = []
                for j in range(b_count, 0, -1):
                    idx = top - j
                    if 0 <= idx < len(stack):
                        parts.append(stack[idx].text)
                    else:
                        parts.append('nil')

                result += (',\n' + '\t' * (level + 1)).join(parts) + '}'

                pop_val(b_count + 1)  # pop values + table

                remaining = 0
                sv = SVal(result, VKind.TABLE if remaining > 0 else VKind.EXPR)
                push_val(sv, vb_pc)

            elif op == Op.SETMAP:
                count = get_u(ins) * 2  # pairs of key, value

                tbl_pos = top - count - 1
                tbl_val = stack[tbl_pos] if 0 <= tbl_pos < len(stack) else SVal('{}', VKind.TABLE)

                if tbl_val.text.isdigit() or (tbl_val.kind == VKind.TABLE and tbl_val.text.lstrip('-').isdigit()):
                    result = '{'
                else:
                    result = tbl_val.text
                    if result.endswith('}'):
                        result = result[:-1] + ', '

                parts = []
                for j in range(count, 0, -2):
                    key_idx = top - j
                    val_idx = top - j + 1
                    key = stack[key_idx].text if 0 <= key_idx < len(stack) else 'nil'
                    val = stack[val_idx].text if 0 <= val_idx < len(stack) else 'nil'

                    # Unquote key if it's a simple string
                    if key.startswith('"') and key.endswith('"'):
                        clean_key = key[1:-1]
                        parts.append(f'{clean_key}={val}')
                    elif key.startswith('[[') and key.endswith(']]'):
                        clean_key = key[2:-2]
                        parts.append(f'{clean_key}={val}')
                    else:
                        parts.append(f'[{key}]={val}')

                result += (',\n' + '\t' * level).join(parts) + '}'

                pop_val(count + 1)
                push_val(SVal(result, VKind.EXPR), vb_pc)

            elif op in (Op.ADD, Op.ADDI, Op.SUB, Op.MULT, Op.DIV, Op.POW):
                op_chars = {
                    Op.ADD: '+', Op.ADDI: '+', Op.SUB: '-',
                    Op.MULT: '*', Op.DIV: '/', Op.POW: '^'
                }
                op_char = op_chars[op]

                if op == Op.ADDI:
                    right = str(get_s(ins))
                    left = peek(0).text
                    result = f'({left} {op_char} {right})'
                    result = result.replace('+ -', '- ')
                    pop_val(1)
                else:
                    right = peek(0).text
                    left = peek(1).text
                    result = f'({left} {op_char} {right})'
                    pop_val(2)

                push_val(SVal(result, VKind.EXPR), vb_pc)

            elif op == Op.CONCAT:
                count = get_u(ins)
                parts = []
                for j in range(count, 0, -1):
                    idx = top - j
                    if 0 <= idx < len(stack):
                        parts.append(stack[idx].text)
                pop_val(count)
                # Use ' .. ' with spaces to avoid ambiguity (e.g. 9..x parses as 9. .x)
                result = ' .. '.join(parts)
                push_val(SVal(result, VKind.EXPR), vb_pc)

            elif op == Op.MINUS:
                val = peek(0).text
                pop_val(1)
                push_val(SVal(f'-{val}', VKind.EXPR), vb_pc)

            elif op == Op.NOT:
                val = peek(0).text
                pop_val(1)
                push_val(SVal(f'(not {val})', VKind.EXPR), vb_pc)

            elif op in (Op.JMPNE, Op.JMPEQ, Op.JMPLT, Op.JMPLE, Op.JMPGT, Op.JMPGE):
                # Determine if this is while or if
                is_while = self._is_while_block(chunk, pc)
                jump_types.append('w' if is_while else 'c')

                # Get comparison operator
                cmp_op = CMP_OPS[op]

                # Check for next condition in chain
                next_cond = self._find_next_condition(chunk, pc, include_jmp=False)

                # Check for A = (condition) form (PUSHNILJMP follows)
                if pc + 1 < N and get_op(ins_list[pc + 1]) == Op.PUSHNILJMP:
                    right = peek(0).text
                    left = peek(1).text
                    result = cond_str + f'({left}{cmp_op}{right})'
                    pop_val(2)
                    push_val(SVal(result, VKind.EXPR), vb_pc)
                    cond_str = ''
                    jump_types.pop()
                    pc += 2  # skip PUSHNILJMP and PUSHINT
                    pc += 1
                    continue

                # Check for compound (A and B) or (C and D) pattern at first cond
                if not compound_info and cond_str == '':
                    compound_info = self._find_compound_chain(chunk, pc)

                # Build condition text
                jt = jump_types[-1]
                right = peek(0).text
                left = peek(1).text

                if compound_info:
                    # COMPOUND PATH: use structural classification
                    ci_dict = {cpc: ior for cpc, ior in compound_info}
                    ci_pcs = [cpc for cpc, _ in compound_info]
                    is_or_compound = ci_dict.get(pc, False)
                    is_last = (pc == ci_pcs[-1])

                    if jt == 'c':
                        if is_or_compound:
                            cond_str += f'({left}{cmp_op}{right}) or '
                        else:
                            rev_op = CMP_REVERSE.get(cmp_op, cmp_op)
                            cond_str += f'({left}{rev_op}{right}) and '
                    else:  # while — flip sense
                        if not is_or_compound:
                            cond_str += f'({left}{cmp_op}{right}) or '
                        else:
                            rev_op = CMP_REVERSE.get(cmp_op, cmp_op)
                            cond_str += f'({left}{rev_op}{right}) and '

                    if not is_last:
                        jump_types.pop()
                    else:
                        # Emit compound condition
                        jt = jump_types[-1]
                        cond_text = cond_str.rstrip()
                        if cond_text.endswith(' and'):
                            cond_text = cond_text[:-4]
                        elif cond_text.endswith(' or'):
                            cond_text = cond_text[:-3]
                        # Add parentheses around AND groups separated by OR
                        cond_text = self._parenthesize_compound(cond_text)

                        is_elseif = self._find_elseif_presence(chunk, pc)
                        prefix = 'else' if is_elseif else ''

                        if jt == 'c':
                            emit(f'{prefix}if {cond_text} then', semi=False)
                        else:
                            emit(f'{prefix}while {cond_text} do', semi=False)

                        level += 1
                        cond_str = ''
                        compound_info = None

                        target = pc + 1 + get_s(ins)
                        if target < N:
                            target_ins = ins_list[target - 1] if target > 0 else 0
                            target_op = get_op(target_ins) if target > 0 else Op.END
                            if target_op != Op.JMP:
                                end_positions.append(target + 1)
                else:
                    # NORMAL PATH: use _find_or_presence
                    if jt == 'c':
                        if self._find_or_presence(chunk, pc):
                            cond_str += f'({left}{cmp_op}{right}) or '
                        else:
                            rev_op = CMP_REVERSE.get(cmp_op, cmp_op)
                            cond_str += f'({left}{rev_op}{right}) and '
                    else:  # while
                        if self._find_or_presence(chunk, pc) or next_cond < 0:
                            rev_op = CMP_REVERSE.get(cmp_op, cmp_op)
                            cond_str += f'({left}{rev_op}{right}) and '
                        else:
                            cond_str += f'({left}{cmp_op}{right}) or '

                    if next_cond >= 0:
                        jump_types.pop()
                    else:
                        jt = jump_types[-1]
                        cond_text = cond_str.rstrip()
                        if cond_text.endswith(' and'):
                            cond_text = cond_text[:-4]
                        elif cond_text.endswith(' or'):
                            cond_text = cond_text[:-3]
                        # Add grouping parentheses for mixed and/or
                        cond_text = self._add_grouping_parens(cond_text)

                        is_elseif = self._find_elseif_presence(chunk, pc)
                        prefix = 'else' if is_elseif else ''

                        if jt == 'c':
                            emit(f'{prefix}if {cond_text} then', semi=False)
                        else:
                            emit(f'{prefix}while {cond_text} do', semi=False)

                        level += 1
                        cond_str = ''

                        target = pc + 1 + get_s(ins)
                        if target < N:
                            target_ins = ins_list[target - 1] if target > 0 else 0
                            target_op = get_op(target_ins) if target > 0 else Op.END
                            if target_op != Op.JMP:
                                end_positions.append(target + 1)

                pop_val(2)

            elif op in (Op.JMPT, Op.JMPF, Op.JMPONT, Op.JMPONF):
                is_while = self._is_while_block(chunk, pc)
                jump_types.append('w' if is_while else 'c')

                val = peek(0).text

                if op in (Op.JMPT, Op.JMPONT):
                    cond_part = f' not ({val})'
                else:
                    cond_part = f' ({val})'

                next_cond = self._find_next_condition(chunk, pc, include_jmp=False)

                if next_cond >= 0:
                    jt = jump_types[-1]
                    if self._find_or_presence(chunk, pc):
                        cond_str += cond_part + ' and '
                    else:
                        cond_str += ' not ' + cond_part + ' or '
                    jump_types.pop()
                else:
                    cond_str += cond_part
                    jt = jump_types[-1]

                    cond_text = cond_str.strip()
                    # Clean up double negations
                    while 'not not' in cond_text:
                        cond_text = cond_text.replace('not not', '')
                    while '  ' in cond_text:
                        cond_text = cond_text.replace('  ', ' ')
                    cond_text = cond_text.strip()
                    # Add grouping parentheses for mixed and/or
                    cond_text = self._add_grouping_parens(cond_text)

                    is_elseif = self._find_elseif_presence(chunk, pc)
                    prefix = 'else' if is_elseif else ''

                    if jt == 'c':
                        emit(f'{prefix}if {cond_text} then', semi=False)
                    else:
                        emit(f'{prefix}while {cond_text} do', semi=False)

                    level += 1
                    cond_str = ''

                    target = pc + 1 + get_s(ins)
                    if target < N:
                        target_ins = ins_list[target - 1] if target > 0 else 0
                        target_op = get_op(target_ins) if target > 0 else Op.END
                        if target_op != Op.JMP:
                            end_positions.append(target + 1)

                # Pop for JMPT/JMPF but not for JMPONT/JMPONF (they leave value)
                if op in (Op.JMPT, Op.JMPF):
                    pop_val(1)
                elif op == Op.JMPONT:
                    if peek(0).kind != VKind.NIL:
                        pop_val(1)
                elif op == Op.JMPONF:
                    if peek(0).kind == VKind.NIL:
                        pop_val(1)

            elif op == Op.JMP:
                level -= 1
                jt = jump_types[-1] if jump_types else 'c'

                if jt == 'c':
                    # If block: check for else
                    end_req = self._find_end_requirement(chunk, pc)
                    else_req = self._find_else_requirement(chunk, pc)

                    if end_req:
                        emit('else', semi=False)
                        level += 1
                        end_positions.append(end_req + 1)
                    elif else_req:
                        emit('else', semi=False)
                        level += 1
                        target = pc + 1 + get_s(ins)
                        end_positions.append(target + 1)
                    else:
                        # No else needed, but still need end for this if block
                        target = pc + 1 + get_s(ins)
                        end_positions.append(target + 1)
                        level += 1  # restore level

                elif jt == 'w':
                    emit('end', semi=False)
                    emit_blank()
                    if jump_types:
                        jump_types.pop()

                elif jt == 'f':
                    level += 1  # restore
                    # Check if next is FORLOOP
                    if pc + 1 < N:
                        next_op = get_op(ins_list[pc + 1])
                        if next_op in (Op.FORLOOP, Op.LFORLOOP):
                            emit('break')
                        else:
                            emit('do break end', semi=False)

            elif op == Op.PUSHNILJMP:
                push_val(SVal('nil', VKind.NIL), vb_pc)

            elif op in (Op.FORPREP, Op.LFORPREP):
                loc_idx = self._find_locals_at(chunk, vb_pc)

                if op == Op.FORPREP:
                    # Numeric for: for i = start, end[, step] do
                    if loc_idx >= 0 and loc_idx < len(chunk.locals):
                        var_name = chunk.locals[loc_idx].name
                    else:
                        var_name = f'_for_var'

                    step_val = process_value_for_output(0)
                    end_val = process_value_for_output(-1)
                    start_val = process_value_for_output(-2)

                    step_text = ''
                    try:
                        if float(step_val) != 1.0:
                            step_text = f', {step_val}'
                    except (ValueError, TypeError):
                        step_text = f', {step_val}'

                    emit(f'for {var_name}={start_val}, {end_val}{step_text} do', semi=False)
                    # DON'T pop: VM keeps start/limit/step on stack as loop state
                    # The loop variable shares the counter slot (accessed via GETLOCAL)
                    # Mark for-loop locals as initialized so push_val doesn't grab them
                    if loc_idx >= 0:
                        for j in range(self._count_locals_at(chunk, vb_pc)):
                            if loc_idx + j < len(local_init):
                                local_init[loc_idx + j] = True
                else:
                    # Generic for: for k, v in expr do
                    if loc_idx >= 0 and loc_idx + 2 < len(chunk.locals):
                        k_name = chunk.locals[loc_idx + 1].name
                        v_name = chunk.locals[loc_idx + 2].name
                    else:
                        k_name = '_k'
                        v_name = '_v'

                    iter_val = process_value_for_output(0)
                    emit(f'for {k_name}, {v_name} in {iter_val} do', semi=False)
                    # DON'T pop: VM keeps iterator state on stack
                    if loc_idx >= 0:
                        for j in range(self._count_locals_at(chunk, vb_pc)):
                            if loc_idx + j < len(local_init):
                                local_init[loc_idx + j] = True

                jump_types.append('f')
                level += 1

            elif op in (Op.FORLOOP, Op.LFORLOOP):
                level -= 1
                if jump_types and jump_types[-1] == 'f':
                    jump_types.pop()
                emit('end', semi=False)
                emit_blank()

                # Pop loop state (3 internals: counter, limit, step)
                pop_val(min(3, top))

            elif op == Op.CLOSURE:
                func_idx = get_a(ins)
                # b_arg = get_b(ins)  # number of upvalues

                if func_idx < len(chunk.functions):
                    sub_chunk = chunk.functions[func_idx]
                    # Decompile the sub-function
                    sub_lines = self._decompile_chunk(sub_chunk, chunk, level + 1)
                    # Build function text with placeholder for name
                    params = []
                    for j in range(sub_chunk.num_params):
                        if j < len(sub_chunk.locals):
                            params.append(sub_chunk.locals[j].name)
                        else:
                            params.append(f'arg{j}')
                    param_str = ', '.join(params)

                    func_body = '\n'.join(sub_lines)
                    func_text = f'function %n({param_str})\n{func_body}\n{chr(9) * level}end'

                    stack[top] = SVal(func_text, VKind.CLOSURE)
                    top += 1
                else:
                    stack[top] = SVal(f'-- unknown function {func_idx}', VKind.CLOSURE)
                    top += 1

            else:
                if self.debug:
                    emit(f'-- unknown opcode {op} at pc={pc}')

            pc += 1

        # Emit any remaining end statements
        for epc in sorted(end_positions, reverse=True):
            level -= 1
            emit('end', semi=False)
            emit_blank()

        return lines

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='Lua 4.0 bytecode decompiler')
    parser.add_argument('input', help='Input .luab file')
    parser.add_argument('-o', '--output', help='Output .lua file (default: stdout)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    try:
        chunk = read_lua4_file(args.input)
    except Exception as e:
        print(f'Error reading {args.input}: {e}', file=sys.stderr)
        sys.exit(1)

    dec = Decompiler(debug=args.debug)
    try:
        source = dec.decompile(chunk)
    except Exception as e:
        print(f'Error decompiling: {e}', file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(source)
        print(f'Decompiled to {args.output}')
    else:
        print(source)

if __name__ == '__main__':
    main()
