"""Minimal Dalvik emulator for the v2 "analysis" mobile challenges.

Days 23-29 Time Trial / Mastery ship a ``puzzle.v2`` with no embedded answer.
The evidence code is instead *computed* inside the APK's dex by
``...->Release;->code(Context)`` as a fixed chain of 64-bit integer ops over
constants baked into the dex (seed token -> mixing functions -> ``ANS-`` + 16
hex).  The running app posts that code to its local backend, but the value is
fully determined offline, so we evaluate the method directly.

This is a tiny interpreter covering exactly the opcode subset these self
contained numeric methods use, plus a minimal StringBuilder/String/Long model
so ``code()`` returns the real ``ANS-...`` string.  It executes only arithmetic
on dex constants — no I/O, reflection, or Android calls — so it is safe.

Requires androguard (``pip install androguard``).
"""

import os
import re

os.environ.setdefault("LOGURU_LEVEL", "ERROR")
try:  # keep androguard's verbose logger quiet
    from loguru import logger as _lg
    _lg.remove()
except Exception:
    pass

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def _u64(x):
    return x & MASK64


def _u32(x):
    return x & MASK32


def _s32(x):
    x &= MASK32
    return x - (1 << 32) if x & 0x80000000 else x


def _s64(x):
    x &= MASK64
    return x - (1 << 64) if x & 0x8000000000000000 else x


def _param_types(descriptor):
    """Return list of 'wide'/'single' for each parameter in a dex descriptor."""
    inner = descriptor[descriptor.index("(") + 1:descriptor.index(")")]
    inner = inner.replace(" ", "")
    types, i = [], 0
    while i < len(inner):
        c = inner[i]
        if c in "JD":
            types.append("wide"); i += 1
        elif c == "L":
            j = inner.index(";", i); types.append("single"); i = j + 1
        elif c == "[":
            i += 1
            while inner[i] == "[":
                i += 1
            if inner[i] == "L":
                i = inner.index(";", i) + 1
            else:
                i += 1
            types.append("single")
        else:
            types.append("single"); i += 1
    return types


class _SB:
    __slots__ = ("parts",)

    def __init__(self):
        self.parts = []


class DexEvaluator:
    def __init__(self, dex, members=None):
        self.dex = dex
        self.members = members or {}
        self.statics = {}
        self._initialized = set()
        self._asset_cache = {}
        self.methods = {}  # (class_short, name) -> EncodedMethod
        self._index(dex)
        # Also index any secondary dex modules (e.g. assets/payload.dex loaded
        # later via InMemoryDexClassLoader) so cross-dex reflective calls resolve.
        from androguard.core.dex import DEX
        for name, blob in (members or {}).items():
            if name.endswith(".dex") and blob[:4] == b"dex\n":
                try:
                    self._index(DEX(blob))
                except Exception:
                    pass

    def _index(self, dex):
        for cls in dex.get_classes():
            short = cls.get_name().split("/")[-1].rstrip(";")
            for m in cls.get_methods():
                if m.get_code():
                    self.methods.setdefault((short, m.get_name()), m)

    def _find(self, class_token, name):
        short = class_token.split("/")[-1].rstrip(";")
        return self.methods.get((short, name))

    def call(self, class_token, name, args):
        m = self._find(class_token, name)
        if m is None:
            raise KeyError("no method %s->%s" % (class_token, name))
        return self._run(m, args)

    def _run(self, m, args):
        code = m.get_code()
        regs = code.get_registers_size()
        nins = code.get_ins_size()
        ptypes = _param_types(m.get_descriptor())
        reg = [0] * regs

        # place args into the trailing parameter registers
        rp = regs - nins
        ai = 0
        for t in ptypes:
            reg[rp] = args[ai] if ai < len(args) else 0
            rp += 2 if t == "wide" else 1
            ai += 1

        # build offset -> index table
        instrs, offsets, off = [], {}, 0
        for ins in code.get_bc().get_instructions():
            offsets[off] = len(instrs)
            instrs.append((off, ins))
            off += ins.get_length()

        pc = 0
        result = None
        while pc < len(instrs):
            ioff, ins = instrs[pc]
            nm = ins.get_name()
            ops = ins.get_operands()
            rv = [op[1] for op in ops if int(op[0]) == 0]   # register operands
            lits = [op[1] for op in ops if int(op[0]) == 1]  # literals
            offs = [op[1] for op in ops if int(op[0]) == 3]  # branch offsets
            meths = []

            jump = None
            if nm.startswith("const-string"):
                reg[rv[0]] = self._string_operand(ins)
            elif nm.startswith("const-class"):
                tok = self._type_operand(ins)  # Lcom/..;
                inner = tok[1:-1] if tok.startswith("L") else tok
                reg[rv[0]] = inner.replace("/", ".")
            elif nm.startswith("const-wide"):
                reg[rv[0]] = _u64(lits[0])
            elif nm.startswith("const"):
                reg[rv[0]] = _u32(lits[0]) if lits else 0
            elif nm in ("move", "move/16", "move/from16", "move-object",
                        "move-object/16", "move-object/from16", "move-wide",
                        "move-wide/16", "move-wide/from16"):
                reg[rv[0]] = reg[rv[1]]
            elif nm in ("move-result", "move-result-wide", "move-result-object"):
                reg[rv[0]] = result
            elif nm == "int-to-long":
                reg[rv[0]] = _u64(_s32(reg[rv[1]]))
            elif nm == "long-to-int":
                reg[rv[0]] = _u32(reg[rv[1]])
            elif nm in ("neg-long",):
                reg[rv[0]] = _u64(-reg[rv[1]])
            elif nm in ("neg-int",):
                reg[rv[0]] = _u32(-reg[rv[1]])
            # ---- long arithmetic ----
            elif nm == "add-long" or nm == "add-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(a + b)
            elif nm == "sub-long" or nm == "sub-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(a - b)
            elif nm == "mul-long" or nm == "mul-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(a * b)
            elif nm == "xor-long" or nm == "xor-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(a ^ b)
            elif nm == "and-long" or nm == "and-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(a & b)
            elif nm == "or-long" or nm == "or-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(a | b)
            elif nm == "shl-long" or nm == "shl-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(a << (b & 63))
            elif nm == "ushr-long" or nm == "ushr-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = (a & MASK64) >> (b & 63)
            elif nm == "shr-long" or nm == "shr-long/2addr":
                a, b = self._bin(nm, reg, rv)
                reg[rv[0]] = _u64(_s64(a) >> (b & 63))
            # ---- int arithmetic (incl. lit forms) ----
            elif nm.startswith(("add-int", "sub-int", "mul-int", "xor-int",
                                "and-int", "or-int", "shl-int", "ushr-int",
                                "shr-int", "rem-int", "div-int")):
                reg[rv[0]] = self._int_op(nm, reg, rv, lits)
            # ---- control flow ----
            elif nm == "goto" or nm == "goto/16" or nm == "goto/32":
                jump = offs[0]
            elif nm.startswith("if-"):
                jump = self._branch(nm, reg, rv, offs)
            elif nm.startswith("invoke"):
                result = self._invoke(ins, nm, reg, rv, meths)
            elif nm.startswith("new-instance"):
                tok = self._type_operand(ins)
                reg[rv[0]] = _SB() if "StringBuilder" in tok else {}
            elif nm == "new-array":
                reg[rv[0]] = [0] * (reg[rv[1]] & MASK32)
            elif nm == "array-length":
                reg[rv[0]] = len(reg[rv[1]])
            elif nm.startswith("return-void"):
                return None
            elif nm.startswith("return"):
                return reg[rv[0]]
            elif nm.startswith("aput"):
                v = reg[rv[0]]
                if nm == "aput-byte":
                    v = v & 0xFF
                reg[rv[1]][reg[rv[2]] & MASK32] = v
            elif nm.startswith("aget"):
                v = reg[rv[1]][reg[rv[2]] & MASK32]
                if nm == "aget-byte":
                    v = (v & 0xFF) - 256 if (v & 0x80) else (v & 0xFF)
                    v = _u32(v)
                reg[rv[0]] = v
            elif nm.startswith("sput"):
                self.statics[self._field_key(ins)] = reg[rv[0]]
            elif nm.startswith("sget"):
                reg[rv[0]] = self._static(ins)
            elif nm.startswith("iput"):
                obj = reg[rv[1]]
                if isinstance(obj, dict):
                    obj[self._field_key(ins)] = reg[rv[0]]
            elif nm.startswith("iget"):
                obj = reg[rv[1]]
                reg[rv[0]] = obj.get(self._field_key(ins), 0) if isinstance(obj, dict) else 0
            elif nm == "check-cast":
                pass  # type assertion only; value unchanged
            elif nm == "packed-switch" or nm == "sparse-switch":
                jump = self._switch(instrs, offsets, ioff, offs[0], reg[rv[0]])
            elif nm.endswith("-payload") or nm in ("nop",):
                pass  # switch/array data pseudo-ops are not executed
            else:
                raise NotImplementedError("opcode %s (%s)" % (nm, ins.get_output()))

            if jump is not None:
                pc = offsets[ioff + jump * 2]
            else:
                pc += 1
        return result

    def _bin(self, nm, reg, rv):
        if nm.endswith("/2addr"):
            return reg[rv[0]], reg[rv[1]]
        return reg[rv[1]], reg[rv[2]]

    def _int_op(self, nm, reg, rv, lits):
        base = nm.split("/")[0]
        if "/lit" in nm:  # vA = vB OP lit
            a, b = reg[rv[1]], lits[0]
        elif nm.endswith("/2addr"):
            a, b = reg[rv[0]], reg[rv[1]]
        else:
            a, b = reg[rv[1]], reg[rv[2]]
        if base == "add-int":
            return _u32(a + b)
        if base == "sub-int":
            return _u32(a - b)
        if base == "rsub-int":
            return _u32(b - a)
        if base == "mul-int":
            return _u32(a * b)
        if base == "xor-int":
            return _u32(a ^ b)
        if base == "and-int":
            return _u32(a & b)
        if base == "or-int":
            return _u32(a | b)
        if base == "shl-int":
            return _u32(a << (b & 31))
        if base == "ushr-int":
            return (a & MASK32) >> (b & 31)
        if base == "shr-int":
            return _u32(_s32(a) >> (b & 31))
        if base == "rem-int":
            return _u32(int(_s32(a) - (abs(_s32(a)) // abs(b)) * b * (1 if _s32(a) >= 0 else 1)) if b else 0) if False else _u32(_fix_rem(_s32(a), b))
        if base == "div-int":
            return _u32(_fix_div(_s32(a), b))
        raise NotImplementedError(base)

    def _branch(self, nm, reg, rv, offs):
        op = nm[3:]
        if op.endswith("z"):
            a, b, op = _s32(reg[rv[0]]), 0, op[:-1]
        else:
            a, b = _s32(reg[rv[0]]), _s32(reg[rv[1]])
        cond = {"eq": a == b, "ne": a != b, "lt": a < b,
                "ge": a >= b, "gt": a > b, "le": a <= b}[op]
        return offs[0] if cond else None

    def _invoke(self, ins, nm, reg, rv, meths):
        tok = self._method_operand(ins)
        cls_tok, mname, desc = tok
        # internal numeric/builder methods we evaluate directly
        if "StringBuilder" in cls_tok:
            if mname == "<init>":
                return None
            sb = reg[rv[0]]
            if mname == "append":
                ptypes = _param_types(desc)
                arg = reg[rv[1]]
                sb.parts.append(chr(arg & 0xFFFF) if desc[desc.index("(") + 1] == "C"
                                else str(arg))
                return sb
            if mname == "toString":
                return "".join(sb.parts)
            return sb
        if cls_tok.endswith("String;"):
            s = reg[rv[0]]
            if mname == "charAt":
                return ord(s[_s32(reg[rv[1]])])
            if mname == "equalsIgnoreCase":
                return 1
            if mname == "indexOf":
                ch = reg[rv[1]]
                return s.find(chr(ch) if isinstance(ch, int) else str(ch))
            if mname == "substring":
                a = _s32(reg[rv[1]])
                return s[a:_s32(reg[rv[2]])] if len(rv) > 2 else s[a:]
            if mname == "length":
                return len(s)
            if mname in ("trim",):
                return s.strip()
            return s
        if cls_tok.endswith("ClassLoader;"):
            if mname == "loadClass":
                return reg[rv[1]]            # dotted class name string
            return 0                         # getClassLoader etc. -> unused
        if cls_tok.endswith("ByteBuffer;") and mname == "wrap":
            return 0                         # unused; dex resolved by name globally
        if cls_tok.endswith("Long;"):
            if mname == "toHexString":
                return "%x" % (reg[rv[0]] & MASK64)
            if mname == "valueOf":      # box
                return reg[rv[0]]
            if mname == "longValue":    # unbox
                return reg[rv[0]]
            return reg[rv[0]] if rv else 0
        if cls_tok.endswith("Integer;"):
            if mname in ("valueOf", "intValue", "parseInt"):
                return reg[rv[0]]
            return reg[rv[0]] if rv else 0
        if cls_tok.endswith("Uri;") and mname == "encode":
            return reg[rv[0]]
        # ---- reflection: Class.forName / getDeclaredMethod / Method.invoke ----
        if cls_tok.endswith("Class;"):
            if mname == "forName":
                return reg[rv[0]]                         # dotted class name string
            if mname in ("getDeclaredMethod", "getMethod"):
                return ("__method__", reg[rv[0]], reg[rv[1]])  # (marker, class, name)
            return 0
        if cls_tok.endswith("reflect/Method;") and mname == "invoke":
            mref = reg[rv[0]]
            argarr = reg[rv[2]] if len(rv) > 2 else []
            args = list(argarr) if isinstance(argarr, list) else []
            _, cls_name, meth = mref
            tok = "L" + str(cls_name).replace(".", "/") + ";"
            return self.call(tok, meth, args)
        # recurse into an internal class method
        m = self._find(cls_tok, mname)
        ptypes = _param_types(desc)
        is_static = nm.startswith("invoke-static")
        regs_list = list(rv) if is_static else list(rv[1:])
        args, k = [], 0
        for t in ptypes:
            if k < len(regs_list):
                args.append(reg[regs_list[k]])
            k += 2 if t == "wide" else 1
        if m is not None:
            asset = self._maybe_asset(m, args)
            if asset is not None:
                return asset
            return self._run(m, args)
        # a declared-but-codeless method is native: emulate it from the .so
        nat = self._native(cls_tok, mname, args)
        if nat is not None:
            return nat
        return 0  # unknown external call (e.g. Context setters) -> ignore

    def _maybe_asset(self, m, args):
        """Short-circuit a method that reads a packed asset into a byte[].

        Split-APK challenges load bytes from ``assets/<name>`` via
        ZipFile/InputStream; rather than model that I/O, return the embedded
        asset bytes directly when the method returns [B and reads an asset.
        """
        if not m.get_descriptor().endswith(")[B"):
            return None
        key = (m.get_class_name(), m.get_name())
        reads = self._asset_cache.get(key)
        if reads is None:
            body = "\n".join(i.get_output() for i in m.get_code().get_bc().get_instructions())
            reads = ("ZipFile" in body or "InputStream" in body
                     or "getAssets" in body or "splitSourceDirs" in body)
            self._asset_cache[key] = reads
        if not reads:
            return None
        name = next((a for a in args if isinstance(a, str)), None)
        if name is None:
            return None
        for n, blob in self.members.items():
            if n.endswith("assets/" + name) or n.endswith("/" + name) or n.endswith(name):
                return list(blob)
        return None

    def _native(self, cls_tok, mname, args):
        import nativeeval
        sym = nativeeval.jni_symbol(cls_tok, mname)
        for name, blob in self.members.items():
            if name.endswith(".so"):
                try:
                    return nativeeval.emulate(blob, sym, args)
                except KeyError:
                    continue
                except Exception:
                    return None
        return None

    # ---- operand string helpers (resolve refs from the printed output) ----
    def _string_operand(self, ins):
        out = ins.get_output()
        mm = re.search(r"'(.*)'$", out) or re.search(r'"(.*)"$', out)
        return mm.group(1) if mm else out.split(",")[-1].strip().strip("'\"")

    def _type_operand(self, ins):
        return ins.get_output().split(",")[-1].strip()

    def _field_key(self, ins):
        # output: "vX, Lcls;->name type"  -> key "Lcls;->name"
        ref = ins.get_output().split(", ")[-1]
        return ref.split(" ")[0] if " " in ref else ref

    def _static(self, ins):
        key = self._field_key(ins)
        if key not in self.statics:
            cls_tok = key.split("->")[0]
            clinit = self._find(cls_tok, "<clinit>")
            if clinit is not None and cls_tok not in self._initialized:
                self._initialized.add(cls_tok)
                self._run(clinit, [])
        return self.statics.get(key, 0)

    def _switch(self, instrs, offsets, ioff, rel, value):
        """Return the relative unit-offset to jump to for a packed/sparse switch."""
        payload_off = ioff + rel * 2
        pins = instrs[offsets[payload_off]][1]
        try:
            targets = list(pins.get_targets())
        except Exception:
            return None
        keys = None
        for attr in ("get_keys", "get_cases"):
            if hasattr(pins, attr):
                try:
                    keys = list(getattr(pins, attr)())
                    break
                except Exception:
                    pass
        if keys is None:  # packed switch: consecutive from first_key in the output
            nums = [int(x) for x in re.findall(r"-?\d+", pins.get_output())]
            first = nums[0] if nums else 0
            keys = list(range(first, first + len(targets)))
        sval = _s32(value)
        for k, t in zip(keys, targets):
            if sval == k:
                return t  # unit offset relative to the switch instruction
        return None

    def _method_operand(self, ins):
        out = ins.get_output()
        mref = out.split(", ")[-1]
        cls_tok, rest = mref.split("->", 1)
        mname = rest[:rest.index("(")]
        desc = rest[rest.index("("):]
        return cls_tok.strip(), mname, desc


def _fix_div(a, b):
    if b == 0:
        return 0
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _fix_rem(a, b):
    if b == 0:
        return 0
    return a - _fix_div(a, b) * b


ANSWER_RE = re.compile(r"ANS-[0-9A-F]{16}")


def solve_analysis(dex_bytes, members=None):
    """Evaluate ...->Release;->code() and return the ANS- evidence string.

    `members` (name -> bytes of all APK files) lets native (.so) methods in the
    token chain be emulated.
    """
    from androguard.core.dex import DEX
    dex = DEX(dex_bytes)
    ev = DexEvaluator(dex, members)
    # find the Release class (its full type token)
    release = None
    for (short, name), m in ev.methods.items():
        if short == "Release" and name == "code":
            release = m.get_class_name()
            break
    if release is None:
        raise RuntimeError("no Release.code() in dex")
    val = ev.call(release, "code", [None])  # arg: Context (unused)
    if isinstance(val, str):
        mm = ANSWER_RE.search(val)
        if mm:
            return mm.group(0)
        raise RuntimeError("Release.code() returned %r" % val[:40])
    return "ANS-%016X" % (val & MASK64)
