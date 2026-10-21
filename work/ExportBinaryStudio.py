# ExportBinaryStudio.py
#@category REA Binary Studio

import codecs
import json
import os
import traceback

from ghidra.app.decompiler import DecompInterface


def safe_text(value):
    if value is None:
        return u""
    try:
        return unicode(value)
    except Exception:
        return u"<unprintable>"


def csv_cell(value):
    return u'"' + safe_text(value).replace(u'"', u'""').replace(u'\r', u' ').replace(u'\n', u'\\n') + u'"'


def csv_row(stream, values):
    stream.write(u",".join([csv_cell(v) for v in values]) + u"\n")


args = getScriptArgs()
if len(args) < 1:
    raise Exception("ExportBinaryStudio.py needs an output folder")

out_dir = args[0]
if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

listing = currentProgram.getListing()
manager = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()
symbol_table = currentProgram.getSymbolTable()

summary = {
    "program": safe_text(currentProgram.getName()),
    "executable_format": safe_text(currentProgram.getExecutableFormat()),
    "language": safe_text(currentProgram.getLanguageID()),
    "compiler": safe_text(currentProgram.getCompilerSpec().getCompilerSpecID()),
    "image_base": safe_text(currentProgram.getImageBase()),
    "entry_point": safe_text(currentProgram.getSymbolTable().getExternalEntryPointIterator().next()) if currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext() else u"",
    "counts": {},
    "warnings": []
}

with codecs.open(os.path.join(out_dir, "sections.csv"), "w", "utf-8") as stream:
    csv_row(stream, ["name", "start", "end", "size", "permissions"])
    count = 0
    for block in memory.getBlocks():
        perms = (u"r" if block.isRead() else u"-") + (u"w" if block.isWrite() else u"-") + (u"x" if block.isExecute() else u"-")
        csv_row(stream, [block.getName(), block.getStart(), block.getEnd(), block.getSize(), perms])
        count += 1
    summary["counts"]["sections"] = count

with codecs.open(os.path.join(out_dir, "symbols.csv"), "w", "utf-8") as stream, codecs.open(os.path.join(out_dir, "imports.csv"), "w", "utf-8") as imports:
    csv_row(stream, ["address", "name", "type", "namespace", "source", "external"])
    csv_row(imports, ["address", "name", "namespace", "type"])
    total = 0
    external = 0
    for symbol in symbol_table.getAllSymbols(True):
        row = [symbol.getAddress(), symbol.getName(), symbol.getSymbolType(), symbol.getParentNamespace(), symbol.getSource(), symbol.isExternal()]
        csv_row(stream, row)
        total += 1
        if symbol.isExternal():
            csv_row(imports, [symbol.getAddress(), symbol.getName(), symbol.getParentNamespace(), symbol.getSymbolType()])
            external += 1
    summary["counts"]["symbols"] = total
    summary["counts"]["imports"] = external

with codecs.open(os.path.join(out_dir, "strings.csv"), "w", "utf-8") as stream:
    csv_row(stream, ["address", "length", "value"])
    count = 0
    for data in listing.getDefinedData(True):
        try:
            if data.hasStringValue():
                csv_row(stream, [data.getAddress(), data.getLength(), data.getValue()])
                count += 1
        except Exception:
            pass
    summary["counts"]["strings"] = count

with codecs.open(os.path.join(out_dir, "disassembly.txt"), "w", "utf-8") as stream:
    count = 0
    for instruction in listing.getInstructions(True):
        stream.write(safe_text(instruction.getAddress()) + u"  " + safe_text(instruction) + u"\n")
        count += 1
    summary["counts"]["instructions"] = count

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
function_count = 0
decompiled_count = 0
failed_count = 0
with codecs.open(os.path.join(out_dir, "functions.csv"), "w", "utf-8") as functions, \
        codecs.open(os.path.join(out_dir, "calls.csv"), "w", "utf-8") as calls, \
        codecs.open(os.path.join(out_dir, "pseudocode.c"), "w", "utf-8") as pseudocode:
    csv_row(functions, ["entry", "name", "signature", "body_bytes", "decompiled", "error"])
    csv_row(calls, ["caller_entry", "caller_name", "callee_entry", "callee_name"])
    for function in manager.getFunctions(True):
        if monitor.isCancelled():
            break
        function_count += 1
        entry = safe_text(function.getEntryPoint())
        name = safe_text(function.getName())
        error = u""
        code = u""
        try:
            result = decompiler.decompileFunction(function, 90, monitor)
            if result is not None and result.decompileCompleted() and result.getDecompiledFunction() is not None:
                code = safe_text(result.getDecompiledFunction().getC())
                decompiled_count += 1
            else:
                error = safe_text(result.getErrorMessage() if result is not None else u"No result")
                failed_count += 1
        except Exception as exc:
            error = safe_text(exc)
            failed_count += 1
        csv_row(functions, [entry, name, function.getSignature(), function.getBody().getNumAddresses(), bool(code), error])
        pseudocode.write(u"\n/* ===== " + name + u" @ " + entry + u" ===== */\n")
        pseudocode.write(code if code else u"/* Decompilation unavailable: " + error + u" */\n")
        if code and not code.endswith(u"\n"):
            pseudocode.write(u"\n")
        try:
            for callee in function.getCalledFunctions(monitor):
                csv_row(calls, [entry, name, callee.getEntryPoint(), callee.getName()])
        except Exception as exc:
            summary["warnings"].append(u"Calls unavailable for " + name + u": " + safe_text(exc))
        if function_count % 50 == 0:
            println("REA_BINARY_STUDIO_PROGRESS functions=" + str(function_count))

decompiler.dispose()
summary["counts"]["functions"] = function_count
summary["counts"]["decompiled_functions"] = decompiled_count
summary["counts"]["failed_decompilations"] = failed_count
summary["cancelled"] = bool(monitor.isCancelled())
with codecs.open(os.path.join(out_dir, "ghidra-summary.json"), "w", "utf-8") as stream:
    stream.write(safe_text(json.dumps(summary, ensure_ascii=False, indent=2)))

println("REA_BINARY_STUDIO_COMPLETE " + str(function_count) + " functions")
