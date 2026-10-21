// ExportBinaryStudio.java
// @category REA Binary Studio

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

public class ExportBinaryStudio extends GhidraScript {
    private static String value(Object input) {
        return input == null ? "" : input.toString();
    }

    private static String csv(Object input) {
        return "\"" + value(input).replace("\"", "\"\"").replace("\r", " ").replace("\n", "\\n") + "\"";
    }

    private static void row(BufferedWriter writer, Object... values) throws IOException {
        for (int i = 0; i < values.length; i++) {
            if (i > 0) writer.write(',');
            writer.write(csv(values[i]));
        }
        writer.newLine();
    }

    private static String json(Object input) {
        return "\"" + value(input).replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t") + "\"";
    }

    private static BufferedWriter writer(Path folder, String name) throws IOException {
        return Files.newBufferedWriter(folder.resolve(name), StandardCharsets.UTF_8);
    }

    private static String node(Varnode value) {
        if (value == null) return "";
        if (value.isConstant()) return "const:" + value.getOffset() + ":" + value.getSize();
        if (value instanceof VarnodeAST) return "v" + ((VarnodeAST) value).getUniqueId() + ":" + value.getSize();
        return value.toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("Output folder argument is required");
        Path output = Paths.get(args[0]);
        Files.createDirectories(output);

        int sectionCount = 0;
        try (BufferedWriter stream = writer(output, "sections.csv")) {
            row(stream, "name", "start", "end", "size", "permissions");
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                String permissions = (block.isRead() ? "r" : "-") + (block.isWrite() ? "w" : "-") +
                    (block.isExecute() ? "x" : "-");
                row(stream, block.getName(), block.getStart(), block.getEnd(), block.getSize(), permissions);
                sectionCount++;
            }
        }

        int symbolCount = 0;
        int importCount = 0;
        try (BufferedWriter symbols = writer(output, "symbols.csv");
             BufferedWriter imports = writer(output, "imports.csv")) {
            row(symbols, "address", "name", "type", "namespace", "source", "external");
            row(imports, "address", "name", "namespace", "type");
            SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true);
            while (iterator.hasNext()) {
                Symbol symbol = iterator.next();
                row(symbols, symbol.getAddress(), symbol.getName(), symbol.getSymbolType(),
                    symbol.getParentNamespace(), symbol.getSource(), symbol.isExternal());
                symbolCount++;
                if (symbol.isExternal()) {
                    row(imports, symbol.getAddress(), symbol.getName(), symbol.getParentNamespace(), symbol.getSymbolType());
                    importCount++;
                }
            }
        }

        int stringCount = 0;
        try (BufferedWriter strings = writer(output, "strings.csv")) {
            row(strings, "address", "length", "value");
            DataIterator iterator = currentProgram.getListing().getDefinedData(true);
            while (iterator.hasNext()) {
                Data data = iterator.next();
                if (data.hasStringValue()) {
                    row(strings, data.getAddress(), data.getLength(), data.getValue());
                    stringCount++;
                }
            }
        }

        int instructionCount = 0;
        int xrefCount = 0;
        try (BufferedWriter disassembly = writer(output, "disassembly.txt");
             BufferedWriter xrefs = writer(output, "xrefs.csv")) {
            row(xrefs, "from_address", "to_address", "type", "operand_index");
            InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
            while (iterator.hasNext()) {
                Instruction instruction = iterator.next();
                disassembly.write(instruction.getAddress() + "  " + instruction);
                disassembly.newLine();
                instructionCount++;
                for (Reference reference : instruction.getReferencesFrom()) {
                    row(xrefs, reference.getFromAddress(), reference.getToAddress(),
                        reference.getReferenceType(), reference.getOperandIndex());
                    xrefCount++;
                }
            }
        }

        int functionCount = 0;
        int decompiledCount = 0;
        int failedCount = 0;
        int callCount = 0;
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int pcodeCount = 0;
        try (BufferedWriter functions = writer(output, "functions.csv");
             BufferedWriter calls = writer(output, "calls.csv");
             BufferedWriter pcode = writer(output, "pcode-ssa.csv");
             BufferedWriter pseudocode = writer(output, "pseudocode.c")) {
            row(functions, "entry", "name", "signature", "body_bytes", "decompiled", "error");
            row(calls, "caller_entry", "caller_name", "callee_entry", "callee_name");
            row(pcode, "function_entry", "address", "opcode", "output", "inputs");
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Function function = iterator.next();
                functionCount++;
                String code = "";
                String error = "";
                try {
                    DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
                    if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        code = result.getDecompiledFunction().getC();
                        decompiledCount++;
                        try {
                        HighFunction high = result.getHighFunction();
                        if (high != null && pcodeCount < 500000) {
                            Iterator<PcodeOpAST> operations = high.getPcodeOps();
                            int localCount = 0;
                            while (operations.hasNext() && localCount < 10000 && pcodeCount < 500000) {
                                PcodeOpAST operation = operations.next();
                                StringBuilder inputs = new StringBuilder();
                                for (int input = 0; input < operation.getNumInputs(); input++) {
                                    if (input > 0) inputs.append(';');
                                    inputs.append(node(operation.getInput(input)));
                                }
                                row(pcode, function.getEntryPoint(), operation.getSeqnum().getTarget(),
                                    operation.getMnemonic(), node(operation.getOutput()), inputs);
                                localCount++;
                                pcodeCount++;
                            }
                        }
                        } catch (Exception pcodeError) {
                            println("SSA export unavailable for " + function.getName() + ": " + pcodeError);
                        }
                    } else {
                        error = result == null ? "No result" : value(result.getErrorMessage());
                        failedCount++;
                    }
                } catch (Exception exception) {
                    error = value(exception);
                    failedCount++;
                }
                row(functions, function.getEntryPoint(), function.getName(), function.getSignature(),
                    function.getBody().getNumAddresses(), !code.isEmpty(), error);
                pseudocode.write("\n/* ===== " + function.getName() + " @ " + function.getEntryPoint() + " ===== */\n");
                pseudocode.write(code.isEmpty() ? "/* Decompilation unavailable: " + error + " */\n" : code);
                if (!code.isEmpty() && !code.endsWith("\n")) pseudocode.newLine();
                try {
                    for (Function callee : function.getCalledFunctions(monitor)) {
                        row(calls, function.getEntryPoint(), function.getName(), callee.getEntryPoint(), callee.getName());
                        callCount++;
                    }
                } catch (Exception exception) {
                    println("Calls unavailable for " + function.getName() + ": " + exception);
                }
                if (functionCount % 50 == 0) println("REA_BINARY_STUDIO_PROGRESS functions=" + functionCount);
            }
        } finally {
            decompiler.dispose();
        }

        String summary = String.format(Locale.ROOT,
            "{\n  \"program\": %s,\n  \"executable_format\": %s,\n  \"language\": %s,\n" +
            "  \"compiler\": %s,\n  \"image_base\": %s,\n  \"cancelled\": %s,\n" +
            "  \"counts\": {\n    \"sections\": %d,\n    \"symbols\": %d,\n    \"imports\": %d,\n" +
            "    \"strings\": %d,\n    \"instructions\": %d,\n    \"xrefs\": %d,\n    \"functions\": %d,\n" +
            "    \"decompiled_functions\": %d,\n    \"failed_decompilations\": %d,\n    \"calls\": %d,\n    \"pcode_ops\": %d\n  }\n}\n",
            json(currentProgram.getName()), json(currentProgram.getExecutableFormat()),
            json(currentProgram.getLanguageID()), json(currentProgram.getCompilerSpec().getCompilerSpecID()),
            json(currentProgram.getImageBase()), monitor.isCancelled(), sectionCount, symbolCount,
            importCount, stringCount, instructionCount, xrefCount, functionCount, decompiledCount, failedCount, callCount,
            pcodeCount);
        Files.writeString(output.resolve("ghidra-summary.json"), summary, StandardCharsets.UTF_8);
        println("REA_BINARY_STUDIO_COMPLETE functions=" + functionCount);
    }
}
