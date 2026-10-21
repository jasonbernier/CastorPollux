// Configure an explicitly provided local PDB or DWARF sidecar before analysis.
// @category CastorPollux

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.util.bin.format.dwarf.external.*;

public class CastorPolluxSymbols extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected symbol kind and local path");
        File file = new File(args[1]);
        if (!file.isFile()) throw new IllegalArgumentException("Symbol file missing: " + file);
        if ("pdb".equals(args[0])) {
            PdbUniversalAnalyzer.setPdbFileOption(currentProgram, file);
            PdbUniversalAnalyzer.setAllowUntrustedOption(currentProgram, false);
            println("CASTORPOLLUX_SYMBOLS PDB configured: " + file.getName());
        }
        else if ("dwarf".equals(args[0])) {
            File dir = file.getParentFile();
            List<DebugInfoProvider> locations = new ArrayList<>();
            File buildIds = new File(dir, ".build-id");
            if (buildIds.isDirectory()) locations.add(new BuildIdDebugFileProvider(buildIds));
            locations.add(new LocalDirDebugLinkProvider(dir));
            ExternalDebugFilesService service = new ExternalDebugFilesService(
                LocalDirDebugInfoDProvider.getGhidraCacheInstance(), locations);
            ExternalDebugFilesService.saveToPrefs(service);
            println("CASTORPOLLUX_SYMBOLS DWARF search configured: " + dir);
        }
        else throw new IllegalArgumentException("Unknown symbol kind: " + args[0]);
    }
}
