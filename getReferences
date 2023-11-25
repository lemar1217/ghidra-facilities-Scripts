import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.HashMap;
import java.util.Map;

public class FindFrequentlyCalledFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Map<Function, Integer> functionCallCounts = new HashMap<>();

        // Iterate over all functions in the program
        FunctionIterator functions = functionManager.getFunctions(true);
        for (Function function : functions) {
            // Get all references to the entry point of the function
            ReferenceIterator references = referenceManager.getReferencesTo(function.getEntryPoint());

            // Count the number of references
            int count = 0;
            while (references.hasNext() && !monitor.isCancelled()) {
                references.next();
                count++;
            }
            
            functionCallCounts.put(function, count);
        }

        // Filter and print functions called more than 20 times
        for (Map.Entry<Function, Integer> entry : functionCallCounts.entrySet()) {
            if (entry.getValue() > 20) {
                printf("Function %s is called %d times\n", entry.getKey().getName(), entry.getValue());
            }
        }
    }
}
