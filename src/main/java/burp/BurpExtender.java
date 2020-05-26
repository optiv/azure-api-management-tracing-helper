package burp;

import com.optiv.azureapimanagementtracing.TraceScanner;
import com.optiv.azureapimanagementtracing.TraceViewTabFactory;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {
    private static final String name = "Azure API Management Request Tracing Helper";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Set our extension name
        callbacks.setExtensionName(name);

        // Register the custom editor tab
        TraceViewTabFactory tabFactory = new TraceViewTabFactory(callbacks);
        callbacks.registerMessageEditorTabFactory(tabFactory);

        // Register the scanner
        TraceScanner scanner = new TraceScanner(callbacks);
        callbacks.registerScannerCheck(scanner);

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println(name + " started");
    }
}
