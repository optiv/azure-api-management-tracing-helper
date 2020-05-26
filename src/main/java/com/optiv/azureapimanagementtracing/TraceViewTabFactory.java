package com.optiv.azureapimanagementtracing;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class TraceViewTabFactory implements IMessageEditorTabFactory {
    private final IBurpExtenderCallbacks callbacks;

    public TraceViewTabFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new TraceViewerTab(controller, editable, callbacks);
    }
}
