package com.optiv.azureapimanagementtracing;

import burp.*;

import java.awt.*;

class TraceViewerTab implements IMessageEditorTab {
    private static final String tabName = "Azure API Management Tracing";
    private final IExtensionHelpers helpers;
    private final ITextEditor traceViewer;
    private byte[] message = null;
    private final IBurpExtenderCallbacks callbacks;

    public TraceViewerTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        traceViewer = callbacks.createTextEditor();
        traceViewer.setEditable(editable);
    }

    @Override
    public String getTabCaption() {
        return tabName;
    }

    @Override
    public Component getUiComponent() {
        return this.traceViewer.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return Utils.getResponseHeader(content, this.helpers) != null;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        String url;
        if(this.message != null) {
            // Use the cached copy
            this.traceViewer.setText(this.message);
        } else if(content != null && !isRequest && null != (url = Utils.getResponseHeader(content, this.helpers))) {
            // Download message
            String uglyJson = Utils.doGetRequest(url);

            // Pretty print
            String prettyJson = Utils.prettyPrintJson(uglyJson);
            this.message = prettyJson == null ? null : this.helpers.stringToBytes(prettyJson);

            this.traceViewer.setText(this.message);
        } else {
            this.traceViewer.setText(null);
        }
    }

    @Override
    public byte[] getMessage() {
        return this.message;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return this.traceViewer.getSelectedText();
    }
}
