package com.optiv.azureapimanagementtracing;

import burp.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TraceScanner implements IScannerCheck {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public TraceScanner(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        ArrayList<int[]> reqMarkers = new ArrayList<>();
        ArrayList<int[]> resMarkers = new ArrayList<>();

        reqMarkers.add(Utils.getRequestHeaderOffsets(baseRequestResponse.getRequest(), this.helpers));
        resMarkers.add(Utils.getResponseHeaderOffsets(baseRequestResponse.getResponse(), this.helpers));
        IHttpRequestResponseWithMarkers markedRequestResponse = this.callbacks.applyMarkers(baseRequestResponse, reqMarkers, resMarkers);

        if(resMarkers.get(0) != null) {
            int start = resMarkers.get(0)[0] + Utils.responseHeaderSearchText.length();
            int end = resMarkers.get(0)[1];
            String url = this.helpers.bytesToString(Arrays.copyOfRange(baseRequestResponse.getResponse(), start, end));
            IHttpRequestResponseWithMarkers traceRequestResponse = this.callbacks.applyMarkers(Utils.sendRequest(url, this.callbacks), null, null);
            issues.add(new ScanIssue(helpers, markedRequestResponse, traceRequestResponse, url, ScanIssue.TraceIssueType.ResponseHeader));
        } else {
            // Only check for the request header if we didn't get the response header
            byte[] request = baseRequestResponse.getRequest();
            String requestHeaderValue = Utils.getRequestHeader(baseRequestResponse.getRequest(), this.helpers);

            if(reqMarkers.get(0) != null) {
                if (!requestHeaderValue.equals("true")) {
                    // Add an info if the right header was there with the wrong value
                    issues.add(new ScanIssue(helpers, markedRequestResponse, ScanIssue.TraceIssueType.RequestHeaderIncorrectValue));

                    // The header was set, but not set to true. Try setting it to true
                    ByteArrayOutputStream modifiedRequest = new ByteArrayOutputStream();
                    try {
                        modifiedRequest.write(Arrays.copyOfRange(request, 0, reqMarkers.get(0)[0]));
                        modifiedRequest.write(this.helpers.stringToBytes("Ocp-Apim-Trace: true"));
                        modifiedRequest.write(Arrays.copyOfRange(request, reqMarkers.get(0)[1], request.length));
                    } catch (IOException e) {
                        return issues;
                    }

                    issues.addAll(sendActiveRequest(baseRequestResponse, modifiedRequest));
                    return issues;
                }
            } else {
                //There was no header, try adding it
                IRequestInfo requestInfo = this.helpers.analyzeRequest(request);

                ByteArrayOutputStream modifiedRequest = new ByteArrayOutputStream();
                try {
                    modifiedRequest.write(Arrays.copyOfRange(request, 0, requestInfo.getBodyOffset() - 2));
                    modifiedRequest.write(this.helpers.stringToBytes("Ocp-Apim-Trace: true\r\n\r\n"));
                    modifiedRequest.write(Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length));
                } catch (IOException e) {
                    return issues;
                }

                return sendActiveRequest(baseRequestResponse, modifiedRequest);
            }
        }

        return issues.size() > 0 ? issues : null;
    }

    private List<IScanIssue> sendActiveRequest(IHttpRequestResponse baseRequestResponse, ByteArrayOutputStream outputStream) {
        ArrayList<int[]> reqMarkersActive = new ArrayList<>();
        ArrayList<int[]> resMarkersActive = new ArrayList<>();

        byte[] modifiedRequest = outputStream.toByteArray();
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest);

        reqMarkersActive.add(Utils.getRequestHeaderOffsets(modifiedRequest, this.helpers));
        resMarkersActive.add(Utils.getResponseHeaderOffsets(checkRequestResponse.getResponse(), this.helpers));
        IHttpRequestResponseWithMarkers marked = this.callbacks.applyMarkers(checkRequestResponse, reqMarkersActive, resMarkersActive);

        if (resMarkersActive.get(0) != null) {
            List<IScanIssue> issues = new ArrayList<>();
            int start = resMarkersActive.get(0)[0] + Utils.responseHeaderSearchText.length();
            int end = resMarkersActive.get(0)[1];
            String url = this.helpers.bytesToString(Arrays.copyOfRange(checkRequestResponse.getResponse(), start, end));
            IHttpRequestResponseWithMarkers traceRequestResponse = this.callbacks.applyMarkers(Utils.sendRequest(url, this.callbacks), null, null);
            issues.add(new ScanIssue(helpers, marked, traceRequestResponse, url, ScanIssue.TraceIssueType.ResponseHeader));
            return issues;
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
