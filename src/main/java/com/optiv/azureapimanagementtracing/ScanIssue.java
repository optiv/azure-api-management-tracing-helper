package com.optiv.azureapimanagementtracing;

import burp.*;

import java.net.URL;

class ScanIssue implements IScanIssue {
    public enum TraceIssueType {
        RequestHeaderIncorrectValue,
        ResponseHeader
    }

    private final IExtensionHelpers helpers;
    private final IHttpRequestResponseWithMarkers requestResponse;
    private final IHttpRequestResponseWithMarkers traceRequestResponse;
    private final String traceUrl;
    private final TraceIssueType issueType;

    public ScanIssue(IExtensionHelpers helpers, IHttpRequestResponseWithMarkers requestResponse, TraceIssueType issueType) {
        this.helpers = helpers;
        this.requestResponse = requestResponse;
        this.traceRequestResponse = null;
        this.traceUrl = null;
        this.issueType = issueType;
    }

    public ScanIssue(IExtensionHelpers helpers, IHttpRequestResponseWithMarkers requestResponse, IHttpRequestResponseWithMarkers traceInfo, String traceUrl, TraceIssueType issueType) {
        this.helpers = helpers;
        this.requestResponse = requestResponse;
        this.traceRequestResponse = traceInfo;
        this.traceUrl = traceUrl;
        this.issueType = issueType;
    }

    @Override
    public URL getUrl() {
        return this.helpers.analyzeRequest(requestResponse.getHttpService(), this.requestResponse.getRequest()).getUrl();
    }

    @Override
    public String getIssueName() {
        switch (this.issueType) {
            case RequestHeaderIncorrectValue:
                return "Azure API Management Tracing";
            case ResponseHeader:
                return "Azure API Management Tracing Enabled";
        }
        return null;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        switch (this.issueType) {
            case RequestHeaderIncorrectValue:
                return "Information";
            case ResponseHeader:
                return "Medium";
        }
        return null;
    }

    @Override
    public String getConfidence() {
        switch (this.issueType) {
            case RequestHeaderIncorrectValue:
                return "Tentative";
            case ResponseHeader:
                return "Certain";
        }
        return null;
    }

    @Override
    public String getIssueBackground() {
        return "<p>Azure API Management allows developers to view tracing information when this option is configured by system administrators." +
                " Trace information often contains technical information and URLs to backend services. Tracing can be enabled for each consumer/subscriber to the API.</p>" +
                "<ul><li><a href='https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-api-inspector'>https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-api-inspector</a></li></ul>";
    }

    @Override
    public String getRemediationBackground() {
        switch (this.issueType) {
            case RequestHeaderIncorrectValue:
                return "Ensure that tracing is disabled in the Azure portal.";
            case ResponseHeader:
                return "<p>Disable tracing in the Azure portal for the current subscriber.</p>" +
                        "<b>Vulnerability classifications</b><br/>" +
                        "<ul><li><a href='https://cwe.mitre.org/data/definitions/200.html'>CWE-200: Information Exposure</a></li></ul>";
        }
        return null;
    }

    @Override
    public String getIssueDetail() {
        switch (this.issueType) {
            case RequestHeaderIncorrectValue:
                return "The HTTP request header 'Ocp-Apim-Trace' was found to be in use by the application.";
            case ResponseHeader:
                return "<p>Tracing was found to be enabled for the current user on the endpoint:</p>" +
                        "<ul><li>" + this.getUrl().toString() + "</li></ul>" +
                        "<p>The following temporary URL was returned in the HTTP response header \"Ocp-Apim-Trace-Location\":</p>" +
                        "<ul><li><a href='" + this.traceUrl + "'>"+ this.traceUrl + "</a></li></ul>";
        }
        return null;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponseWithMarkers[] getHttpMessages() {
        if (this.traceRequestResponse == null) {
            return new IHttpRequestResponseWithMarkers[]{requestResponse};
        }  else {
            return new IHttpRequestResponseWithMarkers[]{requestResponse, traceRequestResponse};
        }
    }

    @Override
    public IHttpService getHttpService() {
        return this.requestResponse.getHttpService();
    }
}
