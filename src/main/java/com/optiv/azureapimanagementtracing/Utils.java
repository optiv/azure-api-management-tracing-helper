package com.optiv.azureapimanagementtracing;

import burp.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.Arrays;

class Utils {
    private static final String requestHeaderSearchText = "Ocp-Apim-Trace: ";
    public static final String responseHeaderSearchText = "Ocp-Apim-Trace-Location: ";

    public static String getRequestHeader(byte[] content, IExtensionHelpers helpers) {
        int[] match = getRequestHeaderOffsets(content, helpers);
        if(match != null) {
            return helpers.bytesToString(Arrays.copyOfRange(content, match[0] + requestHeaderSearchText.length(), match[1]));
        }
        return null;
    }

    public static int[] getRequestHeaderOffsets(byte[] content, IExtensionHelpers helpers) {
        IRequestInfo requestInfo = helpers.analyzeRequest(content);
        int start = helpers.indexOf(content, helpers.stringToBytes(requestHeaderSearchText), true, 0, requestInfo.getBodyOffset());
        if(start != -1) {
            int end = helpers.indexOf(content, helpers.stringToBytes("\r\n"), true, start, requestInfo.getBodyOffset());
            return new int[] {start, end};
        }
        return null;
    }

    public static String getResponseHeader(byte[] content, IExtensionHelpers helpers) {
        int[] match = getResponseHeaderOffsets(content, helpers);
        if(match != null) {
            return helpers.bytesToString(Arrays.copyOfRange(content, match[0] + responseHeaderSearchText.length(), match[1]));
        }
        return null;
    }

    public static int[] getResponseHeaderOffsets(byte[] content, IExtensionHelpers helpers) {
        IResponseInfo responseInfo = helpers.analyzeResponse(content);
        int start = helpers.indexOf(content, helpers.stringToBytes(responseHeaderSearchText), true, 0, responseInfo.getBodyOffset());
        if(start != -1) {
            int end = helpers.indexOf(content, helpers.stringToBytes("\r\n"), true, start, responseInfo.getBodyOffset());
            return new int[] {start, end};
        }
        return null;
    }

    public static String prettyPrintJson(String data) {
        try {
            String json;
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
            JsonParser jp = new JsonParser();
            JsonElement je = jp.parse(data);
            json = gson.toJson(je);
            return json;
        } catch (Exception ex) {
            return data;
        }
    }

    public static String doGetRequest(String url) {
        try {
            HttpURLConnection connection;
            URL traceUrl = new URL(url);
            connection = (HttpURLConnection) traceUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setUseCaches(false);
            connection.setDoOutput(true);

            InputStream is = connection.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            rd.close();
            return response.toString();
        } catch (ProtocolException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static IHttpRequestResponse sendRequest(String url, IBurpExtenderCallbacks callbacks) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        try {
            URL traceUrl = new URL(url);
            byte[] request = helpers.buildHttpRequest(traceUrl);
            IHttpService httpService = helpers.buildHttpService(traceUrl.getHost(), traceUrl.getDefaultPort(), traceUrl.getProtocol());
            return callbacks.makeHttpRequest(httpService, request);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return null;
    }
}
