package com.verygoodsecurity;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class OutboundIntegration {
  public static void main(String[] args) throws IOException, InterruptedException, GeneralSecurityException {
    System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
    final String proxyHost = "tntsfeqzp4a.sandbox.verygoodproxy.com";
    final var proxyPort = 8080;
    final String proxyUser = "USiyQvWcT7wcpy8gvFb1GVmz";
    final String proxyPassword = "2b48a642-615a-4b3c-8db5-e02a88147174";

    final HttpClient client = HttpClient.newBuilder()
        .sslContext(buildSSLContext())
        .proxy(ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort)))
        .build();
    final String proxyAuthentication = proxyUser + ":" + proxyPassword;
    final String proxyAuthenticationEncoded = new String(Base64.getEncoder().encode(proxyAuthentication.getBytes()));
    final HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("https://echo.apps.verygood.systems/post"))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString("{"account_number":"tok_sandbox_w8CBfH8vyYL2xWSmMWe3Ds"}"))
        .setHeader("Proxy-Authorization", "Basic " + proxyAuthenticationEncoded)
        .build();
    final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

    System.out.println("status code=" + response.statusCode());
    System.out.println("response=" + response.body());
  }

  private static SSLContext buildSSLContext() throws IOException, GeneralSecurityException {
    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null);

    FileInputStream fileInputStream = new FileInputStream("path/to/sandbox.pem");

    final Certificate certificate = CertificateFactory.getInstance("X.509")
        .generateCertificate(fileInputStream);
    keyStore.setCertificateEntry("vgs", certificate);

    final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keyStore);
    final TrustManager[] trustManagers = tmf.getTrustManagers();

    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustManagers, null);
    return sslContext;
  }
}