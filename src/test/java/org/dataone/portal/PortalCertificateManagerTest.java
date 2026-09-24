package org.dataone.portal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.dataone.client.auth.CertificateManager;
import org.dataone.service.types.v1.Session;
import org.junit.Test;

/**
 * Tests for {@link PortalCertificateManager#getSession(HttpServletRequest)}.
 */
public class PortalCertificateManagerTest {

    private static final String CERT_FILE =
        "src/test/resources/org/dataone/portal/unitTestSelfSignedCert.pem";

    /**
     * A minimal HttpServletRequest with the given headers and attributes; other methods return
     * null (or false/0).
     */
    private static HttpServletRequest request(final Map<String, String> headers,
                                              final Map<String, Object> attributes) {
        return (HttpServletRequest) Proxy.newProxyInstance(
            HttpServletRequest.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class},
            (proxy, method, args) -> {
                switch (method.getName()) {
                case "getHeader":
                    return headers.get(args[0]);
                case "getAttribute":
                    return attributes.get(args[0]);
                case "toString":
                    return "test request";
                default:
                    Class<?> type = method.getReturnType();
                    if (type == boolean.class) {
                        return false;
                    }
                    if (type == int.class || type == long.class) {
                        return 0;
                    }
                    return null;
                }
            });
    }

    private static HttpServletRequest requestWithHeader(String name, String value) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put(name, value);
        return request(headers, new HashMap<String, Object>());
    }

    private static X509Certificate loadTestCertificate() throws Exception {
        // the file holds a certificate followed by its private key; parse just the certificate
        String pem = new String(Files.readAllBytes(Paths.get(CERT_FILE)), StandardCharsets.UTF_8);
        String end = "-----END CERTIFICATE-----";
        String certPem = pem.substring(pem.indexOf("-----BEGIN CERTIFICATE-----"),
                                       pem.indexOf(end) + end.length());
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(certPem.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    public void testGetSession_fromClientCertificate() throws Exception {
        X509Certificate cert = loadTestCertificate();
        Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("javax.servlet.request.X509Certificate", new X509Certificate[] {cert});

        Session session = PortalCertificateManager.getInstance()
            .getSession(request(new HashMap<String, String>(), attributes));

        assertNotNull(session);
        assertEquals(CertificateManager.getInstance().getSubjectDN(cert),
                     session.getSubject().getValue());
    }

    @Test
    public void testGetSession_fromBearerToken() throws Exception {
        String userId = "http://orcid.org/0000-0000-0000-0001";
        String token = TokenGenerator.getInstance().getJWT(userId, "Test User");

        Session session = PortalCertificateManager.getInstance()
            .getSession(requestWithHeader("Authorization", "Bearer " + token));

        assertNotNull(session);
        assertEquals(userId, session.getSubject().getValue());
    }

    @Test
    public void testGetSession_withoutCredentials() {
        Session session = PortalCertificateManager.getInstance()
            .getSession(request(new HashMap<String, String>(), new HashMap<String, Object>()));

        assertNull(session);
    }

    @Test
    public void testGetSession_withMalformedAuthorizationHeader() {
        Session session = PortalCertificateManager.getInstance()
            .getSession(requestWithHeader("Authorization", "Bearer"));

        assertNull(session);
    }

    @Test
    public void testGetSession_withInvalidToken() {
        Session session = PortalCertificateManager.getInstance()
            .getSession(requestWithHeader("Authorization", "Bearer not-a-jwt"));

        assertNull(session);
    }
}
