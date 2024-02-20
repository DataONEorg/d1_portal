package org.dataone.portal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import org.dataone.service.types.v1.Session;
import org.dataone.client.auth.CertificateManager;
import org.dataone.configuration.Settings;
import org.junit.Test;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;


public class TokenGeneratorTest {

    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_FULL_NAME = "Jane Scientist";
    public static final String PUB_CERT_KEY = "cn.server.publiccert.filename";
    private static final String CERT_BASE = "src/test/resources/org/dataone/portal/";
    public static final String LOCAL_CERT_1 = CERT_BASE + "unitTestSelfSignedCert.pem";
    public static final String LOCAL_CERT_2 = CERT_BASE + "unitTestSelfSignedCert2.pem";

    @Test
    public void testBasicCalendarInstanceAssumptions() {
        // make sure getInstance() doesn't mean it's a singleton
        Calendar x = Calendar.getInstance();
        Date now = x.getTime();
        Calendar y = Calendar.getInstance();
        System.out.println(y);
        if (x == y) {
            fail("Calendar instances are the same. Not expected");
        }
        Date later = x.getTime();
        if (now.getTime() != later.getTime()) {
            fail("Calendar.getTime() should return a constant value over time (a Date object)");
        }
    }

    @Test
    public void testFetchServerCertificate() throws IOException {
        assertTrue(CertificateManager.getInstance().getSubjectDN(fetchServerCertificate())
                       .contains("dataone.org"));
    }

    @Test
    public void testGetJWT() throws Exception {

        // To parse the JWS and verify it, e.g. on client-side
        SignedJWT signedJWT = SignedJWT.parse(getTestToken());

        // verify
        String certificateFileName =
            Settings.getConfiguration().getString(PUB_CERT_KEY);
        RSAPublicKey publicKey = (RSAPublicKey) CertificateManager.getInstance()
            .loadCertificateFromFile(certificateFileName).getPublicKey();

        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        assertTrue(signedJWT.verify(verifier));

        // make sure the secret is required for verification
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair kp = keyGenerator.genKeyPair();
        RSAPublicKey otherKey = (RSAPublicKey) kp.getPublic();

        JWSVerifier invalidVerifier = new RSASSAVerifier(otherKey);
        assertFalse(signedJWT.verify(invalidVerifier));

        // Retrieve the JWT claims
        assertEquals(TEST_USER_ID, signedJWT.getJWTClaimsSet().getClaim("userId"));
        assertEquals(TEST_USER_ID, signedJWT.getJWTClaimsSet().getClaim("sub"));
        assertEquals(TEST_USER_ID, signedJWT.getJWTClaimsSet().getSubject());

        assertTrue(Calendar.getInstance().getTime()
                       .before(signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    @Test
    public void testGetSession() throws Exception {

        Session session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNotNull(session);
        assertEquals(TEST_USER_ID, session.getSubject().getValue());
    }

    @Test
    public void testGetSession_multipleCerts() throws Exception {

        // save original values so we can clean up afterward
        String pvtKeyKey = "cn.server.privatekey.filename";
        String origPvtKey = Settings.getConfiguration().getString(pvtKeyKey);
        String origLocalCert = Settings.getConfiguration().getString(PUB_CERT_KEY);
        String cnUrlKey = "D1Client.CN_URL";
        String origCnUrl = Settings.getConfiguration().getString(cnUrlKey);
        ////////

        // should fail: sign with pvt key 1; verify against pub key 2
        Settings.getConfiguration().setProperty(pvtKeyKey, LOCAL_CERT_1);
        Settings.getConfiguration().setProperty(PUB_CERT_KEY, LOCAL_CERT_2);
        TokenGenerator.getInstance().setPublicKeys();

        Session session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNull(session);
        // should be 2 certs in store: one from CN and 1 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 2,
                     TokenGenerator.publicKeys.size());

        // should fail: sign with pvt key 2; verify against pub key 1
        Settings.getConfiguration().setProperty(pvtKeyKey, LOCAL_CERT_1);
        Settings.getConfiguration().setProperty(PUB_CERT_KEY, LOCAL_CERT_2);
        TokenGenerator.getInstance().setPublicKeys();

        session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNull(session);
        // should be 2 certs in store: one from CN and 1 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 2,
                     TokenGenerator.publicKeys.size());

        // should pass: sign with pvt key 1; verify against pvt keys 1 & 2
        Settings.getConfiguration().setProperty(pvtKeyKey, LOCAL_CERT_1);
        Settings.getConfiguration().setProperty(PUB_CERT_KEY, LOCAL_CERT_2 + ";" + LOCAL_CERT_1);
        TokenGenerator.getInstance().setPublicKeys();

        session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNotNull(session);
        assertEquals(TEST_USER_ID, session.getSubject().getValue());
        // should be 3 certs in store: one from CN and 2 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 3,
                     TokenGenerator.publicKeys.size());

        // should pass: sign with pvt key 2; verify against pvt keys 1 & 2
        Settings.getConfiguration().setProperty(pvtKeyKey, LOCAL_CERT_2);
        Settings.getConfiguration().setProperty(PUB_CERT_KEY, LOCAL_CERT_1 + ";" + LOCAL_CERT_2);
        TokenGenerator.getInstance().setPublicKeys();

        session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNotNull(session);
        assertEquals(TEST_USER_ID, session.getSubject().getValue());
        // should be 3 certs in store: one from CN and 2 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 3,
                     TokenGenerator.publicKeys.size());

        // clean up
        Settings.getConfiguration().setProperty(pvtKeyKey, origPvtKey);
        Settings.getConfiguration().setProperty(PUB_CERT_KEY, origLocalCert);
        Settings.getConfiguration().setProperty(cnUrlKey, origCnUrl);
    }

    @Test
    public void testSetPublicKeys_multipleCerts() throws Exception {

        String orig = Settings.getConfiguration().getString(PUB_CERT_KEY);
        String bogusLocalCert = "/tmp/nonExistentCert.pem";

        ///////////////////////////////////////////
        // Verify code can handle missing config
        // (i.e. backwards compatible)
        ///////////////////////////////////////////
        Settings.getConfiguration().clearProperty(PUB_CERT_KEY);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 1 public key total: none from disk & one from CN server
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 1,
                     TokenGenerator.publicKeys.size());

        Settings.getConfiguration().addProperty(PUB_CERT_KEY, null);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 1 public key total: none from disk & one from CN server
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 1,
                     TokenGenerator.publicKeys.size());

        ///////////////////////////////////////////
        // Verify 1 local cert & 1 server cert case
        // (i.e. backwards compatible)
        ///////////////////////////////////////////
        Settings.getConfiguration().setProperty(PUB_CERT_KEY, LOCAL_CERT_1);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 2 public keys total: one from disk & one from CN server
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 2,
                     TokenGenerator.publicKeys.size());

        ///////////////////////////////////////////
        // Verify 1 present & 1 missing local cert
        ///////////////////////////////////////////
        Settings.getConfiguration()
            .setProperty(PUB_CERT_KEY, LOCAL_CERT_1 + ";" + bogusLocalCert);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 2 public keys total: one from disk & one from CN server. Other one from
        // disk
        // was a bogus path
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 2,
                     TokenGenerator.publicKeys.size());

        ///////////////////////////////////////////
        // Verify duplicate local certs appear once
        ///////////////////////////////////////////
        Settings.getConfiguration()
            .setProperty(PUB_CERT_KEY, LOCAL_CERT_1 + ";" + LOCAL_CERT_1);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 2 public keys total: one from disk & one from CN server.
        // Other one from disk was a repeat
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 2,
                     TokenGenerator.publicKeys.size());

        Settings.getConfiguration().setProperty(PUB_CERT_KEY, orig);
    }

    @Test
    public void testSetPublicKeys_ordering() throws Exception {
        ////////////////////////////////////////////////////
        // Verify duplicate server & local certs appear once
        // and server cert appears first in list
        ////////////////////////////////////////////////////
        X509Certificate serverCertCopy = fetchServerCertificate();
        assertNotNull(serverCertCopy);
        String locServerCertCopy = CERT_BASE + "unitTestLocalServerCertCopy.pem";
        Path serverCertCopyFile = null;
        try {
            String encodedCert = Base64.getEncoder().encodeToString(serverCertCopy.getEncoded());

            // Wrap the encoded certificate with PEM headers and footers
            String pemCert = "-----BEGIN CERTIFICATE-----\n" + encodedCert + "\n-----END CERTIFICATE-----";

            // Write the PEM formatted certificate to a file
            serverCertCopyFile = Files.write(Paths.get(locServerCertCopy), pemCert.getBytes());
            Settings.getConfiguration().setProperty(
                PUB_CERT_KEY, LOCAL_CERT_1 + ";" + locServerCertCopy + ";" + LOCAL_CERT_2);
            TokenGenerator.getInstance().setPublicKeys();

            // should be 3 public keys total: two from disk & one from CN server.
            // Other one from disk was a repeat of server one
            assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()), 3,
                         TokenGenerator.publicKeys.size());

            // Ensure server cert appears first in list
            RSAPublicKey serverPubKey = (RSAPublicKey) serverCertCopy.getPublicKey();
            assertEquals(serverPubKey, TokenGenerator.publicKeys.get(0));
        } finally {
            // delete file
            if (serverCertCopyFile != null) {
                Files.deleteIfExists(serverCertCopyFile);
            }
        }
    }

    private String getTestToken() throws Exception {
        return TokenGenerator.getInstance().getJWT(TEST_USER_ID, TEST_FULL_NAME);
    }

    private X509Certificate fetchServerCertificate() throws IOException {
        return (X509Certificate) TokenGenerator.getInstance().fetchServerCertificate();
    }
}
