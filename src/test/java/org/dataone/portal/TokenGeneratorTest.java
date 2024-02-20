package org.dataone.portal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
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
    public void testFetchServerCertificate() {
        X509Certificate certificate;
        try {
            certificate = (X509Certificate) TokenGenerator.getInstance().fetchServerCertificate();
            assertTrue(
                CertificateManager.getInstance().getSubjectDN(certificate).contains("dataone.org"));
        } catch (IOException e) {
            fail(e.getMessage());
        }
    }


    @Test
    public void testGetJWT() throws Exception {

        // To parse the JWS and verify it, e.g. on client-side
        SignedJWT signedJWT = SignedJWT.parse(getTestToken());

        // verify
        String certificateFileName =
            Settings.getConfiguration().getString("cn.server.publiccert.filename");
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

        // save original values so we can clean up afterwards
        String pvtKeyKey = "cn.server.privatekey.filename";
        String origPvtKey = Settings.getConfiguration().getString(pvtKeyKey);
        String pubCertkey = "cn.server.publiccert.filename";
        String origLocalCert = Settings.getConfiguration().getString(pubCertkey);
        String cnUrlKey = "D1Client.CN_URL";
        String origCnUrl = Settings.getConfiguration().getString(cnUrlKey);
        ////////

        // these pem files contain both the private and public keys
        String cert1 = "src/test/resources/org/dataone/portal/unitTestSelfSignedCert.pem";
        String cert2 = "src/test/resources/org/dataone/portal/unitTestSelfSignedCert2.pem";

        // should fail: sign with pvt key 1; verify against pub key 2
        Settings.getConfiguration().setProperty(pvtKeyKey, cert1);
        Settings.getConfiguration().setProperty(pubCertkey, cert2);
        TokenGenerator.getInstance().setPublicKeys();

        Session session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNull(session);
        // should be 2 certs in store: one from CN and 1 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()),
                     2, TokenGenerator.publicKeys.size());

        // should fail: sign with pvt key 2; verify against pub key 1
        Settings.getConfiguration().setProperty(pvtKeyKey, cert1);
        Settings.getConfiguration().setProperty(pubCertkey, cert2);
        TokenGenerator.getInstance().setPublicKeys();

        session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNull(session);
        // should be 2 certs in store: one from CN and 1 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()),
                     2, TokenGenerator.publicKeys.size());

        // should pass: sign with pvt key 1; verify against pvt keys 1 & 2
        Settings.getConfiguration().setProperty(pvtKeyKey, cert1);
        Settings.getConfiguration().setProperty(pubCertkey, cert2 + ";" + cert1);
        TokenGenerator.getInstance().setPublicKeys();

        session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNotNull(session);
        assertEquals(TEST_USER_ID, session.getSubject().getValue());
        // should be 3 certs in store: one from CN and 2 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()),
                     3, TokenGenerator.publicKeys.size());

        // should pass: sign with pvt key 2; verify against pvt keys 1 & 2
        Settings.getConfiguration().setProperty(pvtKeyKey, cert2);
        Settings.getConfiguration().setProperty(pubCertkey, cert1 + ";" + cert2);
        TokenGenerator.getInstance().setPublicKeys();

        session = TokenGenerator.getInstance().getSession(getTestToken());
        assertNotNull(session);
        assertEquals(TEST_USER_ID, session.getSubject().getValue());
        // should be 3 certs in store: one from CN and 2 local
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()),
                     3, TokenGenerator.publicKeys.size());

        // clean up
        Settings.getConfiguration().setProperty(pvtKeyKey, origPvtKey);
        Settings.getConfiguration().setProperty(pubCertkey, origLocalCert);
        Settings.getConfiguration().setProperty(cnUrlKey, origCnUrl);
    }

    @Test
    public void testSetPublicKeys_multipleCerts() throws Exception {

        String pubCertKey = "cn.server.publiccert.filename";
        String orig = Settings.getConfiguration().getString(pubCertKey);
        String validLocalCert = "src/test/resources/org/dataone/portal/unitTestSelfSignedCert.pem";
        String bogusLocalCert = "/tmp/nonExistentCert.pem";

        Settings.getConfiguration().setProperty(pubCertKey, validLocalCert);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 2 public keys total: one from disk & one from CN server
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()),
                     2, TokenGenerator.publicKeys.size());

        Settings.getConfiguration().setProperty(pubCertKey, validLocalCert + ";" + bogusLocalCert);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 2 public keys total: one from disk & one from CN server. Other one from disk
        // was a bogus path
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()),
                     2, TokenGenerator.publicKeys.size());

        Settings.getConfiguration().setProperty(pubCertKey, validLocalCert + ";" + validLocalCert);
        TokenGenerator.getInstance().setPublicKeys();
        // should be 2 public keys total: one from disk & one from CN server.
        // Other one from disk was a repeat
        assertEquals(Arrays.toString(TokenGenerator.publicKeys.toArray()),
                     2, TokenGenerator.publicKeys.size());

        Settings.getConfiguration().setProperty(pubCertKey, orig);
    }

    private String getTestToken() throws Exception {
        return TokenGenerator.getInstance().getJWT(TEST_USER_ID, TEST_FULL_NAME);
    }
}
