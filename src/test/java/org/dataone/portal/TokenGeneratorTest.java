package org.dataone.portal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import org.dataone.client.auth.CertificateManager;
import org.dataone.configuration.Settings;
import org.junit.BeforeClass;
import org.junit.Test;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

public class TokenGeneratorTest {

	@BeforeClass
	public static void setUp() throws FileNotFoundException {
		
		//File certificateFile = CertificateManager.getInstance().locateDefaultCertificate();
		URL url = TokenGeneratorTest.class.getResource("unitTestSelfSignedCert.pem");
		String certificatePath = url.getPath();
		String keyPath = url.getPath();

//		Settings.getConfiguration().setProperty("cn.server.publiccert.filename", certificatePath);
//		Settings.getConfiguration().setProperty("cn.server.privatekey.filename", keyPath);

	}
	
	
	@Test
    public void testGetJWT() {
    	try {
    		    	
	    	String userId = "test";
	    	
	    	String fullName = "Jane Scientist";
			
			String token = TokenGenerator.getInstance().getJWT(userId, fullName);
			
			// To parse the JWS and verify it, e.g. on client-side
			SignedJWT signedJWT = SignedJWT.parse(token);
	
			// verify
	    	String certificateFileName = Settings.getConfiguration().getString("cn.server.publiccert.filename");
			RSAPublicKey publicKey = (RSAPublicKey) CertificateManager.getInstance().loadCertificateFromFile(certificateFileName).getPublicKey();

			JWSVerifier verifier = new RSASSAVerifier(publicKey);
			assertTrue(signedJWT.verify(verifier));
			
			// make sure the secret is required for verification
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(1024);
			KeyPair kp = keyGenerator.genKeyPair();
			RSAPublicKey otherKey = (RSAPublicKey)kp.getPublic();
			
			JWSVerifier invalidVerifier = new RSASSAVerifier(otherKey);
			assertFalse(signedJWT.verify(invalidVerifier));
			
			// Retrieve the JWT claims
			assertEquals(userId, signedJWT.getJWTClaimsSet().getClaim("userId"));
    	
    	} catch (Exception e) {
    		e.printStackTrace();
    		fail(e.getMessage());
    	}
    	
    }

    
}
