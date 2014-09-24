package org.dataone.portal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.dataone.configuration.Settings;
import org.junit.Test;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;

public class TokenGeneratorTest {

	@Test
    public void testGetJWT() {
    	try {
    	
	    	String sharedSecret = Settings.getConfiguration().getString("annotator.sharedSecret");
	    	
	    	String userId = "test";
			
			String token = TokenGenerator.getJWT(userId);
			
			// To parse the JWS and verify it, e.g. on client-side
			SignedJWT signedJWT = SignedJWT.parse(token);
	
			JWSVerifier verifier = new MACVerifier(sharedSecret);
	
			assertTrue(signedJWT.verify(verifier));
	
			// Retrieve the JWT claims
			assertEquals(userId, signedJWT.getJWTClaimsSet().getClaim("userId"));
    	
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	
    }
    
}
