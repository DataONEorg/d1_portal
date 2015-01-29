package org.dataone.portal;

import static org.junit.Assert.assertTrue;

import java.text.ParseException;
import java.util.Calendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.configuration.Settings;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.util.DateTimeMarshaller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Class for generating JSON web tokens for authenticated users.
 * Targeting this for use with AnnotateIt.org.
 * @see "http://docs.annotatorjs.org/en/latest/authentication.html"
 * @author leinfelder
 *
 */
public class TokenGenerator {
	
    public static Log log = LogFactory.getLog(TokenGenerator.class);


    public static String getJWT(String userId, String fullName) throws JOSEException, ParseException {
    	String sharedSecret = Settings.getConfiguration().getString("annotator.sharedSecret");
    	String consumerKey = Settings.getConfiguration().getString("annotator.consumerKey");

		JWSSigner signer = new MACSigner(sharedSecret);
		
		Calendar now = Calendar.getInstance();
		
		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setClaim("consumerKey", consumerKey);
		claimsSet.setClaim("userId", userId);
		claimsSet.setClaim("fullName", fullName);
		claimsSet.setClaim("issuedAt", DateTimeMarshaller.serializeDateToUTC(now.getTime()));
		claimsSet.setClaim("ttl", 86400);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		// Apply the HMAC
		signedJWT.sign(signer);

		// To serialize to compact form, produces something like
		// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
		String token = signedJWT.serialize();
		
		return token;
    	
    }
    
    public static Session getSession(String token) {
    	Session session = null;
    	
    	try {
	    	// parse the JWS and verify it
	    	String sharedSecret = Settings.getConfiguration().getString("annotator.sharedSecret");
			SignedJWT signedJWT = SignedJWT.parse(token);
			JWSVerifier verifier = new MACVerifier(sharedSecret);
			assertTrue(signedJWT.verify(verifier));
			
			// extract user info
			String userId = signedJWT.getJWTClaimsSet().getClaim("userId").toString();
			Subject subject = new Subject();
			subject.setValue(userId);
			session = new Session();
			session.setSubject(subject);
			
    	} catch (Exception e) {
    		// if we got here, we don't have a good session
    		log.warn("Could not get session from provided token: " + token, e);
    		return null;
    	}
    	
    	return session;
    }
    
}
