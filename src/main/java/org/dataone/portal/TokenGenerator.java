package org.dataone.portal;

import java.text.ParseException;
import java.util.Calendar;

import org.dataone.configuration.Settings;
import org.dataone.service.util.DateTimeMarshaller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
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
    
}
