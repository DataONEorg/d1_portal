package org.dataone.portal;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.auth.CertificateManager;
import org.dataone.client.v1.itk.D1Client;
import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.BaseException;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectInfo;
import org.dataone.service.util.DateTimeMarshaller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
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

    private static TokenGenerator instance = null;
    
    private String consumerKey = null;
    private RSAPublicKey publicKey = null;
	private RSAPrivateKey privateKey = null;
	
	public static TokenGenerator getInstance() throws IOException {
		if (instance == null) {
			instance = new TokenGenerator();
		}
		return instance;
	}
	
    private TokenGenerator() throws IOException  {
     	
    	String privateKeyFileName = Settings.getConfiguration().getString("cn.server.privatekey.filename");
    	String privateKeyPassword = null;
    	
    	// consumers do not need the private key
    	if (privateKeyFileName != null) {
    		privateKey = (RSAPrivateKey) CertificateManager.getInstance().loadPrivateKeyFromFile(privateKeyFileName, privateKeyPassword);
    	}

		consumerKey = Settings.getConfiguration().getString("annotator.consumerKey");
		
		// use either the configured certificate, or fetch it from the CN
		String certificateFileName = Settings.getConfiguration().getString("cn.server.publiccert.filename");
		if (certificateFileName != null) {
	    	publicKey = (RSAPublicKey) CertificateManager.getInstance().loadCertificateFromFile(certificateFileName).getPublicKey();
		} else {
			Certificate cert = fetchServerCertificate();
			if (cert != null) {
				publicKey = (RSAPublicKey) cert.getPublicKey();
			}
		}
		
    }

    public Certificate fetchServerCertificate() {
		try {
			String baseUrl = D1Client.getCN().getNodeBaseServiceUrl();
			URL url = new URL(baseUrl);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.connect();
			Certificate serverCertificate = conn.getServerCertificates()[0];
			return serverCertificate;
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
		
		return null;
	}

	public String getJWT(String userId, String fullName) throws JOSEException, ParseException, IOException {
    	
		// Create RSA-signer with the private key
    	JWSSigner signer = new RSASSASigner(privateKey);
		
		Calendar now = Calendar.getInstance();
		
		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setClaim("consumerKey", consumerKey);
		claimsSet.setClaim("userId", userId);
		claimsSet.setClaim("fullName", fullName);
		claimsSet.setClaim("issuedAt", DateTimeMarshaller.serializeDateToUTC(now.getTime()));
		claimsSet.setClaim("ttl", 86400);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);

		// Compute the RSA signature
		signedJWT.sign(signer);

		// To serialize to compact form, produces something like
		// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
		String token = signedJWT.serialize();
		
		return token;
    	
    }
    
    public Session getSession(String token) {
    	Session session = null;
    	
    	try {
	    	// parse the JWS and verify it
			SignedJWT signedJWT = SignedJWT.parse(token);
	
			JWSVerifier verifier = new RSASSAVerifier(publicKey);
			assertTrue(signedJWT.verify(verifier));
			
			// extract user info
			String userId = signedJWT.getJWTClaimsSet().getClaim("userId").toString();
			Subject subject = new Subject();
			subject.setValue(userId);
			session = new Session();
			session.setSubject(subject);
			
			SubjectInfo subjectInfo = null;
			try {
				subjectInfo = D1Client.getCN().getSubjectInfo(subject);
			} catch (BaseException be) {
				log.warn(be.getMessage());
			}
			
			// TODO: fill in more subject info if we didn't retrieve it
			if (subjectInfo == null) {
				subjectInfo = new SubjectInfo();
				Person person = new Person();
				person.setSubject(subject);
				subjectInfo.setPersonList(Arrays.asList(person));
			}
			session.setSubjectInfo(subjectInfo);
			
    	} catch (Exception e) {
    		// if we got here, we don't have a good session
    		log.warn("Could not get session from provided token: " + token, e);
    		return null;
    	}
    	
    	return session;
    }
    
}
