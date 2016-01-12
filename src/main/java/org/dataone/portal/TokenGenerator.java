package org.dataone.portal;

import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.auth.AuthTokenSession;
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
	
	// 18 hour default, like certificates, in seconds
	private int TTL_SECONDS = Settings.getConfiguration().getInt("token.ttl", 18 * 60 * 60); 
	
	public static TokenGenerator getInstance() throws IOException {
		if (instance == null) {
			instance = new TokenGenerator();
		}
		return instance;
	}
	
    private TokenGenerator() throws IOException  {
     	
    	String privateKeyFileName = Settings.getConfiguration().getString("cn.server.privatekey.filename");
    	String privateKeyPassword = null;
    	
    	CertificateManager cmInst = CertificateManager.getInstance();
    	// consumers do not need the private key
    	if (privateKeyFileName != null) {
    		privateKey = (RSAPrivateKey) cmInst.loadPrivateKeyFromFile(privateKeyFileName, privateKeyPassword);
    	}

		consumerKey = Settings.getConfiguration().getString("annotator.consumerKey");
		
		// use either the configured certificate, or fetch it from the CN
		String certificateFileName = Settings.getConfiguration().getString("cn.server.publiccert.filename");
		log.debug("certificateFileName=" +  certificateFileName);
		if (certificateFileName != null && certificateFileName.length() > 0) {
	    	publicKey = (RSAPublicKey) cmInst.loadCertificateFromFile(certificateFileName).getPublicKey();
		} else {
			Certificate cert = fetchServerCertificate();
			log.debug("using certificate from server: " +  cert);
			if (cert != null) {
				publicKey = (RSAPublicKey) cert.getPublicKey();
			}  // what happens if publicKey is null?
		}
		
    }

    /**
     * fetches the server certificates from the remote CN using the configured
     * CN baseurl from d1_libclient_java.  Returns the first server certificate.
     * 
     * @return either the Certificate or null (if problem)
     */
    public Certificate fetchServerCertificate() {
		try {
			String baseUrl = D1Client.getCN().getNodeBaseServiceUrl();
			log.debug("fetching cert from server: " +  baseUrl);
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
		
    	// Calendar instances are associated with a fixed Date, confusingly
    	// accessed with getTime() method.  
		Calendar now = Calendar.getInstance();
		Calendar expires = Calendar.getInstance();
		expires.setTime(now.getTime());
		expires.add(Calendar.SECOND, TTL_SECONDS);
		
		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet();
		// claims for annotator: http://docs.annotatorjs.org/en/v1.2.x/authentication.html
		claimsSet.setClaim("consumerKey", consumerKey);
		claimsSet.setClaim("userId", userId);
		claimsSet.setClaim("issuedAt", DateTimeMarshaller.serializeDateToUTC(now.getTime()));
		claimsSet.setClaim("ttl", TTL_SECONDS); 
		
		claimsSet.setClaim("fullName", fullName);

		// standard JWT fields: https://tools.ietf.org/html/rfc7519#section-4.1.4
		claimsSet.setSubject(userId);
		claimsSet.setIssueTime(now.getTime());
		claimsSet.setExpirationTime(expires.getTime());
		
		// purposefully skipping setting the claimsSet.setNotBeforeTime(nbf) to 
		// avoid fussiness related to clock skew.
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);

		// Compute the RSA signature
		signedJWT.sign(signer);

		// To serialize to compact form, produces something like
		// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
		String token = signedJWT.serialize();
		
		return token;
    	
    }
    /**
     * Extracts the subject from the token string, and attempts to get the
     * SubjectInfo from the CN.  If not able to, builds a SubjectInfo entry 
     * from the token subject.
     * @param token
     * @return  a Session or null if Exceptions raised (they are logged as Warnings)
     */
    public Session getSession(String token) {
    	AuthTokenSession session = null;
    	
    	try {
	    	// parse the JWS and verify it
			SignedJWT signedJWT = SignedJWT.parse(token);
	
			// verify the signing
			JWSVerifier verifier = new RSASSAVerifier(publicKey);
			if (!signedJWT.verify(verifier)) {
	    		log.info("public key: " + publicKey);
	    		log.warn("Could not use public key to verify provided token: " + token);
				return null;
			}
			
			// check the expiration
			Calendar now = Calendar.getInstance();
			Date expDate = signedJWT.getJWTClaimsSet().getExpirationTime();
			if (!expDate.after(now.getTime())) {
	    		log.warn("Token expiration date has passed: " + expDate);
				return null;
			}
			
			// we only accept tokens generated in this class, and since we don't
			// generate a NotBeforeTime claim, we don't need to process it.
			
			// extract user info
			String userId = signedJWT.getJWTClaimsSet().getSubject();
			Subject subject = new Subject();
			subject.setValue(userId);
			session = new AuthTokenSession(token);
			session.setSubject(subject);
			
			SubjectInfo subjectInfo = null;
			try {
				subjectInfo = D1Client.getCN().getSubjectInfo(subject);
			} catch (Exception be) {
				log.warn(be.getMessage(), be);
			}
			
			// TODO: fill in more subject info if we didn't retrieve it
			if (subjectInfo == null) {
				subjectInfo = new SubjectInfo();
				Person person = new Person();
				person.setSubject(subject);
				person.setFamilyName("Unknown");
            	person.addGivenName("Unknown");
				subjectInfo.setPersonList(Arrays.asList(person));
			}
			session.setSubjectInfo(subjectInfo);
			
    	} catch (Exception e) {
    		// if we got here, we don't have a good session
    		log.warn("Could not get session from provided token: " + token, e);
//    		e.printStackTrace();
    		return null;
    	}
    	
    	return session;
    }
    
}
