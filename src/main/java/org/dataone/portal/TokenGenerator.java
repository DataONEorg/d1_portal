package org.dataone.portal;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.auth.AuthTokenSession;
import org.dataone.client.auth.CertificateManager;
import org.dataone.client.v1.itk.D1Client;
import org.dataone.configuration.Settings;
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
 * Class for generating JSON web tokens for authenticated users. Targeting this for use with
 * AnnotateIt.org.
 *
 * @author leinfelder
 * @see "http://docs.annotatorjs.org"
 */
public class TokenGenerator {

    public static Log log = LogFactory.getLog(TokenGenerator.class);

    private static volatile TokenGenerator instance = null;

    private String consumerKey = null;
    protected static List<RSAPublicKey> publicKeys = null;
    private BigInteger serverPubKeyModulus;
    private RSAPrivateKey privateKey = null;

    // 18 hour default, like certificates, in seconds
    private final int TTL_SECONDS = Settings.getConfiguration().getInt("token.ttl", 18 * 60 * 60);


    public static TokenGenerator getInstance() throws IOException {
        if (instance == null) {
            synchronized (TokenGenerator.class) {
                if (instance == null) {
                    instance = new TokenGenerator();
                }
            }
        }
        return instance;
    }

    /*
     * Construct a token generator
     * @throws IOException an I/O exception if the certificates cannot be read
     */
    private TokenGenerator() throws IOException {

        setAllKeys();

        /* Create a timer to monitor the signing certificate every five minutes */
        Timer timer = new Timer("Signing Certificate Monitor");

        long certMonitorPeriod = 5 * 60 * 1000;
        timer.scheduleAtFixedRate(new TimerTask() {
            /**
             * Check the server certificate's public key modulus for changes
             * Update the TokenGenerator singleton if it has changed
             */
            @Override
            public void run() {
                try {
                    Certificate newServerCert = fetchServerCertificate();
                    if (newServerCert != null) {
                        RSAPublicKey newPubKey = (RSAPublicKey) newServerCert.getPublicKey();
                        // Replace the singleton in-memory key if it does not match the fetched key
                        if (!newPubKey.getModulus().equals(serverPubKeyModulus)) {
                            setAllKeys();
                            log.info(
                                "Portal reset the private key and public certificate after the "
                                + "certificate was renewed. The new certificate has the "
                                + "modulus " + serverPubKeyModulus);
                        }
                    }
                } catch (Exception e) {
                    log.warn("Couldn't fetch the server certificate for change comparison. "
                                 + e.getMessage());
                }
            }
        }, new Date(), certMonitorPeriod);
    }

    /**
     * fetches the server certificates from the remote CN using the configured CN baseurl from
     * d1_libclient_java.  Returns the first server certificate.
     *
     * @return either the Certificate or null (if problem)
     */
    public Certificate fetchServerCertificate() {
        String baseUrl = "URL NOT FOUND!";
        try {
            baseUrl = D1Client.getCN().getNodeBaseServiceUrl();
            URL url = new URL(baseUrl);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            // it's safe to select the first array member, because `getServerCertificates()` returns
            //   "...an ordered array of server certificates, with the peer's
            //    own certificate first followed by any certificate authorities."
            // @see https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/HttpsURLConnection.html#getServerCertificates--
            return conn.getServerCertificates()[0];
        } catch (Exception e) {
            log.error("Unable to fetch cert from server: " + baseUrl + "; error was: " + e.getMessage(), e);
        }

        return null;
    }

    public String getJWT(String userId, String fullName)
        throws JOSEException, ParseException, IOException {

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
        return signedJWT.serialize();
    }

    /*
     * Set the private key
     * @throws IOException IO exception
     */
    private synchronized void setPrivateKey() throws IOException {
        String privateKeyFileName =
            Settings.getConfiguration().getString("cn.server.privatekey.filename");

        CertificateManager cmInst = CertificateManager.getInstance();
        // consumers do not need the private key
        if (privateKeyFileName != null) {
            // uses a null password:
            privateKey = (RSAPrivateKey) cmInst.loadPrivateKeyFromFile(privateKeyFileName, null);
        }
    }

    /*
     * Set the public key
     * @throws IOException
     */
    protected synchronized void setPublicKeys() throws IOException {

        publicKeys = new ArrayList<>();
        List<BigInteger> publicKeyModuli = new ArrayList<>();
        BigInteger currentKeyModulus;

        // Always add the CN server cert as the first list item, to reduce lookup time, since
        // this is the most-used cert
        Certificate cert = fetchServerCertificate();
        if (cert != null) {
            RSAPublicKey serverPublicKey = (RSAPublicKey) cert.getPublicKey();
            publicKeys.add(serverPublicKey);

            // keep a global copy of public key modulus, so we can periodically check if it's been
            // updated
            serverPubKeyModulus = serverPublicKey.getModulus();
            publicKeyModuli.add(serverPubKeyModulus);

            log.info("Successfully added cert from CN server, with modulus beginning: "
                         + serverPubKeyModulus.toString().substring(0, 10) + "...");
        } else {
            log.warn("There was a problem retrieving the Certificate from the server.");
        }

        // now add any local certificates, if configured
        String[] certificateFileNames =
            Settings.getConfiguration().getStringArray("cn.server.publiccert.filename");
        if (certificateFileNames == null || certificateFileNames.length == 0) {
            log.info("No local certs defined in Settings");
            return;
        }
        log.debug("local certificate FileNames to be loaded: \n"
                      + Arrays.toString(certificateFileNames));
        for (String certFileName : certificateFileNames) {
            Path certPath = Paths.get(certFileName);
            if (Files.isDirectory(certPath) || !Files.isReadable(certPath)) {
                // Note: see https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html -
                // "Accessing a file using an empty path is equivalent to accessing the default
                // directory of the file system".
                // So if certFileName == "", Files.isReadable(certPath) will be true. However,
                // the Files.isDirectory("") check will filter out this value
                log.warn("No readable Certificate file found at path: " + certFileName);
                continue;
            }
            RSAPublicKey currentKey = (RSAPublicKey) CertificateManager.getInstance()
                .loadCertificateFromFile(certFileName).getPublicKey();

            currentKeyModulus = currentKey.getModulus();

            if (publicKeyModuli.contains(currentKeyModulus)) {
                log.warn("Certificate file " + certFileName + " is a duplicate.");
                continue;
            }
            publicKeys.add(currentKey);
            publicKeyModuli.add(currentKeyModulus);

            log.info("Successfully added cert: " + certFileName + ", with modulus beginning: "
                         + currentKeyModulus.toString().substring(0, 10) + "...");
        }
    }

    /*
     * Set the consumer key
     */
    private void setConsumerKey() {
        consumerKey = Settings.getConfiguration().getString("annotator.consumerKey");
    }

    /**
     * Uses configured public keys to verify provided token. Then extracts the subject from the
     * token string, and attempts to get the SubjectInfo from the CN. If unsuccessful, builds a
     * SubjectInfo entry from the token subject.
     *
     * @param token the given JWT token string
     * @return a Session or null if Exceptions raised (they are logged as Warnings)
     */
    public Session getSession(String token) {

        AuthTokenSession session;
        try {
            // parse the JWS and verify it
            SignedJWT signedJWT = SignedJWT.parse(token);

            // verify the signing
            if (!isKeyVerified(signedJWT)) {
                log.warn("FAILED to verify token against (total " + publicKeys.size()
                             + ") configured public key(s)");

                // Reload the certificate keys in case they changed, and retry
                setAllKeys();

                if (!isKeyVerified(signedJWT)) {
                    log.warn("FAILED a second time, to verify token against (total "
                                 + publicKeys.size() + ") configured public key(s). "
                                 + "Non-valid token follows:\n" + token);
                    return null;
                }
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
                subjectInfo.setPersonList(Collections.singletonList(person));
            }
            session.setSubjectInfo(subjectInfo);

        } catch (Exception e) {
            // if we got here, we don't have a good session
            log.warn("Could not get session from provided token: " + token, e);
            return null;
        }
        return session;
    }

    private boolean isKeyVerified(SignedJWT signedJWT) throws JOSEException {
        JWSVerifier verifier;
        for (RSAPublicKey publicKey : publicKeys) {
            verifier = new RSASSAVerifier(publicKey);
            if (signedJWT.verify(verifier)) {
                return true;
            }
        }
        return false;
    }

    private void setAllKeys() throws IOException {
        setPublicKeys();
        setPrivateKey();
        setConsumerKey();
    }

    /**
     * For generating custom tokens outside the portal workflow. These properties should be set in
     * portal.properties:
     *      token.ttl=31536000
     *      cn.server.privatekey.filename=/Users/leinfelder/Downloads/dataone_org.key
     *      cn.server.publiccert.filename=/Users/leinfelder/Downloads/_.dataone.org.crt
     * The main class should be called with <userId> and <fullName> parameters. The token will be
     * printed to System.out
     *
     * @param args command-line arguments: <userId> (required) and <fullName> (optional)
     */
    public static void main(String[] args) {

        String userId = args[0];
        String fullName = "Unknown";
        if (args.length > 1) {
            fullName = args[1];
        }
        String token = null;
        try {
            token = TokenGenerator.getInstance().getJWT(userId, fullName);
        } catch (JOSEException | ParseException | IOException e) {
            e.printStackTrace();
        }
        System.out.println(token);
    }

}
