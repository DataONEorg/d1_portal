package org.dataone.portal;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Handler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.auth.CertificateManager;
import org.dataone.configuration.Settings;
import org.dataone.service.types.v1.Session;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.ClientEnvironmentUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;

public class PortalCertificateManager {
    //this default value can be overwritten by a property named "oa4mp.client.config.file" in the
    // portal.properties file.
    private static final String DEFAULT_OA4MP_CONFIG_PATH =
        "/var/lib/tomcat7/webapps/portal/WEB-INF/client.xml";

    private String configFile = Settings.getConfiguration()
        .getString("oa4mp.client.config.file", DEFAULT_OA4MP_CONFIG_PATH);

    private String configName = null;

    private static int maxAttempts = 10;

    private static volatile PortalCertificateManager instance;

    public static Log log = LogFactory.getLog(PortalCertificateManager.class);

    public static PortalCertificateManager getInstance() {
        if (instance == null) {
            synchronized (PortalCertificateManager.class) {
                if (instance == null) {
                    instance = new PortalCertificateManager();
                }
            }
        }
        return instance;
    }

    public PortalCertificateManager() {
    }

    public PortalCertificateManager(String configFile) {
        this.configFile = configFile;
    }

    /**
     * To prevent .lck files from persisting, we close the loggers when shutting down the system
     * http://stackoverflow.com/questions/2723280/why-is-my-program-creating-empty-lck-files
     * @throws Exception
     */
    public void closeLoggers() throws Exception {
        ClientEnvironment ce = ClientEnvironmentUtil.load(new File(configFile), configName);
        Handler[] handlers = ce.getMyLogger().getLogger().getHandlers();
        // close the log handlers for uiuc
        for (Handler h : handlers) {
            h.close();   //must call h.close or a .LCK file will remain.
        }
    }

    /**
     * Gets the current configuration file path
     * @return
     */
    public String getConfigFile() {
        return configFile;
    }

    /**
     * Sets the client configuration file path
     * @param configFile
     */
    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    /**
     * Sets the certificate Cookie on the response. Future interactions with
     * this service will be tied to the certificate by this cookie
     *
     * @param identifier
     * @param httpServletResponse
     */
    public void setCookie(String identifier, HttpServletResponse httpServletResponse) {
        // SameSite=None:   Allow third-parties to use this cookie (needed for authentication from
        //                  other domains)
        // Secure:          Only send over HTTPS
        // Path:            Need to cross contexts
        // Max-Age:         18 hours for certificate, so the cookie need not be longer
        httpServletResponse.setHeader("Set-Cookie",
                                      ClientServlet.OA4MP_CLIENT_REQUEST_ID + "=" + identifier
                                          + "; SameSite=None; Secure; Path=/; Max-Age="
                                          + (18 * 60 * 60));
    }

    /**
     * Retrieves the certificate Cookie from the request
     *
     * @param httpServletRequest
     * @return
     */
    public Cookie getCookie(HttpServletRequest httpServletRequest) {
        if (httpServletRequest.getCookies() != null) {
            for (Cookie cookie : httpServletRequest.getCookies()) {
                if (cookie.getName().equals(ClientServlet.OA4MP_CLIENT_REQUEST_ID)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * Removes the certificate cookie, essentially logging out the user
     *
     * @param httpServletResponse
     */
    public void removeCookie(HttpServletResponse httpServletResponse) {
        // put our d1 cookie back but expires immediately to remove it
        Cookie cookie = new Cookie(ClientServlet.OA4MP_CLIENT_REQUEST_ID, "removeMe");
        cookie.setMaxAge(0); // clear now
        cookie.setPath("/"); // need to cross contexts
        httpServletResponse.addCookie(cookie);
    }

    /**
     * Get the certificate from the store, based on the cookie (if present)
     *
     * @param request
     * @return
     * @throws IOException
     */
    public X509Certificate getCertificate(HttpServletRequest request) throws Exception {
        Asset credential = getCredentials(request);
        if (credential == null || credential.getCertificates() == null
            || credential.getCertificates().length < 1) {
            return null;
        }
        return credential.getCertificates()[0];
    }

    /**
     * Get the private key from the store, based on the cookie (if present)
     *
     * @param request
     * @return
     * @throws IOException
     */
    public PrivateKey getPrivateKey(HttpServletRequest request) throws Exception {
        Asset credential = getCredentials(request);
        if (credential == null) {
            return null;
        }
        return credential.getPrivateKey();
    }

    /**
     * Get the credentials from the store, based on the token/identifier
     *
     * @param identifier
     *            for the certificate/credential
     * @return
     * @throws IOException
     */
    public Asset getCredentials(String identifier) throws Exception {

        if (identifier != null) {
            ClientEnvironment ce = ClientEnvironmentUtil.load(new File(configFile), configName);

            Asset asset = null;
            int attempts = 0;
            while (asset == null) {
                try {
                    asset = ce.getAssetStore().get(identifier);
                } catch (Exception e) {
                    // sleep and try again, for a while until failing
                    log.warn(
                        attempts + " - Error getting transaction, trying again. " + e.getMessage());
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ie) {
                        log.error("Could not wait for credentials: " + ie.getMessage());
                        // just throw the original error
                        throw e;
                    }
                    attempts++;
                    if (attempts > maxAttempts) {
                        throw e;
                    }
                }
            }

            return asset;
        }
        // if there was no cookie or certificate
        return null;
    }

    /**
     * Get the credentials from the store, based on the cookie (if present)
     *
     * @param request
     * @return
     * @throws IOException
     */
    public Asset getCredentials(HttpServletRequest request) throws Exception {
        Cookie[] cookies = request.getCookies();
        String identifier;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(ClientServlet.OA4MP_CLIENT_REQUEST_ID)) {
                    identifier = cookie.getValue();
                    return getCredentials(identifier);
                }
            }
        }
        return null;
    }

    public Session putPortalCertificateOnRequest(HttpServletRequest request) throws Exception {
        Session session = CertificateManager.getInstance().getSession(request);
        if (session == null) {
            X509Certificate certificate =
                PortalCertificateManager.getInstance().getCertificate(request);
            log.debug("Proxy certificate for the request = " + certificate);
            if (certificate != null) {
                X509Certificate[] x509Certificates = new X509Certificate[]{certificate};
                request.setAttribute("javax.servlet.request.X509Certificate", x509Certificates);
                log.debug("Added proxy certificate to the request");
            }
            session = CertificateManager.getInstance().getSession(request);
        }
        return session;
    }

    public void registerPortalCertificateWithCertificateManger(HttpServletRequest request)
        throws Exception {
        X509Certificate certificate =
            PortalCertificateManager.getInstance().getCertificate(request);
        if (certificate != null) {
            PrivateKey key = PortalCertificateManager.getInstance().getPrivateKey(request);
            String subjectName = CertificateManager.getInstance().getSubjectDN(certificate);
            if (subjectName != null && key != null) {
                CertificateManager.getInstance().registerCertificate(subjectName, certificate, key);
            }
        }
    }

    public Session registerPortalCertificateAndPlaceOnRequest(HttpServletRequest request)
        throws Exception {
        Session session = CertificateManager.getInstance().getSession(request);
        if (session == null) {
            PortalCertificateManager.getInstance().putPortalCertificateOnRequest(request);
            PortalCertificateManager.getInstance()
                .registerPortalCertificateWithCertificateManger(request);
            session = CertificateManager.getInstance().getSession(request);
        }
        return session;
    }

    /**
     * Gets the requests Session, either the X509 Certificate if there is one,
     * or by checking for Authorization headers.  If neither are available,
     * it attempts to.
     * @param request
     * @return
     */
    public Session getSession(HttpServletRequest request) {
        // initialize the session - three options
        Session session = null;

        // #1
        // load session from certificate in request
        try {
            session = CertificateManager.getInstance().getSession(request);
        } catch (Exception e) {
            log.warn("For request " + request + ":" + e.getMessage(), e);
        }

        // #2
        // check for token
        if (session == null) {
            String token = request.getHeader("Authorization");
            if (token != null) {
                try {
                    token = token.split(" ")[1];
                    session = TokenGenerator.getInstance().getSession(token);
                } catch (IndexOutOfBoundsException e) {
                    log.warn("For request " + request
                            + ": Could not extract a valid token from the request's "
                                 + "Authorization header ('" + token
                                 + "') in order to set the Session. Continuing...");
                } catch (Exception e) {
                    log.warn("For request " + request + ":" + e.getMessage(), e);
                }
            }
        }

        // #3 check for portal certificate
        if (session == null) {
            try {
                session = this.registerPortalCertificateAndPlaceOnRequest(request);
            } catch (Exception e) {
                log.warn("For request " + request + ":" + e.getMessage(), e);
            }
        }

        return session;
    }
}
