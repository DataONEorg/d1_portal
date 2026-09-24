package org.dataone.portal;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.auth.CertificateManager;
import org.dataone.service.types.v1.Session;

/**
 * Determines the authenticated DataONE Session for an incoming request, from either an X.509
 * client certificate presented in the TLS handshake or a DataONE JWT in the Authorization header.
 * <p>
 * Before version 3.0.0 this class also looked up certificates that the CILogon/MyProxy portal
 * login stored server-side and linked to the browser with a cookie. That login flow has been
 * removed, along with the oa4mp dependency.
 */
public class PortalCertificateManager {

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

    /**
     * Gets the request's Session, either from the X509 client certificate if there is one,
     * or from a DataONE JWT in the Authorization header.
     * @param request the incoming request
     * @return the Session, or null if the request carries no valid credentials
     */
    public Session getSession(HttpServletRequest request) {
        // initialize the session - two options
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

        return session;
    }
}
