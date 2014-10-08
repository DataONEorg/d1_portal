/**
 * This work was created by participants in the DataONE project, and is
 * jointly copyrighted by participating institutions in DataONE. For 
 * more information on DataONE, see our web site at http://dataone.org.
 *
 *   Copyright ${year}
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 * 
 * $Id$
 */

package org.dataone.portal;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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
    
    private static final String DEFAULT_OA4MP_CONFIG_PATH = "/var/lib/tomcat7/webapps/portal/WEB-INF/client/xml";

    private String configFile = Settings.getConfiguration().getString("oa4mp.client.config.file", DEFAULT_OA4MP_CONFIG_PATH);

    private String configName = null;

    private static int maxAttempts = 10;

    private static PortalCertificateManager instance;

    public static Log log = LogFactory.getLog(PortalCertificateManager.class);

    public static PortalCertificateManager getInstance() {
        if (instance == null) {
            instance = new PortalCertificateManager();
        }
        return instance;
    }
    
    public PortalCertificateManager() {}

    public PortalCertificateManager(String configFile) {
    	this.configFile = configFile;
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
        // put our d1 cookie back so we can look up the credential as needed.
        Cookie cookie = new Cookie(ClientServlet.OA4MP_CLIENT_REQUEST_ID, identifier);
        cookie.setMaxAge(18 * 60 * 60); // 18 hours for certificate, so the
                                        // cookie need not be longer
        cookie.setPath("/"); // need to cross contexts
        httpServletResponse.addCookie(cookie);
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
        if (credential == null || credential.getCertificates() == null || credential.getCertificates().length < 1) {
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
                    log.warn(attempts + " - Error getting transaction, trying again. "
                            + e.getMessage());
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
        String identifier = null;
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
            X509Certificate certificate = PortalCertificateManager.getInstance().getCertificate(request);
            log.debug("Proxy certificate for the request = " + certificate);
            if (certificate != null) {
                X509Certificate[] x509Certificates = new X509Certificate[] { certificate };
                request.setAttribute("javax.servlet.request.X509Certificate", x509Certificates);
                log.debug("Added proxy certificate to the request");
            }
            session = CertificateManager.getInstance().getSession(request);
        }
        return session;
    }

    public void registerPortalCertificateWithCertificateManger(HttpServletRequest request)
            throws Exception {
        X509Certificate certificate = PortalCertificateManager.getInstance().getCertificate(request);
        if (certificate != null) {
            PrivateKey key = PortalCertificateManager.getInstance().getPrivateKey(request);
            String subjectName = CertificateManager.getInstance().getSubjectDN(certificate);
            if (subjectName != null && key != null && certificate != null) {
                CertificateManager.getInstance().registerCertificate(subjectName, certificate, key);
            }
        }
    }

    public Session registerPortalCertificateAndPlaceOnRequest(HttpServletRequest request)
            throws Exception {
        Session session = CertificateManager.getInstance().getSession(request);
        if (session == null) {
            PortalCertificateManager.getInstance().putPortalCertificateOnRequest(request);
            PortalCertificateManager.getInstance().registerPortalCertificateWithCertificateManger(request);
            session = CertificateManager.getInstance().getSession(request);
        }
        return session;
    }
}
