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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cilogon.portal.CILogonService;
import org.cilogon.portal.PortalEnvironment;
import org.cilogon.portal.config.cli.PortalConfigurationDepot;
import org.cilogon.portal.util.PortalCredentials;
import org.cilogon.rdf.CILogonConfiguration;
import org.cilogon.util.exceptions.CILogonException;

public class PortalCertificateManager {

	// initialize the portal store
//	private PortalCertificateManager() {
//		PortalAbstractServlet pas = new PortalAbstractServlet() {
//			@Override
//			protected void doIt(HttpServletRequest arg0,
//					HttpServletResponse arg1) throws Throwable {
//				// do nothing here, it's not a servlet here
//			}
//		};
//		try {
//			pas.init();
//		} catch (ServletException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
//	}
	
	public static String D1_CERTIFICATE_COOKIE_ID = "d1_certificate_cookie";
	
	private static String configFile = "/var/lib/tomcat6/webapps/portal/WEB-INF/cfg.rdf";
	
	private static int maxAttempts = 10;
	
	private static PortalCertificateManager instance;
	
	public static Log log = LogFactory.getLog(PortalCertificateManager.class);
	
	public static PortalCertificateManager getInstance() {
		if (instance == null) {
			instance = new PortalCertificateManager();
		}
		return instance;
	}
	
	/**
	 * Sets the certificate Cookie on the response.
	 * Future interactions with this service will be tied to the certificate
	 * by this cookie
	 * @param identifier
	 * @param httpServletResponse
	 */
	public void setCookie(String identifier, HttpServletResponse httpServletResponse) {
		// put our d1 cookie back so we can look up the credential as needed.
        Cookie cookie = new Cookie(D1_CERTIFICATE_COOKIE_ID, identifier);
    	cookie.setMaxAge(18 * 60 * 60); // 18 hours for certificate, so the cookie need not be longer
    	cookie.setPath("/"); // need to cross contexts
    	httpServletResponse.addCookie(cookie);
	}
	
	/**
	 * Retrieves the certificate Cookie from the request
	 * @param httpServletRequest
	 * @return
	 */
	public Cookie getCookie(HttpServletRequest httpServletRequest) {
    	if (httpServletRequest.getCookies() != null) {
    		for (Cookie cookie: httpServletRequest.getCookies()) {
    			if (cookie.getName().equals(D1_CERTIFICATE_COOKIE_ID)) {
    				return cookie;
    			}
    		}
    	}
    	return null;
	}
	
	/**
	 * Removes the certificate cookie, essentially logging out the user
	 * @param httpServletResponse
	 */
	public void removeCookie(HttpServletResponse httpServletResponse) {
		// put our d1 cookie back but expires immediately to remove it
        Cookie cookie = new Cookie(D1_CERTIFICATE_COOKIE_ID, "removeMe");
    	cookie.setMaxAge(0); // clear now
    	cookie.setPath("/"); // need to cross contexts
    	httpServletResponse.addCookie(cookie);
	}
	
	/**
	 * Get the certificate from the store, based on the cookie (if present)
	 * @param request
	 * @return 
	 * @throws IOException
	 */
	public X509Certificate getCertificate(HttpServletRequest request) throws IOException {
        PortalCredentials credential = getCredentials(request);
        if (credential == null) {
        	return null;
        }
		return credential.getX509Certificate();  
	}
	
	/**
	 * Get the private key from the store, based on the cookie (if present)
	 * @param request
	 * @return 
	 * @throws IOException
	 */
	public PrivateKey getPrivateKey(HttpServletRequest request) throws IOException {
        PortalCredentials credential = getCredentials(request);
        if (credential == null) {
        	return null;
        }
		return credential.getPrivateKey();  
	}
	
	/**
	 * Get the credentials from the store, based on the token/identifier
	 * @param identifier for the certificate/credential
	 * @return 
	 * @throws IOException
	 */
	public PortalCredentials getCredentials(String identifier) throws IOException {
        if (identifier != null) {
			PortalConfigurationDepot configurationDepot = new PortalConfigurationDepot(configFile);
        	CILogonConfiguration ciLogonConfiguration = configurationDepot.getCurrentConfiguration();
        	
        	//PortalEnvironment portalEnvironment = PortalAbstractServlet.getPortalEnvironment();
        	PortalEnvironment portalEnvironment = new PortalEnvironment();
			portalEnvironment.setConfiguration(ciLogonConfiguration);
			
        	CILogonService cis = new CILogonService(portalEnvironment);
            PortalCredentials credential = null;
            int attempts = 0;
        	while (credential == null) {
    	        try {
    	        	credential = cis.getCredential(identifier);
    	        } catch (CILogonException e) {
    				// sleep and try again, for a while until failing
    	        	log.warn(attempts + " - Error getting transaction, trying again. " + e.getMessage());
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
            
            return credential;
        }
        // if there was no cookie or certificate
        return null;
	}
	
	/**
	 * Get the credentials from the store, based on the cookie (if present)
	 * @param request
	 * @return 
	 * @throws IOException
	 */
	public PortalCredentials getCredentials(HttpServletRequest request) throws IOException {
		Cookie[] cookies = request.getCookies();
        String identifier = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(PortalCertificateManager.D1_CERTIFICATE_COOKIE_ID)) {
                    identifier = cookie.getValue();
                    return getCredentials(identifier);
                }
            }
        }
        return null;
	}
}
