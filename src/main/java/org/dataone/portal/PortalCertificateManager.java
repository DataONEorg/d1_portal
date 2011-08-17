package org.dataone.portal;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cilogon.portal.CILogonService;
import org.cilogon.portal.PortalEnvironment;
import org.cilogon.portal.config.cli.PortalConfigurationDepot;
import org.cilogon.portal.util.PortalCredentials;
import org.cilogon.rdf.CILogonConfiguration;

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
	
	private static PortalCertificateManager instance;
	
	public static PortalCertificateManager getInstance() {
		if (instance == null) {
			instance = new PortalCertificateManager();
		}
		return instance;
	}
	
	public void setCookie(String identifier, HttpServletResponse httpServletResponse) {
		// put our d1 cookie back so we can look up the credential as needed.
        Cookie cookie = new Cookie(D1_CERTIFICATE_COOKIE_ID, identifier);
    	cookie.setMaxAge(18 * 60 * 60); // 18 hours for certificate, so the cookie need not be longer
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
		Cookie[] cookies = request.getCookies();
        String identifier = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(PortalCertificateManager.D1_CERTIFICATE_COOKIE_ID)) {
                    identifier = cookie.getValue();
                    break;
                }
            }
            if (identifier != null) {
            	
				PortalConfigurationDepot configurationDepot = new PortalConfigurationDepot(configFile);
            	CILogonConfiguration ciLogonConfiguration = configurationDepot.getCurrentConfiguration();
            	
            	//PortalEnvironment portalEnvironment = PortalAbstractServlet.getPortalEnvironment();
            	PortalEnvironment portalEnvironment = new PortalEnvironment();
				portalEnvironment.setConfiguration(ciLogonConfiguration);
				
            	CILogonService cis = new CILogonService(portalEnvironment);
                PortalCredentials credential = cis.getCredential(identifier);
                return credential.getX509Certificate();
            }
            
        }
        // if there was no cookie or certificate
        return null;
	}
}
