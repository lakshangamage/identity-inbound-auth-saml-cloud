package org.wso2.carbon.identity.sso.saml.cloud.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.builders.SingleLogoutMessageBuilder;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.exception.SAML2ClientException;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Created by lakshan on 12/15/16.
 */
public class SPInitLogoutRequestValidator implements SLOAuthnRequestValidator{

    private static Log log = LogFactory.getLog(SPInitLogoutRequestValidator.class);
    private SAMLMessageContext messageContext;

    public SPInitLogoutRequestValidator(SAMLMessageContext messageContext) {
        this.messageContext = messageContext;
    }

    @Override
    public boolean validate(LogoutRequest request) throws IdentityException, IOException {

        try {
            messageContext.setLogoutRequest(true);
            String issuer = null;
            String defaultSigningAlgoUri = messageContext.getSamlssoServiceProviderDO().getSigningAlgorithmUri();
            String defaultDigestAlgoUri = messageContext.getSamlssoServiceProviderDO().getDigestAlgorithmUri();
            String sessionId = null;
            Cookie ssoTokenIdCookie = getTokenIdCookie(messageContext);

            if (ssoTokenIdCookie != null) {
                sessionId = ssoTokenIdCookie.getValue();
            }
            if (StringUtils.isBlank(sessionId)) {
                String message = "Session was already Expired";
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(buildErrorResponse(request.getID(), SAMLSSOConstants.StatusCodes
                        .REQUESTOR_ERROR, message, request.getDestination(), defaultSigningAlgoUri, defaultDigestAlgoUri));
            }

            if (request != null) {
                if (request.getIssuer() == null) {
                    String message = "Issuer should be mentioned in the Logout Request";
                    if (log.isDebugEnabled()) {
                        log.debug(message);
                    }
                    messageContext.setValid(false);
                    throw SAML2ClientException.error(buildErrorResponse(request.getID(), SAMLSSOConstants.StatusCodes
                            .REQUESTOR_ERROR, message, request.getDestination(), defaultSigningAlgoUri, defaultDigestAlgoUri));
                }

                if (request.getNameID() == null) {
                    String message = "Subject Name should be specified in the Logout Request";
                    if (log.isDebugEnabled()) {
                        log.debug(message);
                    }
                    throw SAML2ClientException.error(buildErrorResponse(request.getID(), SAMLSSOConstants.StatusCodes
                            .REQUESTOR_ERROR, message, request.getDestination(), defaultSigningAlgoUri, defaultDigestAlgoUri));
                }

                if (request.getSessionIndexes() == null) {
                    String message = "At least one Session Index should be present in the Logout Request";
                    log.error(message);
                    throw SAML2ClientException.error(buildErrorResponse(request.getID(), SAMLSSOConstants.StatusCodes
                            .REQUESTOR_ERROR, message, request.getDestination(), defaultSigningAlgoUri, defaultDigestAlgoUri));
                }

                issuer = request.getIssuer().getValue();

                if (IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                    if (issuer.contains("@")) {
                        String tenantDomain = issuer.substring(issuer.lastIndexOf('@') + 1);
                        issuer = issuer.substring(0, issuer.lastIndexOf('@'));
                        if (StringUtils.isNotBlank(tenantDomain) && StringUtils.isNotBlank(issuer)) {
                            SAMLSSOUtil.setTenantDomainInThreadLocal(tenantDomain);
                            if (log.isDebugEnabled()) {
                                log.debug("Tenant Domain: " + tenantDomain + " & Issuer name: " + issuer + "has been " +
                                        "split");
                            }
                        }
                    }
                    if (IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                        SAMLSSOServiceProviderDO serviceProvider = messageContext.getSamlssoServiceProviderDO();
                        if (serviceProvider != null) {
                            SAMLSSOUtil.setTenantDomainInThreadLocal(serviceProvider.getTenantDomain());
                        } else {
                            String message = "Service provider :" + issuer + " does not exist in session " +
                                    "info data.";
                            if (log.isDebugEnabled()) {
                                log.debug(message);
                            }
                            messageContext.setValid(false);
                            String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                                    message, null);
                            throw SAML2ClientException.error(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null);
                        }
                    }
                }
            }
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while handling SAML2 SSO request", e);
            }
            messageContext.setValid(false);
            String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                    "Error occurred while handling SAML2 SSO request", null);
            throw SAML2ClientException.error(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null);
        }
        return false;
    }

    /**
     * Builds the SAML error response and sets the compressed value to the reqValidationResponseDTO
     *
     * @param id
     * @param status
     * @param statMsg
     * @param destination
     * @return
     * @throws IdentityException
     */
    private String buildErrorResponse(String id, String status, String statMsg, String
            destination, String responseSigningAlgorithmUri, String responseDigestAlgorithmUri)
            throws IdentityException {
        String response;
        LogoutResponse logoutResp = new SingleLogoutMessageBuilder().buildLogoutResponse(id, status, statMsg,
                destination, false, null, responseSigningAlgorithmUri, responseDigestAlgorithmUri);
        try {
            response = SAMLSSOUtil.compressResponse(SAMLSSOUtil.marshall(logoutResp));
        } catch (IOException e) {
            throw IdentityException.error("Error while creating logout response", e);
        }
        return response;
    }

    private Cookie getTokenIdCookie(SAMLMessageContext messageContext) {
        Cookie[] cookies = messageContext.getRequest().getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (StringUtils.equals(cookie.getName(), SAMLSSOConstants.SSO_TOKEN_ID)) {
                    return cookie;
                }
            }
        }
        return null;
    }
}
