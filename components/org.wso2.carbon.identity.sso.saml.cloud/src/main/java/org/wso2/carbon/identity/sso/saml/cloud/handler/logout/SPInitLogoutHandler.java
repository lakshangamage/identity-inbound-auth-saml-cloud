package org.wso2.carbon.identity.sso.saml.cloud.handler.logout;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.LogoutRequestSender;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.request.SingleLogoutRequest;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLLoginResponse;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLLogoutResponse;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLResponse;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;

import java.io.IOException;

public class SPInitLogoutHandler extends LogoutHandler {
    private static Log log = LogFactory.getLog(SPInitLogoutHandler.class);

    @Override
    public boolean canHandle(SAMLMessageContext messageContext) {
        if (messageContext.getRequest() instanceof SAMLSpInitRequest) {
            if (messageContext.isLogoutRequest()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SAMLResponse.SAMLResponseBuilder validateLogoutResponseFromFramework(
            SAMLMessageContext messageContext, IdentityRequest identityRequest)
            throws IdentityException, IOException {
        SAMLResponse.SAMLResponseBuilder builder;
        SingleLogoutRequest[] logoutRequests = messageContext.getLogoutRequests();
        if (logoutRequests != null) {
            LogoutRequestSender.getInstance().sendLogoutRequests(logoutRequests);
        }
        SAMLSSOUtil.removeSession(messageContext.getSessionId(), messageContext.getIssuer());
        removeSessionDataFromCache(messageContext.getRequest().getParameter(SAMLSSOConstants.SESSION_DATA_KEY));
        builder = new SAMLLogoutResponse.SAMLLogoutResponseBuilder(messageContext);
        ((SAMLLogoutResponse.SAMLLogoutResponseBuilder)(builder)).setAcsUrl(messageContext.getAssertionConsumerURL());
        ((SAMLLogoutResponse.SAMLLogoutResponseBuilder)(builder)).setRelayState(messageContext.getRelayState());
        ((SAMLLogoutResponse.SAMLLogoutResponseBuilder)(builder)).setTenantDomain(messageContext.getTenantDomain());
        String respString = ((SAMLLogoutResponse.SAMLLogoutResponseBuilder) builder).buildResponse();
        if (log.isDebugEnabled()) {
            log.debug("Logout successfully processed. The SAMLResponse is :" + respString);
        }
        return builder;
    }

    private void removeSessionDataFromCache(String sessionDataKey) {
        if (sessionDataKey != null) {
            FrameworkUtils.removeSessionContextFromCache(sessionDataKey);
        }
    }
}
