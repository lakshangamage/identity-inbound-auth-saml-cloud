package org.wso2.carbon.identity.sso.saml.cloud.handler.logout;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLResponse;

import java.io.IOException;

public abstract class LogoutHandler extends AbstractIdentityHandler {
    public abstract boolean canHandle(SAMLMessageContext messageContext);

    /**
     * Process the logout response from the framework
     */
    public abstract SAMLResponse.SAMLResponseBuilder validateLogoutResponseFromFramework(SAMLMessageContext
                                                                                                messageContext,
                                                                                        IdentityRequest
                                                                                                identityRequest)
            throws IdentityException, IOException;
}

