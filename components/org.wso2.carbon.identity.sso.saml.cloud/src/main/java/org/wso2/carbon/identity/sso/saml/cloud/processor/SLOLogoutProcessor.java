package org.wso2.carbon.identity.sso.saml.cloud.processor;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;

public class SLOLogoutProcessor extends IdentityProcessor {
    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {
        SAMLMessageContext messageContext = (SAMLMessageContext) getContextIfAvailable(identityRequest);
        //TODO implement relevant handler
        return null;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext identityMessageContext) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        //TODO modify this to avoid contradictions
        if (context != null) {
            if (context.getRequest() instanceof SAMLSpInitRequest || context.getRequest() instanceof
                    SAMLIdpInitRequest) {
                if (((SAMLMessageContext)context).isLogoutRequest()) {
                    return true;
                }
            }
        }
        return false;
    }
}
