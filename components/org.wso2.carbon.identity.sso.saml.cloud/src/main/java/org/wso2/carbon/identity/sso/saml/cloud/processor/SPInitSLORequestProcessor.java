package org.wso2.carbon.identity.sso.saml.cloud.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.handler.HandlerManager;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;

import java.util.HashMap;

public class SPInitSLORequestProcessor extends LogoutRequestProcessor{

    private static final Log log = LogFactory.getLog(SPInitSLORequestProcessor.class);
    private SAMLMessageContext messageContext;
    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof SAMLSpInitRequest && ((SAMLSpInitRequest) identityRequest).getSamlRequest
                () != null) {
            if (messageContext != null) {
                messageContext = (SAMLMessageContext) getContextIfAvailable(identityRequest);
                SAMLSpInitRequest samlIdentityRequest = (SAMLSpInitRequest) identityRequest;
                String decodedRequest;
                try {
                    if (samlIdentityRequest.isRedirect()) {
                        decodedRequest = SAMLSSOUtil.decode(samlIdentityRequest.getSamlRequest());
                    } else {
                        decodedRequest = SAMLSSOUtil.decodeForPost(samlIdentityRequest.getSamlRequest());
                    }
                    messageContext.setDecodedRequest(decodedRequest);
                    XMLObject request = SAMLSSOUtil.unmarshall(decodedRequest);

                    if (request instanceof LogoutRequest) {
                        messageContext.setAuthnRequest(false);
                        messageContext.setLogoutRequest(true);
                        return true;
                    }
                } catch (IdentityException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Could not unmarshall Request");
                    }
                }
            }
        }
        return false;
    }

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {
        if (messageContext == null) {
            messageContext = new SAMLMessageContext((SAMLSpInitRequest) identityRequest, new
                    HashMap<String, String>());
        }
        HandlerManager.getInstance().validateRequest(messageContext);
        return buildResponseForFrameworkLogout(messageContext);
    }
}

