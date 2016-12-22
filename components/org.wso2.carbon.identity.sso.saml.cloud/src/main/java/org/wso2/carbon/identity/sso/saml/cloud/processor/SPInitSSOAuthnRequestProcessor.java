/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.saml.cloud.processor;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.handler.HandlerManager;
import org.wso2.carbon.identity.sso.saml.cloud.handler.validator.SPInitSAMLValidator;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.HashMap;

public class SPInitSSOAuthnRequestProcessor extends AuthnRequestProcessor {

    private static final Log log = LogFactory.getLog(SPInitSAMLValidator.class);
    private String relyingParty;

    @Override
    public int getPriority() {
        return 2;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof SAMLSpInitRequest && ((SAMLSpInitRequest) identityRequest).getSamlRequest
                () != null) {
            SAMLMessageContext messageContext = new SAMLMessageContext((SAMLSpInitRequest) identityRequest, new
                    HashMap<String, String>());
            SAMLSpInitRequest samlIdentityRequest = (SAMLSpInitRequest)messageContext.getRequest();
            String decodedRequest;
            try {
                if (samlIdentityRequest.isRedirect()) {
                    decodedRequest = SAMLSSOUtil.decode(samlIdentityRequest.getSamlRequest());
                } else {
                    decodedRequest = SAMLSSOUtil.decodeForPost(samlIdentityRequest.getSamlRequest());
                }
                messageContext.setDecodedRequest(decodedRequest);
                XMLObject request = SAMLSSOUtil.unmarshall(decodedRequest);

                if (request instanceof AuthnRequest) {
                    messageContext.setAuthnRequest(true);
                    return true;
                } else if (request instanceof LogoutRequest) {
                    messageContext.setLogoutRequest(true);
                    return false;
                }
            } catch (IdentityException e) {
                log.error("Error occurred while unmarshalling SAML Request");
            }
        }
        return false;
    }

    @Override
    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {
        SAMLMessageContext messageContext = new SAMLMessageContext((SAMLSpInitRequest) identityRequest, new
                HashMap<String, String>());
        HandlerManager.getInstance().validateRequest(messageContext);
        return buildResponseForFrameworkLogin(messageContext);
    }
}
