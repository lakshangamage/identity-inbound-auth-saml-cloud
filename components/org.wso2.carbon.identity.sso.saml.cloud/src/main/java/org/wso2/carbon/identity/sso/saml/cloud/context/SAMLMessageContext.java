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

package org.wso2.carbon.identity.sso.saml.cloud.context;

import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.request.SingleLogoutRequest;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.Serializable;
import java.util.Map;

public class SAMLMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {

    private static final long serialVersionUID = 104634801939285909L;
    /**
     * The unmarshelled SAML Request
     */
    private String destination;
    private String id;
    private String assertionConsumerUrl;
    private boolean isPassive;
    private boolean isLogoutRequest;
    private boolean isAuthnRequest;
    private String decodedRequest;

    /**
     * Should be set in validateAuthnRequest
     */
    private boolean isValid;
    private String issuer;
    /**
     * Subject should be validated before set.
     * Validation is done in the request validation.
     */
    private String subject;
    private String tenantDomain;
    private int attributeConsumingServiceIndex;
    private SAMLSSOServiceProviderDO samlssoServiceProviderDO;

    /*
     * Should be set in validate logout request.
     */
    private String sessionId;
    private String sessionIndexId;
    private boolean isDoSignResponse;
    private String signingAlgorithmUri;
    private String digestAlgorithmUri;
    private SingleLogoutRequest[] logoutRequests;
    private String logoutResponse;

    public SAMLMessageContext(SAMLIdentityRequest request, Map<T1, T2> parameters) {
        super(request, parameters);
    }

    @Override
    public SAMLIdentityRequest getRequest() {
        return (SAMLIdentityRequest) request;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getDestination() {
        if (!isIdpInitSSO()) {
            return this.destination;
        } else if (isIdpInitSSO()) {
            return ((SAMLIdpInitRequest) this.getRequest()).getAcs();
        }
        return null;
    }

    public boolean isIdpInitSSO() {
        return this.getRequest() instanceof  SAMLIdpInitRequest;
    }

    public String getRelayState() {
        return this.getRequest().getRelayState();
    }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean isValid) {
        this.isValid = isValid;
    }

    public String getIssuer() {
        if (issuer.contains("@")) {
            String[] splitIssuer = issuer.split("@");
            return splitIssuer[0];
        }
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuerWithDomain() {
        return this.issuer;
    }

    public int getAttributeConsumingServiceIndex() {
        return attributeConsumingServiceIndex;
    }

    public void setAttributeConsumingServiceIndex(int attributeConsumingServiceIndex) {
        this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
    }

    public String getRpSessionId() {
        return this.request.getParameter(MultitenantConstants.SSO_AUTH_SESSION_ID);
    }

    public void setId(String id){
        this.id = id;
    }
    public String getId() {
        if(!isIdpInitSSO()) {
            return this.id;
        }
        return null;
    }

    public void setAssertionConsumerUrl(String assertionConsumerUrl) {
        this.assertionConsumerUrl = assertionConsumerUrl;
    }

    public String getAssertionConsumerURL() {
        if(!isIdpInitSSO()) {
            return this.assertionConsumerUrl;
        } else {
            return samlssoServiceProviderDO.getDefaultAssertionConsumerUrl();
        }
    }

    public void setIsPassive(boolean isPassive) {
        this.isPassive = isPassive;
    }

    public boolean isPassive() {
        return this.isPassive;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public AuthenticatedUser getUser() {
        return this.getAuthenticationResult().getSubject();
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    /**
     *
     * @return AuthenticationResult saved in the messageContext
     * while authenticating in the framework.
     */
    public AuthenticationResult getAuthenticationResult() {
        if (this.getParameter(SAMLSSOConstants.AUTHENTICATION_RESULT) != null) {
            return (AuthenticationResult) this.getParameter(SAMLSSOConstants.AUTHENTICATION_RESULT);
        }
        return new AuthenticationResult();
    }

    public SAMLSSOServiceProviderDO getSamlssoServiceProviderDO() {
        return samlssoServiceProviderDO;
    }

    public void setSamlssoServiceProviderDO(SAMLSSOServiceProviderDO samlssoServiceProviderDO) {
        this.samlssoServiceProviderDO = samlssoServiceProviderDO;
    }

    public boolean isLogoutRequest() {
        return isLogoutRequest;
    }

    public void setLogoutRequest(boolean logoutRequest) {
        isLogoutRequest = logoutRequest;
    }

    public boolean isAuthnRequest() {
        return isAuthnRequest;
    }

    public void setAuthnRequest(boolean authnRequest) {
        isAuthnRequest = authnRequest;
    }

    public boolean isDoSignResponse() {
        return isDoSignResponse;
    }

    public void setDoSignResponse(boolean doSignResponse) {
        isDoSignResponse = doSignResponse;
    }

    public String getSigningAlgorithmUri() {
        return signingAlgorithmUri;
    }

    public void setSigningAlgorithmUri(String signingAlgorithmUri) {
        this.signingAlgorithmUri = signingAlgorithmUri;
    }

    public String getDigestAlgorithmUri() {
        return digestAlgorithmUri;
    }

    public void setDigestAlgorithmUri(String digestAlgorithmUri) {
        this.digestAlgorithmUri = digestAlgorithmUri;
    }

    public SingleLogoutRequest[] getLogoutRequests() {
        return logoutRequests;
    }

    public void setLogoutRequests(SingleLogoutRequest[] logoutRequests) {
        if (logoutRequests == null) {
            this.logoutRequests = new SingleLogoutRequest[0];
        } else {
            this.logoutRequests = logoutRequests.clone();
        }
    }

    public String getLogoutResponse() {
        return logoutResponse;
    }

    public void setLogoutResponse(String logoutResponse) {
        this.logoutResponse = logoutResponse;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getSessionIndexId() {
        return sessionIndexId;
    }

    public void setSessionIndexId(String sessionIndexId) {
        this.sessionIndexId = sessionIndexId;
    }

    public String getDecodedRequest() {
        return decodedRequest;
    }

    public void setDecodedRequest(String decodedRequest) {
        this.decodedRequest = decodedRequest;
    }
}