package org.wso2.carbon.identity.sso.saml.cloud.response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;

import javax.servlet.http.Cookie;
import java.util.Map;

public class SAMLLogoutResponse extends SAMLResponse{

    private String respString;
    private String relayState;
    private String acsUrl;
    private String subject;
    private String tenantDomain;

    protected SAMLLogoutResponse(IdentityResponseBuilder builder) {
        super(builder);
        this.respString = ((SAMLLogoutResponse.SAMLLogoutResponseBuilder) builder).respString;
        this.relayState = ((SAMLLogoutResponse.SAMLLogoutResponseBuilder) builder).relayState;
        this.acsUrl = ((SAMLLogoutResponse.SAMLLogoutResponseBuilder) builder).acsUrl;
        this.tenantDomain = ((SAMLLogoutResponse.SAMLLogoutResponseBuilder) builder).tenantDomain;
        this.subject = ((SAMLLogoutResponse.SAMLLogoutResponseBuilder) builder).subject;
    }

    public String getRespString() {
        return respString;
    }

    public String getRelayState() {
        return relayState;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getSubject() {
        return subject;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public static class SAMLLogoutResponseBuilder extends SAMLResponseBuilder {

        private static Log log = LogFactory.getLog(SAMLLoginResponse.SAMLLoginResponseBuilder.class);

        private String respString;
        private String relayState;
        private String acsUrl;
        private String subject;
        private String tenantDomain;

        public SAMLLogoutResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SAMLLogoutResponse build(){
            return new SAMLLogoutResponse(this);
        }

        public void setRespString(String respString) {
            this.respString = respString;
        }

        public void setRelayState(String relayState) {
            this.relayState = relayState;
        }

        public void setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public void setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
        }

        public String buildResponse() throws IdentityException {
            SAMLMessageContext messageContext = (SAMLMessageContext)this.context;
            if (log.isDebugEnabled()) {
                log.debug("Building SAML Response for the consumer '" + messageContext.getAssertionConsumerURL() + "'");
            }
            Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
            response.setIssuer(SAMLSSOUtil.getIssuer());
            response.setID(SAMLSSOUtil.createID());
            if (!messageContext.isIdpInitSSO()) {
                response.setInResponseTo(messageContext.getId());
            }
            response.setDestination(messageContext.getAssertionConsumerURL());
            response.setStatus(buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
            response.setVersion(SAMLVersion.VERSION_20);
            DateTime issueInstant = new DateTime();
            response.setIssueInstant(issueInstant);
            this.setResponse(response);
            this.setRespString(messageContext.getLogoutResponse());
            return respString;
        }

        private Status buildStatus(String status, String statMsg) {

            Status stat = new StatusBuilder().buildObject();

            // Set the status code
            StatusCode statCode = new StatusCodeBuilder().buildObject();
            statCode.setValue(status);
            stat.setStatusCode(statCode);

            // Set the status Message
            if (statMsg != null) {
                StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
                statMesssage.setMessage(statMsg);
                stat.setStatusMessage(statMesssage);
            }

            return stat;
        }
    }
}
