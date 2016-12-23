package org.wso2.carbon.identity.sso.saml.cloud.processor;

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLogoutResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;

public abstract class LogoutRequestProcessor extends IdentityProcessor {

    @Override
    public String getName() {
        return SAMLSSOConstants.SAMLFormFields.SAML_SSO;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    protected FrameworkLogoutResponse.FrameworkLogoutResponseBuilder buildResponseForFrameworkLogout(IdentityMessageContext context) {
        IdentityRequest identityRequest = context.getRequest();
        Map parameterMap = identityRequest.getParameterMap();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        for (Object entry : identityRequest.getHeaderMap().keySet()) {
            authenticationRequest.addHeader((String) entry, identityRequest.getHeaderMap().get(entry));
        }
        authenticationRequest.setRelyingParty(((SAMLMessageContext) context).getIssuer());
        authenticationRequest.setType(getName());

        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(getCallbackPath(context),
                    StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw FrameworkRuntimeException.error("Error occurred while URL encoding callback path " +
                    getCallbackPath(context), e);
        }

        authenticationRequest.addRequestQueryParam("commonAuthLogout", new String[]{"true"});
        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        String sessionDataKey = UUIDGenerator.generateUUID();
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);
        InboundUtil.addContextToCache(sessionDataKey, context);
        FrameworkLogoutResponse.FrameworkLogoutResponseBuilder responseBuilder = new FrameworkLogoutResponse.FrameworkLogoutResponseBuilder(context);
        responseBuilder.setAuthName(getName());
        responseBuilder.setContextKey(sessionDataKey);
        responseBuilder.setCallbackPath(getCallbackPath(context));
        responseBuilder.setRelyingParty(getRelyingPartyId());
        responseBuilder.setAuthType(getName());
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }
}
