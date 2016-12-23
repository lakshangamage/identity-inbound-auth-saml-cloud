package org.wso2.carbon.identity.sso.saml.cloud.validators;

import org.opensaml.saml2.core.LogoutRequest;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.IOException;

public interface SLOLogoutRequestValidator {
    boolean validate(LogoutRequest request) throws IdentityException, IOException;
}
