package org.wso2.carbon.identity.sso.saml.cloud.validators;

import org.opensaml.saml2.core.LogoutRequest;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.IOException;

/**
 * Created by lakshan on 12/15/16.
 */
public interface SLOAuthnRequestValidator {
    boolean validate(LogoutRequest request) throws IdentityException, IOException;
}
