package org.wso2.carbon.identity.sso.saml.cloud.request;

import java.io.Serializable;

public class SingleLogoutRequest implements Serializable {

    private static final long serialVersionUID = -5086237688925774301L;

    private String assertionConsumerURL;
    private String logoutResponse;
    private String rpSessionId;

    public String getAssertionConsumerURL() {
        return assertionConsumerURL;
    }

    public void setAssertionConsumerURL(String assertionConsumerURL) {
        this.assertionConsumerURL = assertionConsumerURL;
    }

    public String getLogoutResponse() {
        return logoutResponse;
    }

    public void setLogoutResponse(String logoutResponse) {
        this.logoutResponse = logoutResponse;
    }

    public String getRpSessionId() {
        return rpSessionId;
    }

    public void setRpSessionId(String rpSessionId) {
        this.rpSessionId = rpSessionId;
    }
}
