/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.sample.custom.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class CustomAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    public static final String AUTHENTICATOR_FRIENDLY_NAME = "terms-and-condition-enforcer";
    public static final String AUTHENTICATOR_NAME = "CustomAuthenticator";
    private static final Log log = LogFactory.getLog(CustomAuthenticator.class);
    private static final long serialVersionUID = 1819664539416029434L;
    private static final String AUTHENTICATOR_TYPE = "LOCAL";

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException {

        // If the logout request comes, then no need to go through and doing complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        if (StringUtils.isNotEmpty(request.getParameter("tcParam"))) {
            try {
                processAuthenticationResponse(request, response, context);
            } catch (Exception e) {
                context.setRetrying(true);
                context.setCurrentAuthenticator(getName());
                return initiateAuthRequest(response, context, e.getMessage());
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            return initiateAuthRequest(response, context, null);
        }
    }

    /**
     * This will prompt user to accept terms and conditions.
     *
     * @param response
     * @param context
     * @param errorMessage
     * @return
     * @throws AuthenticationFailedException
     */
    private AuthenticatorFlowStatus initiateAuthRequest(HttpServletResponse response, AuthenticationContext context,
                                                        String errorMessage)
            throws AuthenticationFailedException {

        // Find the authenticated user.
        AuthenticatedUser authenticatedUser = getUser(context);

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Authentication failed!. " +
                    "Cannot proceed further without identifying the user");
        }

        String tenantDomain = authenticatedUser.getTenantDomain();
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);

        /*
        In here we do the redirection to the termsAndConditionForm.jsp page.
        If you need to do any api calls and pass any information to the custom page you can do it here and pass
        them as query parameters or else best way is to do the api call using a javascript function within the
        custom page.
         */

        try {
            String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().
                    replace("login.do", "termsAndConditionForm.jsp");
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = "&authFailure=true" +
                        "&authFailureMsg=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8.name());
            }
            String fullyQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername,
                    tenantDomain);
            String encodedUrl =
                    (loginPage + ("?" + queryParams
                            + "&username=" + URLEncoder.encode(fullyQualifiedUsername, StandardCharsets.UTF_8.name())))
                            + "&authenticators=" + getName() + ":" + AUTHENTICATOR_TYPE
                            + retryParam;
            response.sendRedirect(encodedUrl);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        context.setCurrentAuthenticator(getName());
        context.setRetrying(false);
        return AuthenticatorFlowStatus.INCOMPLETE;

    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context) {

        /*
        In here we can process the request submitted from terms and condition page.
         */
        AuthenticatedUser authenticatedUser = getUser(context);

        String input = request.getParameter("tcInput");
        if ("on".equals(input)) {
            /*
            logic when user accept terms and condition
             */
            log.info("user accepted terms and condition");
            updateAuthenticatedUserInStepConfig(context, authenticatedUser);
        } else {
            /*
            logic when user rejects terms and condition
             */
            log.info("user rejected terms and condition");
            updateAuthenticatedUserInStepConfig(context, authenticatedUser);

        }
    }

    /**
     * Get the username from authentication context.
     *
     * @param context
     * @return
     */
    private AuthenticatedUser getUser(AuthenticationContext context) {
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        return stepConfig.getAuthenticatedUser();
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    private void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser) {
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (int i = 1; i <= stepConfigMap.size(); i++) {
            stepConfigMap.get(i).setAuthenticatedUser(authenticatedUser);
        }
        context.setSubject(authenticatedUser);
    }

}
