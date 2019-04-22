package com.amazonaws.services.config.samplerules;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.amazonaws.services.config.AmazonConfig;
import com.amazonaws.services.config.model.*;
import com.amazonaws.services.config.samplerules.exception.FunctionExecutionException;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.model.GetAccountSummaryResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ConfigEvent;

@RunWith(MockitoJUnitRunner.class)
public class RootAccountMFAEnabledTest {

    private static final String RESULT_TOKEN = "resultToken";
    private static final String ACCOUNT_ID = "accountId";
    private static final String ACCOUNT_MFA_ENABLED = "AccountMFAEnabled";
    private static final String ACCOUNT_TYPE = "AWS::::Account";
    /**
     * This test event contains a subset of the parameters for AWS Config events. For all parameters see:
     * http://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_example-events.html
     */
    private static final String INVOKING_EVENT_FORMAT = "{\"messageType\":\"%s\"}";
    private static final Date NOW = new Date();

    @Mock
    private Context context;
    @Mock
    private AmazonConfig configClient;
    @Mock
    private AmazonIdentityManagement iamClient;
    private ConfigEvent event;
    private GetAccountSummaryResult accountSummary;
    private RootAccountMFAEnabled mfaEnabledFunction;

    @Before
    public void setup() {
        event = new ConfigEvent();
        event.setInvokingEvent(String.format(INVOKING_EVENT_FORMAT, MessageType.ScheduledNotification));
        event.setAccountId(ACCOUNT_ID);
        event.setResultToken(RESULT_TOKEN);
        accountSummary = new GetAccountSummaryResult();
        mfaEnabledFunction = new RootAccountMFAEnabled();
        when(configClient.putEvaluations(any(PutEvaluationsRequest.class)))
                .thenReturn(new PutEvaluationsResult().withFailedEvaluations(Collections.emptyList()));
        when(iamClient.getAccountSummary()).thenReturn(accountSummary);
    }

    @Test
    public void testHandleCompliant() throws IOException {
        accountSummary.getSummaryMap().put(ACCOUNT_MFA_ENABLED, 1);
        mfaEnabledFunction.doHandle(event, context, configClient, iamClient, () -> NOW);
        verify(configClient).putEvaluations(buildPutEvaluationsRequest(ComplianceType.COMPLIANT));
    }

    @Test
    public void testHandleNonCompliant() throws IOException {
        accountSummary.getSummaryMap().put(ACCOUNT_MFA_ENABLED, 0);
        mfaEnabledFunction.doHandle(event, context, configClient, iamClient, () -> NOW);
        verify(configClient).putEvaluations(buildPutEvaluationsRequest(ComplianceType.NON_COMPLIANT));
    }

    @Test
    public void testHandleNonCompliantNullCount() throws IOException {
        accountSummary.getSummaryMap().put(ACCOUNT_MFA_ENABLED, null);
        mfaEnabledFunction.doHandle(event, context, configClient, iamClient, () -> NOW);
        verify(configClient).putEvaluations(buildPutEvaluationsRequest(ComplianceType.NON_COMPLIANT));
    }

    @Test
    public void testHandleNonCompliantPropertyMissing() throws IOException {
        mfaEnabledFunction.doHandle(event, context, configClient, iamClient, () -> NOW);
        verify(configClient).putEvaluations(buildPutEvaluationsRequest(ComplianceType.NON_COMPLIANT));
    }

    @Test(expected = FunctionExecutionException.class)
    public void testHandleWrongMessageType() throws IOException {
        accountSummary.getSummaryMap().put(ACCOUNT_MFA_ENABLED, 0);
        event.setInvokingEvent(String.format(INVOKING_EVENT_FORMAT, MessageType.ConfigurationItemChangeNotification));
        mfaEnabledFunction.doHandle(event, context, configClient, iamClient, () -> NOW);
    }

    @Test(expected = FunctionExecutionException.class)
    public void testHandleFailedEvaluations() throws IOException {
        accountSummary.getSummaryMap().put(ACCOUNT_MFA_ENABLED, 0);
        Evaluation failedEvaluation = new Evaluation();
        when(configClient.putEvaluations(any(PutEvaluationsRequest.class)))
                .thenReturn(new PutEvaluationsResult().withFailedEvaluations(failedEvaluation));
        mfaEnabledFunction.doHandle(event, context, configClient, iamClient, () -> NOW);
    }

    private PutEvaluationsRequest buildPutEvaluationsRequest(ComplianceType compliance) {
        Evaluation evaluation = new Evaluation()
                .withComplianceResourceId(ACCOUNT_ID)
                .withComplianceResourceType(ACCOUNT_TYPE)
                .withOrderingTimestamp(NOW)
                .withComplianceType(compliance);
        return new PutEvaluationsRequest()
                .withEvaluations(evaluation)
                .withResultToken(RESULT_TOKEN);
    }

}
