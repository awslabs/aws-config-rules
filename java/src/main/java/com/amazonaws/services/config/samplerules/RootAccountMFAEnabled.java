package com.amazonaws.services.config.samplerules;

import java.io.IOException;
import java.util.Date;
import java.util.function.Supplier;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.config.AmazonConfig;
import com.amazonaws.services.config.AmazonConfigClient;
import com.amazonaws.services.config.model.*;
import com.amazonaws.services.config.samplerules.exception.FunctionExecutionException;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.GetAccountSummaryResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ConfigEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This Lambda function reports to AWS Config whether an AWS account is enabled for Multi-Factor Authentication. The
 * function is invoked when AWS Config publishes an event for periodic Config rules.
 */
public class RootAccountMFAEnabled {

    private static final String AWS_ACCOUNT_RESOURCE_TYPE = "AWS::::Account";
    private static final String AWS_REGION_PROPERTY = "AWS_DEFAULT_REGION";
    private static final String MESSAGE_TYPE_PROPERTY = "messageType";
    private static final String MFA_ENABLED_PROPERTY = "AccountMFAEnabled";

    /**
     * This handler function is executed when AWS Lambda passes the event and context objects.
     * 
     * @param event
     *            Event object published by AWS Config to invoke the function.
     * @param context
     *            Context object provided by AWS Lambda.
     * @throws IOException
     */
    public void handle(ConfigEvent event, Context context) throws IOException {
        Regions region = Regions.fromName(System.getenv(AWS_REGION_PROPERTY));
        AmazonConfig configClient = new AmazonConfigClient()
                .withRegion(region);
        AmazonIdentityManagement iamClient = new AmazonIdentityManagementClient()
                .withRegion(region);
        doHandle(event, context, configClient, iamClient, Date::new);
    }

    /**
     * Handler interface used by the main handler function and test events.
     */
    public void doHandle(ConfigEvent event, Context context, AmazonConfig configClient,
            AmazonIdentityManagement iamClient, Supplier<Date> dateSupplier) throws IOException {
        JsonNode invokingEvent = new ObjectMapper().readTree(event.getInvokingEvent());
        failForIncompatibleEventTypes(invokingEvent);
        // Associates the evaluation result with the AWS account published in the event.
        Evaluation evaluation = new Evaluation()
                .withComplianceResourceId(event.getAccountId())
                .withComplianceResourceType(AWS_ACCOUNT_RESOURCE_TYPE)
                .withOrderingTimestamp(dateSupplier.get())
                .withComplianceType(getCompliance(iamClient));
        doPutEvaluations(configClient, event, evaluation);
    }

    // Ends the function execution if the event is not meant for periodic evaluations.
    private void failForIncompatibleEventTypes(JsonNode invokingEvent) {
        String messageType = invokingEvent.get(MESSAGE_TYPE_PROPERTY).asText();
        if (!MessageType.ScheduledNotification.toString().equals(messageType)) {
            throw new FunctionExecutionException(String.format(
                    "Events with the message type '%s' are not evaluated for this Config rule.", messageType));
        }
    }

    // Evaluates whether the AWS Account published in the event has an MFA device assigned.
    private ComplianceType getCompliance(AmazonIdentityManagement iamClient) {
        GetAccountSummaryResult result = iamClient.getAccountSummary();
        Integer mfaEnabledCount = result.getSummaryMap().get(MFA_ENABLED_PROPERTY);
        if (mfaEnabledCount != null && mfaEnabledCount > 0) {
            return ComplianceType.COMPLIANT; // The account has an MFA device assigned.
        } else {
            return ComplianceType.NON_COMPLIANT; // The account does not have an MFA device assigned.
        }
    }

    // Sends the evaluation results to AWS Config.
    private void doPutEvaluations(AmazonConfig configClient, ConfigEvent event, Evaluation evaluation) {
        PutEvaluationsResult result = configClient.putEvaluations(new PutEvaluationsRequest()
                .withEvaluations(evaluation)
                .withResultToken(event.getResultToken()));
        // Ends the function execution if any evaluation results are not successfully reported.
        if (result.getFailedEvaluations().size() > 0) {
            throw new FunctionExecutionException(String.format(
                    "The following evaluations were not successfully reported to AWS Config: %s",
                    result.getFailedEvaluations()));
        }
    }

}
