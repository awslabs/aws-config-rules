package com.amazonaws.services.config.samplerules;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.config.AmazonConfig;
import com.amazonaws.services.config.AmazonConfigClient;
import com.amazonaws.services.config.model.*;
import com.amazonaws.services.config.samplerules.exception.FunctionExecutionException;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ConfigEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;

public class DbInstanceBackupParameters {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String AWS_REGION_PROPERTY = "AWS_DEFAULT_REGION";
    private static final String MESSAGE_TYPE_PROPERTY = "messageType";
    private static final String CAPTURE_TIME_PATH = "configurationItemCaptureTime";
    private static final String STATUS_PATH = "configurationItemStatus";
    private static final String RESOURCE_DELETED = "ResourceDeleted";
    private static final String RESOURCE_DELETED_NOT_RECORDED = "ResourceDeletedNotRecorded";
    private static final String RESOURCE_NOT_RECORDED = "ResourceNotRecorded";
    private static final String CONFIGURATION = "configuration";
    private static final String RETENTION_PERIOD = "backupRetentionPeriod";
    private static final String BACKUP_WINDOW = "preferredBackupWindow";
    private static final String CONFIGURATION_ITEM = "configurationItem";
    private static final String RESOURCE_ID = "resourceId";
    private static final String RESOURCE_TYPE = "resourceType";

    @VisibleForTesting
    protected static final String INCOMPATIBLE_EVENT_TYPES_MESSAGE = "Events with the message type '%s' are not evaluated for this Config rule.";
    @VisibleForTesting
    protected static final String INVALID_BACKUP_RETENTION_PERIOD = "BackupRetentionPeriod rule parameter value '%s' is not an integer";

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
        doHandle(event, context, configClient);
    }

    /**
     * Handler interface used by the main handler function and test events.
     */
    @VisibleForTesting
    void doHandle(ConfigEvent event, Context context, AmazonConfig configClient) throws IOException {
        JsonNode invokingEvent = OBJECT_MAPPER.readTree(event.getInvokingEvent());
        failForIncompatibleEventTypes(invokingEvent);

        // Associates the evaluation result with the AWS account published in the event.
        Evaluation evaluation = new Evaluation()
                .withComplianceResourceId(getResourceId(invokingEvent))
                .withComplianceResourceType(getResourceType(invokingEvent))
                .withOrderingTimestamp(getCiCapturedTime(invokingEvent))
                .withComplianceType(evaluateCompliance(event));
        doPutEvaluations(configClient, event, evaluation);
    }

    private void failForIncompatibleEventTypes(JsonNode invokingEvent) {
        String messageType = invokingEvent.path(MESSAGE_TYPE_PROPERTY).textValue();
        if (!isCompatibleMessageType(messageType)) {
            throw new FunctionExecutionException(String.format(INCOMPATIBLE_EVENT_TYPES_MESSAGE, messageType));
        }
    }

    private boolean isCompatibleMessageType(String messageType) {
        return MessageType.ConfigurationItemChangeNotification.toString().equals(messageType);
    }

    private String getResourceId(JsonNode invokingEvent) {
        return invokingEvent.path(CONFIGURATION_ITEM).path(RESOURCE_ID).textValue();
    }

    private String getResourceType(JsonNode invokingEvent) {
        return invokingEvent.path(CONFIGURATION_ITEM).path(RESOURCE_TYPE).textValue();
    }

    private Date getCiCapturedTime(JsonNode invokingEvent) {
        return getDate(invokingEvent.path(CONFIGURATION_ITEM).path(CAPTURE_TIME_PATH).textValue());
    }

    private Date getDate(String dateString) {
        return Date.from(Instant.from(DateTimeFormatter.ISO_INSTANT.parse(dateString)));
    }

    private ComplianceType evaluateCompliance(ConfigEvent event) throws JsonProcessingException, IOException {
        JsonNode invokingEvent = OBJECT_MAPPER.readTree(event.getInvokingEvent());
        JsonNode ruleParameters = OBJECT_MAPPER.readTree(event.getRuleParameters());
        if (isEventNotApplicable(invokingEvent, event.isEventLeftScope()) || isNotDBInstance(invokingEvent)) {
            return ComplianceType.NOT_APPLICABLE;
        } else if (isBackUpTurnedOn(invokingEvent) && isExpectedBackUpWindow(invokingEvent, ruleParameters)
                && isExpectedRetentionPeriod(invokingEvent, ruleParameters))
        {
            return ComplianceType.COMPLIANT;
        } else {
            return ComplianceType.NON_COMPLIANT;
        }
    }

    private boolean isBackUpTurnedOn(JsonNode invokingEvent) {
        return invokingEvent.path(CONFIGURATION_ITEM).path(CONFIGURATION).path(RETENTION_PERIOD).intValue() > 0;
    }

    private boolean isExpectedBackUpWindow(JsonNode invokingEvent, JsonNode ruleParameters) {
        String expectedBackupWindow = ruleParameters.path(BACKUP_WINDOW).textValue();
        String actualBackupWindow = invokingEvent.path(CONFIGURATION_ITEM).path(CONFIGURATION).path(BACKUP_WINDOW)
                .textValue();
        return StringUtils.isBlank(expectedBackupWindow) ? true : StringUtils.equalsIgnoreCase(
                expectedBackupWindow, actualBackupWindow);
    }

    private boolean isExpectedRetentionPeriod(JsonNode invokingEvent, JsonNode ruleParameters) {
        String expectedRetentionPeriodString = ruleParameters.path(RETENTION_PERIOD).textValue();
        if (StringUtils.isBlank(expectedRetentionPeriodString)) {
            return true;
        } else {
            int expectedRetentionPeriodInteger = tryGetRetentionPeriodInteger(expectedRetentionPeriodString);
            int actualRetentionPeriod = invokingEvent.path(CONFIGURATION_ITEM).path(CONFIGURATION)
                    .path(RETENTION_PERIOD).intValue();
            return expectedRetentionPeriodInteger == actualRetentionPeriod;
        }
    }

    private int tryGetRetentionPeriodInteger(String retentionPeriodString) {
        if (StringUtils.isNumeric(retentionPeriodString)) {
            return Integer.parseInt(retentionPeriodString);
        }
        else {
            throw new FunctionExecutionException(String.format(INVALID_BACKUP_RETENTION_PERIOD, retentionPeriodString));
        }
    }

    private boolean isEventNotApplicable(JsonNode invokingEvent, boolean eventLeftScope) {
        String status = invokingEvent.path(CONFIGURATION_ITEM).path(STATUS_PATH).textValue();
        return (isStatusNotApplicable(status) || eventLeftScope);
    }

    private boolean isNotDBInstance(JsonNode invokingEvent) {
        return !ResourceType.AWSRDSDBInstance.toString().equals(
                invokingEvent.path(CONFIGURATION_ITEM).path(RESOURCE_TYPE).textValue());
    }

    private boolean isStatusNotApplicable(String status) {
        return RESOURCE_DELETED.equals(status) || RESOURCE_DELETED_NOT_RECORDED.equals(status)
                || RESOURCE_NOT_RECORDED.equals(status);
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

