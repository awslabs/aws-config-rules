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

public class DesiredInstanceTenancy {

    private static final String AWS_REGION_PROPERTY = "AWS_DEFAULT_REGION";
    private static final String MESSAGE_TYPE_PROPERTY = "messageType";
    private static final String HOST_ID = "hostId";
    private static final String PLACEMENT = "placement";
    private static final String CONFIGURATION = "configuration";
    private static final String IMAGE_ID = "imageId";
    private static final String STATUS_PATH = "configurationItemStatus";
    private static final String TENANCY = "tenancy";
    private static final String RESOURCE_DELETED = "ResourceDeleted";
    private static final String RESOURCE_DELETED_NOT_RECORDED = "ResourceDeletedNotRecorded";
    private static final String CAPTURE_TIME_PATH = "configurationItemCaptureTime";
    private static final String CONFIGURATION_ITEM = "configurationItem";
    private static final String RESOURCE_ID = "resourceId";
    private static final Object RESOURCE_NOT_RECORDED = "ResourceNotRecorded";
    private static final String RESOURCE_TYPE = "resourceType";

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
    public void doHandle(ConfigEvent event, Context context, AmazonConfig configClient) throws IOException {
        JsonNode invokingEvent = new ObjectMapper().readTree(event.getInvokingEvent());
        failForIncompatibleEventTypes(invokingEvent);

        // Associates the evaluation result with the AWS account published in the event.
        Evaluation evaluation = new Evaluation()
                .withComplianceResourceId(getResourceId(invokingEvent))
                .withComplianceResourceType(getResourceType(invokingEvent))
                .withOrderingTimestamp(getCiCapturedTime(invokingEvent))
                .withComplianceType(evaluateCompliance(event));
        doPutEvaluations(configClient, event, evaluation);
    }

    private String getResourceType(JsonNode invokingEvent) {
        return invokingEvent.path(CONFIGURATION_ITEM).path(RESOURCE_TYPE).textValue();
    }

    private void failForIncompatibleEventTypes(JsonNode invokingEvent) {
        String messageType = invokingEvent.path(MESSAGE_TYPE_PROPERTY).textValue();
        if (!isCompatibleMessageType(messageType)) {
            throw new FunctionExecutionException(String.format(
                    "Events with the message type '%s' are not evaluated for this Config rule.", messageType));
        }
    }

    private String getResourceId(JsonNode invokingEvent) {
        return invokingEvent.path(CONFIGURATION_ITEM).path(RESOURCE_ID).textValue();
    }

    private Date getCiCapturedTime(JsonNode invokingEvent) {
        return getDate(invokingEvent.path(CONFIGURATION_ITEM).path(CAPTURE_TIME_PATH).textValue());
    }

    private ComplianceType evaluateCompliance(ConfigEvent event) throws JsonProcessingException,
            IOException {
        JsonNode invokingEvent = new ObjectMapper().readTree(event.getInvokingEvent());
        JsonNode ruleParameters = new ObjectMapper().readTree(event.getRuleParameters());

        if (isEventNotApplicable(invokingEvent, event.isEventLeftScope())
                || !hasExpectedImageId(invokingEvent, ruleParameters))
        {
            return ComplianceType.NOT_APPLICABLE;
        } else if (isDesiredTenancy(invokingEvent, ruleParameters)
                && isOnExpectedDedicatedHost(invokingEvent, ruleParameters))
        {
            return ComplianceType.COMPLIANT;
        } else {
            return ComplianceType.NON_COMPLIANT;
        }
    }

    private boolean isCompatibleMessageType(String messageType) {
        return MessageType.ConfigurationItemChangeNotification.toString().equals(messageType);
    }

    private boolean isEventNotApplicable(JsonNode invokingEvent, boolean eventLeftScope) {
        String status = invokingEvent.path(CONFIGURATION_ITEM).path(STATUS_PATH).textValue();
        return (isStatusNotApplicable(status) || eventLeftScope);
    }

    private boolean isStatusNotApplicable(String status) {
        return RESOURCE_DELETED.equals(status) || RESOURCE_DELETED_NOT_RECORDED.equals(status)
                || RESOURCE_NOT_RECORDED.equals(status);
    }

    private boolean isDesiredTenancy(JsonNode invokingEvent, JsonNode ruleParameters) {
        String expectedTenancy = ruleParameters.path(TENANCY).textValue();
        String actualTenancy = invokingEvent.path(CONFIGURATION_ITEM).path(CONFIGURATION).path(PLACEMENT).path(TENANCY)
                .textValue();
        return StringUtils.equalsIgnoreCase(expectedTenancy, actualTenancy);
    }

    private boolean hasExpectedImageId(JsonNode invokingEvent, JsonNode ruleParameters) throws JsonProcessingException,
            IOException {
        String expectedImageId = ruleParameters.path(IMAGE_ID).textValue();
        String actualImageId = invokingEvent.path(CONFIGURATION_ITEM).path(CONFIGURATION).path(IMAGE_ID).textValue();
        return StringUtils.isBlank(expectedImageId) ? true : StringUtils.equalsIgnoreCase(expectedImageId,
                actualImageId);
    }

    private boolean isOnExpectedDedicatedHost(JsonNode invokingEvent, JsonNode ruleParameters)
            throws JsonProcessingException, IOException {
        String expectedHostId = ruleParameters.path(HOST_ID).textValue();
        String actualHostId = invokingEvent.path(CONFIGURATION_ITEM).path(CONFIGURATION).path(PLACEMENT).path(HOST_ID)
                .textValue();
        return StringUtils.isBlank(expectedHostId) ? true : StringUtils.equalsIgnoreCase(expectedHostId, actualHostId);
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

    private Date getDate(String dateString) {
        return Date.from(Instant.from(DateTimeFormatter.ISO_INSTANT.parse(dateString)));
    }
}
