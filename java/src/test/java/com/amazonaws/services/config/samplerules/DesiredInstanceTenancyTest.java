package com.amazonaws.services.config.samplerules;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
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
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ConfigEvent;

@RunWith(MockitoJUnitRunner.class)
public class DesiredInstanceTenancyTest {

    private static final String RESULT_TOKEN = "resultToken";
    private static final String ACCOUNT_ID = "accountId";

    private static final String CI_CAPTURED_TIME = "2016-05-04T18:13:21.605Z";
    private static final String CONFIGURATION_ITEM_FORMAT = "\"resourceType\":\"%s\","
            + "\"resourceId\":\"%s\",\"configurationItemStatus\":\"%s\",\"configurationItemCaptureTime\": \"%s\",\"configuration\":%s";
    private static final String CONFIGURATION_FORMAT = " {\"imageId\":%s, \"placement\": {\"hostId\":%s, \"tenancy\": %s}}";
    private static final String INVOKING_EVENT_FORMAT = "{\"messageType\":%s,\"configurationItem\":{%s}}";
    private static final String PARAMETERS_FORMAT = "{\"tenancy\": %s,\"imageId\":%s,\"hostId\":%s}";
    private static final String CONFIGURATION_FORMAT_WITHOUT_HOST = "{\"imageId\":%s, \"placement\": {\"tenancy\": %s}}";
    private static final String SNAPSHOT_DELIVERY_INVOKING_EVENT_FORMAT = "{\"messageType\":%s}";

    private static final String RESOURCE_ID = "resourceId";
    private static final String DESIRED_HOST_ID = "dummyHostId";
    private static final String DESIRED_IMAGE_ID = "dummyImageId";
    private static final String OTHER_HOST_ID = "OtherHostId";
    private static final String OTHER_IMAGE_ID = "OtherImageId";
    private static final String DEDICATED_TENANCY = "dedicated";
    private static final String HOST_TENANCY = "host";
    private static final String DEFAULT_TENANCY = "default";
    private static final String STATUS_OK = "OK";
    private static final String RESOURCE_DELETED = "ResourceDeleted";
    private static final String RESOURCE_NOT_RECORDED = "ResourceNotRecorded";

    @Mock
    private Context context;
    @Mock
    private AmazonConfig configClient;

    private ConfigEvent event;
    private DesiredInstanceTenancy desiredInstanceTenancyFunction;

    @Before
    public void setUp() throws Exception {
        event = new ConfigEvent();
        event.setAccountId(ACCOUNT_ID);
        event.setResultToken(RESULT_TOKEN);
        event.setEventLeftScope(false);
        desiredInstanceTenancyFunction = new DesiredInstanceTenancy();
        when(configClient.putEvaluations(any(PutEvaluationsRequest.class)))
                .thenReturn(new PutEvaluationsResult().withFailedEvaluations(Collections.emptyList()));
    }

    @Test
    public void test_Compliant_withAllParameters() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.COMPLIANT);
    }

    @Test
    public void test_Compliant_withTenancyAndImageId() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, null);
        invokeFunctionAndAssertCompliance(ComplianceType.COMPLIANT);
    }

    @Test
    public void test_Compliant_withHostTenancy() throws Exception {
        buildAndSetInvokingEvent(HOST_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(HOST_TENANCY, null, null);
        invokeFunctionAndAssertCompliance(ComplianceType.COMPLIANT);
    }

    @Test
    public void test_Compliant_withNoHostIdInCI() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, null);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, null);
        invokeFunctionAndAssertCompliance(ComplianceType.COMPLIANT);
    }

    @Test
    public void test_Compliant_withTenancyAndHostId() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, null, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.COMPLIANT);
    }

    @Test
    public void test_Compliant_withUppercaseTenancy() throws IOException {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, null);
        setRuleParameters("DEDICATED", DESIRED_IMAGE_ID, null);
        invokeFunctionAndAssertCompliance(ComplianceType.COMPLIANT);
    }

    @Test
    public void test_Compliant_withDedicatedTenancy() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, null, null);
        invokeFunctionAndAssertCompliance(ComplianceType.COMPLIANT);
    }

    @Test
    public void test_NonCompliant_withDesiredTenancy_undesiredHostId() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, OTHER_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, null, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.NON_COMPLIANT);
    }

    @Test
    public void test_NonCompliant_withUnDesiredTenancy_desiredImageHostId() throws Exception {
        buildAndSetInvokingEvent(HOST_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.NON_COMPLIANT);
    }

    @Test
    public void test_NonCompliant_withUnDesiredHostTenancy() throws Exception {
        buildAndSetInvokingEvent(HOST_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, null, null);
        invokeFunctionAndAssertCompliance(ComplianceType.NON_COMPLIANT);
    }

    @Test
    public void test_NonCompliant_withNoHostIdInCI() throws Exception {
        buildAndSetInvokingEventWithoutHostId(DEFAULT_TENANCY, DESIRED_IMAGE_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.NON_COMPLIANT);
    }

    @Test
    public void test_NonCompliant_withUnDesiredTenancy() throws Exception {
        buildAndSetInvokingEvent(DEFAULT_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, null, null);
        invokeFunctionAndAssertCompliance(ComplianceType.NON_COMPLIANT);
    }

    @Test
    public void test_NotApplicable_eventLeftScope() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        event.setEventLeftScope(true);
        invokeFunctionAndAssertCompliance(ComplianceType.NOT_APPLICABLE);
    }

    @Test
    public void test_NotApplicable_withAllUndesiredParameters() throws Exception {
        buildAndSetInvokingEvent(HOST_TENANCY, OTHER_IMAGE_ID, OTHER_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.NOT_APPLICABLE);
    }

    @Test
    public void test_NotApplicable_withDesiredTenancy_undesiredImageHostId() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, OTHER_IMAGE_ID, OTHER_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.NOT_APPLICABLE);
    }

    @Test
    public void test_NotApplicable_withDesiredTenancy_undesiredImageId() throws Exception {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, OTHER_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, null);
        invokeFunctionAndAssertCompliance(ComplianceType.NOT_APPLICABLE);
    }

    @Test
    public void test_NotApplicableCase_DeletedResources() throws IOException {
        String configuration = String.format(CONFIGURATION_FORMAT, escapeStringToJson(DESIRED_IMAGE_ID),
                escapeStringToJson(DESIRED_HOST_ID), escapeStringToJson(DEDICATED_TENANCY));
        event.setInvokingEvent(buildConfigurationItem(configuration, RESOURCE_DELETED));
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.NOT_APPLICABLE);
    }

    @Test
    public void test_NotApplicableCase_notRecordedResources() throws IOException {
        String configuration = String.format(CONFIGURATION_FORMAT, escapeStringToJson(DESIRED_IMAGE_ID),
                escapeStringToJson(DESIRED_HOST_ID), escapeStringToJson(DEDICATED_TENANCY));
        event.setInvokingEvent(buildConfigurationItem(configuration, RESOURCE_NOT_RECORDED));
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        invokeFunctionAndAssertCompliance(ComplianceType.NOT_APPLICABLE);
    }

    @Test(expected = FunctionExecutionException.class)
    public void testHandleWrongMessageType() throws IOException {
        event.setInvokingEvent(String.format(SNAPSHOT_DELIVERY_INVOKING_EVENT_FORMAT,
                escapeStringToJson(MessageType.ConfigurationSnapshotDeliveryCompleted.toString())));
        desiredInstanceTenancyFunction.doHandle(event, context, configClient);
    }

    @Test(expected = FunctionExecutionException.class)
    public void testHandleFailedEvaluations() throws IOException {
        buildAndSetInvokingEvent(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        setRuleParameters(DEDICATED_TENANCY, DESIRED_IMAGE_ID, DESIRED_HOST_ID);
        Evaluation failedEvaluation = new Evaluation();
        when(configClient.putEvaluations(any(PutEvaluationsRequest.class)))
                .thenReturn(new PutEvaluationsResult().withFailedEvaluations(failedEvaluation));
        desiredInstanceTenancyFunction.doHandle(event, context, configClient);
    }

    private void buildAndSetInvokingEvent(String tenancy, String imageId, String hostId) {
        event.setInvokingEvent(buildInstanceWithTenancyHostImageIds(tenancy, imageId, hostId,
                STATUS_OK));
    }

    private void buildAndSetInvokingEventWithoutHostId(String tenancy, String imageId) {
        event.setInvokingEvent(buildInstanceWithoutHostId(tenancy, imageId, STATUS_OK));
    }

    private void setRuleParameters(String expectedTenancy, String expectedImageId, String expectedHostId) {
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, escapeStringToJson(expectedTenancy),
                escapeStringToJson(expectedImageId),
                escapeStringToJson(expectedHostId)));
    }

    private void invokeFunctionAndAssertCompliance(ComplianceType expectedCompliance) throws IOException {
        desiredInstanceTenancyFunction.doHandle(event, context, configClient);
        verifyReportedCompliance(expectedCompliance);
    }

    private String buildInstanceWithTenancyHostImageIds(String tenancy, String imageId, String hostId,
            String configurationItemStatus) {
        String configuration = String.format(CONFIGURATION_FORMAT, escapeStringToJson(imageId),
                escapeStringToJson(hostId), escapeStringToJson(tenancy));
        return buildConfigurationItem(configuration, configurationItemStatus);
    }

    private String buildInstanceWithoutHostId(String tenancy, String imageId, String configurationItemStatus) {
        String configuration = String.format(CONFIGURATION_FORMAT_WITHOUT_HOST, escapeStringToJson(imageId),
                escapeStringToJson(tenancy));
        return buildConfigurationItem(configuration, configurationItemStatus);
    }

    private String buildConfigurationItem(String configuration, String configurationItemStatus) {
        String configurationItem = String.format(CONFIGURATION_ITEM_FORMAT, ResourceType.AWSEC2Instance.toString(),
                RESOURCE_ID, configurationItemStatus, CI_CAPTURED_TIME, configuration);
        return String.format(INVOKING_EVENT_FORMAT,
                escapeStringToJson(MessageType.ConfigurationItemChangeNotification.toString()),
                configurationItem);
    }

    private void verifyReportedCompliance(ComplianceType compliance) {
        Evaluation evaluation = new Evaluation()
                .withComplianceResourceId(RESOURCE_ID)
                .withComplianceResourceType(ResourceType.AWSEC2Instance.toString())
                .withOrderingTimestamp(getDate(CI_CAPTURED_TIME))
                .withComplianceType(compliance);
        PutEvaluationsRequest putEvaluationsRequest = new PutEvaluationsRequest()
                .withEvaluations(evaluation)
                .withResultToken(RESULT_TOKEN);
        verify(configClient).putEvaluations(eq(putEvaluationsRequest));
    }

    private String escapeStringToJson(String string) {
        if (string != null) {
            string = String.format("\"%s\"", string);
        }
        return string;
    }

    private Date getDate(String dateString) {
        return Date.from(Instant.from(DateTimeFormatter.ISO_INSTANT.parse(dateString)));
    }
}
