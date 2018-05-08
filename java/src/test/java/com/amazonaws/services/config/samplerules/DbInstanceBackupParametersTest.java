package com.amazonaws.services.config.samplerules;

import static org.junit.Assert.*;
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
public class DbInstanceBackupParametersTest {

    private static final String ACCOUNT_ID = "accountId";
    private static final String RESULT_TOKEN = "resultToken";
    private static final String PARAMETERS_FORMAT =
            "{\"preferredBackupWindow\": \"%s\",\"backupRetentionPeriod\":\"%s\"}";
    private static final String BACKUPWINDOW_ONLY_FORMAT = "{\"preferredBackupWindow\": \"%s\"}";
    private static final String RETENTION_PERIOD_ONLY_FORMAT = "{\"backupRetentionPeriod\":\"%s\"}";
    private static final String ACTUAL_BACKUP_WINDOW = "actualBackupWindow";
    private static final String ACTUAL_RENTENTION_PERIOD = "7";
    private static final String WRONG_RENTENTION_PERIOD = "10";
    private static final String INVALID_RETENTION_PERIOD = "test";
    private static final String NO_PARAMETERS = "{}";
    private static final String ZERO_RENTENTION_PERIOD = "0";
    private static final String WRONG_BACKUP_WINDOW = "wrongBackupWindow";
    //@formatter:off
    private static final String EC2_INSTANCE_CONFIG_EVENT =
            "{"
                + "\"configurationItem\":{"
                    + "\"configurationItemCaptureTime\":\"%s\","
                    + "\"configurationItemStatus\":\"%s\","
                    + "\"resourceType\":\"AWS::EC2::Instance\","
                    + "\"resourceId\":\"%s\""
                + "},"
                + "\"messageType\":\"%s\""
            + "}";
    //@formatter:on

    @Mock
    private Context context;
    @Mock
    private AmazonConfig configClient;

    private String configurationItemStatus;
    private ConfigEvent event;
    private DbInstanceBackupParameters dbInstanceBackupParameters;

    @Before
    public void setup() {
        configurationItemStatus = "OK";
        event = new ConfigEvent();
        event.setAccountId(ACCOUNT_ID);
        event.setResultToken(RESULT_TOKEN);
        event.setEventLeftScope(false);
        dbInstanceBackupParameters = new DbInstanceBackupParameters();
        when(configClient.putEvaluations(any(PutEvaluationsRequest.class)))
                .thenReturn(new PutEvaluationsResult().withFailedEvaluations(Collections.emptyList()));
    }

    @Test
    public void testCompliant_withAllParams() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNonCompliant_forAllParms() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(WRONG_BACKUP_WINDOW,
                WRONG_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.NON_COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testCompliant_withNoParams() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(NO_PARAMETERS);
        invokeAndAssertRuleCompliance(ComplianceType.COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNonCompliant_withNoParams() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ZERO_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(NO_PARAMETERS);
        invokeAndAssertRuleCompliance(ComplianceType.NON_COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNonCompliant_withRetentionPeriodOnly() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                WRONG_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(RETENTION_PERIOD_ONLY_FORMAT, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.NON_COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testCompliant_withRetentionPeriodOnly() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(RETENTION_PERIOD_ONLY_FORMAT, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testException_invalidRententionPeriod() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, INVALID_RETENTION_PERIOD));
        invokeAndAssertException(String.format(DbInstanceBackupParameters.INVALID_BACKUP_RETENTION_PERIOD,
                INVALID_RETENTION_PERIOD));
    }

    @Test
    public void testCompliant_withBackupWindowOnly() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(BACKUPWINDOW_ONLY_FORMAT, ACTUAL_BACKUP_WINDOW));
        invokeAndAssertRuleCompliance(ComplianceType.COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNonCompliant_withBackupWindowOnly() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(WRONG_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(BACKUPWINDOW_ONLY_FORMAT, ACTUAL_BACKUP_WINDOW));
        invokeAndAssertRuleCompliance(ComplianceType.NON_COMPLIANT, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNotApplicable_deletedResource() throws IOException {
        configurationItemStatus = "ResourceDeleted";
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.NOT_APPLICABLE, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNotApplicable_deletedNotRecordedResource() throws IOException {
        configurationItemStatus = "ResourceDeletedNotRecorded";
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.NOT_APPLICABLE, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNotApplicable_notRecordedResource() throws IOException {
        configurationItemStatus = "ResourceNotRecorded";
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.NOT_APPLICABLE, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNotApplicable_eventLeftScope() throws IOException {
        event.setEventLeftScope(true);
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ConfigurationItemChangeNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.NOT_APPLICABLE, ResourceType.AWSRDSDBInstance);
    }

    @Test
    public void testNotApplicable_nonDBInstance() throws IOException {
        event.setInvokingEvent(String.format(EC2_INSTANCE_CONFIG_EVENT, DbInstanceConfigEventBuilder.CI_CAPTURE_TIME,
                configurationItemStatus, DbInstanceConfigEventBuilder.RESOURCE_ID,
                MessageType.ConfigurationItemChangeNotification.toString()));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertRuleCompliance(ComplianceType.NOT_APPLICABLE, ResourceType.AWSEC2Instance);
    }

    @Test
    public void testException_scheduledNotificationMessage() throws IOException {
        event.setInvokingEvent(DbInstanceConfigEventBuilder.buildInvokingEvent(ACTUAL_BACKUP_WINDOW,
                ACTUAL_RENTENTION_PERIOD, configurationItemStatus, MessageType.ScheduledNotification));
        event.setRuleParameters(String.format(PARAMETERS_FORMAT, ACTUAL_BACKUP_WINDOW, ACTUAL_RENTENTION_PERIOD));
        invokeAndAssertException(String.format(DbInstanceBackupParameters.INCOMPATIBLE_EVENT_TYPES_MESSAGE,
                MessageType.ScheduledNotification.toString()));
    }

    private void invokeAndAssertException(String expectedMessage) throws IOException {
        try {
            dbInstanceBackupParameters.doHandle(event, context, configClient);
            fail("expected FuntionExecution exception");
        } catch (FunctionExecutionException ex) {
            assertEquals(expectedMessage, ex.getMessage());
        }
    }

    private void invokeAndAssertRuleCompliance(ComplianceType complianceType, ResourceType resourceType)
            throws IOException {
        dbInstanceBackupParameters.doHandle(event, context, configClient);
        verifyCompliance(complianceType, resourceType);
    }

    private void verifyCompliance(ComplianceType complianceType, ResourceType resourceType) {
        Evaluation evaluation = new Evaluation()
                .withComplianceResourceId(DbInstanceConfigEventBuilder.RESOURCE_ID)
                .withComplianceResourceType(resourceType.toString())
                .withOrderingTimestamp(DbInstanceConfigEventBuilder.CI_CAPTURE_TIME_IN_DATE_FORMAT)
                .withComplianceType(complianceType);
        PutEvaluationsRequest putEvaluationsRequest = new PutEvaluationsRequest()
                .withEvaluations(evaluation)
                .withResultToken(RESULT_TOKEN);
        verify(configClient).putEvaluations(eq(putEvaluationsRequest));
    }

    public static class DbInstanceConfigEventBuilder {
        public static final String CI_CAPTURE_TIME = "2016-07-26T16:03:58.070Z";
        public static final String RESOURCE_ID = "bar";
        public static final Date CI_CAPTURE_TIME_IN_DATE_FORMAT = Date.from(Instant
                .from(DateTimeFormatter.ISO_INSTANT.parse(CI_CAPTURE_TIME)));

        //@formatter:off
        private static final String DB_INSTANCE_CONFIG_EVENT =
                "{"
                    + "\"configurationItem\":{"
                        + "\"configuration\":{"
                            + "\"preferredBackupWindow\":\"%s\","
                            + "\"backupRetentionPeriod\":%s"
                        + "},"
                        + "\"configurationItemCaptureTime\":\"%s\","
                        + "\"configurationItemStatus\":\"%s\","
                        + "\"resourceType\":\"AWS::RDS::DBInstance\","
                        + "\"resourceId\":\"%s\""
                    + "},"
                    + "\"messageType\":\"%s\""
                + "}";
        //@formatter:on

        public static String buildInvokingEvent(String preferredBackupWindow, String backupRentionPeriod,
                String configurationItemStatus, MessageType messageType) {
            return String.format(DB_INSTANCE_CONFIG_EVENT, preferredBackupWindow, backupRentionPeriod, CI_CAPTURE_TIME,
                    configurationItemStatus, RESOURCE_ID, messageType.toString());
        }
    }
}

