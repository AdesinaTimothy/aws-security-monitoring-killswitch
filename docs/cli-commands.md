# Key AWS CLI commands

All commands run in `eu-north-1`. Account IDs shown as `<ACCOUNT_ID>`.

## Phase 1 — Infrastructure

```bash
# Create the honeytoken secret
aws secretsmanager create-secret \
  --name Production_Database_Credentials \
  --description "Production database credentials for the production system" \
  --secret-string '{"username":"admin","password":"<dummy>"}' \
  --region eu-north-1

# Verify the CloudTrail -> CloudWatch integration is live
aws cloudtrail get-trail-status --name security-monitoring-trail --region eu-north-1
aws logs describe-log-groups --region eu-north-1
```

## Phase 2 — Flow 1 (metric filter + alarm)

```bash
# Alarm (note: GreaterThanOrEqualToThreshold, not GreaterThanThreshold)
aws cloudwatch put-metric-alarm \
  --alarm-name "SecretAccessAlarm-Flow1" \
  --namespace "SecurityMetrics" --metric-name "SecretAccessCount" \
  --statistic Sum --period 60 --evaluation-periods 1 --datapoints-to-alarm 1 \
  --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions arn:aws:sns:eu-north-1:<ACCOUNT_ID>:security-alerts-flow1 \
  --region eu-north-1
```

## Phase 3 — Flow 2 (EventBridge)

```bash
# The critical part: state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS
# so the rule matches the read-only GetSecretValue event.
aws events put-rule \
  --name "SecretAccessDetection-Flow2" \
  --event-bus-name "default" \
  --state "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" \
  --event-pattern '{"source":["aws.secretsmanager"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["secretsmanager.amazonaws.com"],"eventName":["GetSecretValue"]}}' \
  --region eu-north-1
```

## Phase 4 — Kill-switch wiring

```bash
# Add the Lambda as a second target on the rule
aws events put-targets \
  --rule "SecretAccessDetection-Flow2" --event-bus-name "default" \
  --targets "Id"="killswitch-lambda-target","Arn"="arn:aws:lambda:eu-north-1:<ACCOUNT_ID>:function:SecretAccessKillSwitch" \
  --region eu-north-1

# Grant EventBridge permission to invoke the Lambda (CLI does not do this automatically)
aws lambda add-permission \
  --function-name SecretAccessKillSwitch \
  --statement-id "AllowEventBridgeInvoke" \
  --action "lambda:InvokeFunction" --principal "events.amazonaws.com" \
  --source-arn "arn:aws:events:eu-north-1:<ACCOUNT_ID>:rule/SecretAccessDetection-Flow2" \
  --region eu-north-1
```

## The trap test

```bash
# As the victim: first read succeeds, second (after kill-switch) is denied
aws secretsmanager get-secret-value --secret-id Production_Database_Credentials --profile victim --region eu-north-1
# ... wait ~1 min ...
aws secretsmanager get-secret-value --secret-id Production_Database_Credentials --profile victim --region eu-north-1
# -> AccessDeniedException

# Confirm zero policies (as admin)
aws iam list-attached-user-policies --user-name victim-user
# -> "AttachedPolicies": []
```
