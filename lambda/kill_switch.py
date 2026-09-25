"""
SecretAccessKillSwitch
----------------------
Triggered by an Amazon EventBridge rule whenever the honeytoken secret
(Production_Database_Credentials) is read via secretsmanager:GetSecretValue.

The function extracts the offending IAM user's identity from the CloudTrail
event and detaches all of their managed policies, revoking their access.

Two safety layers constrain it (see also the execution-role policy):
  1. Code allow-list: it will only ever act on ALLOWED_TARGET.
  2. IAM: the execution role can only detach policies from that one user.
"""

import json
import boto3

# The ONLY user this function is ever allowed to disable.
# Safety guard: even if some other GetSecretValue fires, the function
# refuses to touch anyone except this user.
ALLOWED_TARGET = "victim-user"

iam = boto3.client("iam")


def lambda_handler(event, context):
    print("Received event:", json.dumps(event))

    # 1. Extract the attacker's username from the CloudTrail event
    try:
        user_identity = event["detail"]["userIdentity"]
        username = user_identity.get("userName")
    except (KeyError, TypeError):
        print("Could not find userName in event. Exiting.")
        return {"status": "no username found"}

    print(f"Secret was accessed by: {username}")

    # 2. SAFETY GUARD: only ever act on the designated victim
    if username != ALLOWED_TARGET:
        print(f"User '{username}' is not the allowed target. Taking no action.")
        return {"status": "user not in allowlist, no action taken"}

    # 3. Detach every managed policy attached to the victim
    attached = iam.list_attached_user_policies(UserName=username)
    for policy in attached["AttachedPolicies"]:
        iam.detach_user_policy(
            UserName=username,
            PolicyArn=policy["PolicyArn"],
        )
        print(f"Detached policy: {policy['PolicyName']}")

    print(f"Kill-switch complete. All managed policies stripped from {username}.")
    return {"status": "permissions revoked", "user": username}
