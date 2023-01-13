#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# Wait for a service to enter a state within a timeout period, if it doesn't
# enter the desired state within the timeout period then this function will
# exit the test case with a non zero exit code.
wait_on_state_or_fail () {
    service=$1
    expected_state=$2
    timeout=$3

    state=$(systemctl show "$service" --property=ActiveState --value)
    while [ "$state" != "$expected_state" ]; do
        if [ "$timeout" = "0" ]; then
            systemd-analyze log-level info
            exit 1
        fi
        timeout=$((timeout - 1))
        sleep 1
        state=$(systemctl show "$service" --property=ActiveState --value)
    done
}

systemd-analyze log-level debug

# Trigger testservice-failure-exit-handler-68.service
cat >/run/systemd/system/testservice-failure-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnFailure= trigger
OnFailure=testservice-failure-exit-handler-68.service

[Service]
ExecStart=sh -c "exit 1"
EOF

cat >/run/systemd/system/testservice-failure-68-template.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnFailure= trigger (template)
OnFailure=testservice-failure-exit-handler-68-template@%n.service

[Service]
ExecStart=sh -c "exit 1"
EOF

# Script to check that when an OnFailure= dependency fires, the correct
# MONITOR* env variables are passed.
cat >/tmp/check_on_failure.sh <<"EOF"
#!/bin/sh

set -ex
env | sort
if [ "$MONITOR_SERVICE_RESULT" != "exit-code" ]; then
    echo "MONITOR_SERVICE_RESULT was '$MONITOR_SERVICE_RESULT', expected 'exit-code'"
    exit 1
fi

if [ "$MONITOR_EXIT_CODE" != "exited" ]; then
    echo "MONITOR_EXIT_CODE was '$MONITOR_EXIT_CODE', expected 'exited'"
    exit 1
fi

if [ "$MONITOR_EXIT_STATUS" != "1" ]; then
    echo "MONITOR_EXIT_STATUS was '$MONITOR_EXIT_STATUS', expected '1'"
    exit 1
fi

if [ -z "$MONITOR_INVOCATION_ID" ]; then
    echo "MONITOR_INVOCATION_ID unset"
    exit 1
fi

if [ "$MONITOR_UNIT" != "testservice-failure-68.service" ] &&
   [ "$MONITOR_UNIT" != "testservice-failure-68-template.service" ] &&
   [ "$MONITOR_UNIT" != "testservice-transient-failure-68.service" ]; then

    echo "MONITOR_UNIT was '$MONITOR_UNIT', expected 'testservice[-transient]-failure-68[-template].service'"
    exit 1
fi

exit 0
EOF
chmod +x /tmp/check_on_failure.sh


# Handle testservice-failure-exit-handler-68.service exiting with failure.
cat >/run/systemd/system/testservice-failure-exit-handler-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS handle service exiting in failure

[Service]
ExecStartPre=/tmp/check_on_failure.sh
ExecStart=/tmp/check_on_failure.sh
EOF

# Template version.
cat >/run/systemd/system/testservice-failure-exit-handler-68-template@.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS handle service exiting in failure (template)

[Service]
ExecStartPre=echo "triggered by %i"
ExecStartPre=/tmp/check_on_failure.sh
ExecStart=/tmp/check_on_failure.sh
EOF

systemctl daemon-reload

: "-------I----------------------------------------------------"
systemctl start testservice-failure-68.service
wait_on_state_or_fail "testservice-failure-exit-handler-68.service" "inactive" "10"

# Let's get rid of the failed units so the tests below don't fail, and daemon-reload
# to force garbace collection of the units.
systemctl reset-failed
systemctl daemon-reload

# Test some transient units since these exit very quickly.
: "-------II---------------------------------------------------"
systemd-run --unit=testservice-transient-failure-68 --property=OnFailure=testservice-failure-exit-handler-68.service sh -c "exit 1"
wait_on_state_or_fail "testservice-failure-exit-handler-68.service" "inactive" "10"

systemctl reset-failed
systemctl daemon-reload

# Test template handlers too
: "-------III--------------------------------------------------"
systemctl start testservice-failure-68-template.service
wait_on_state_or_fail "testservice-failure-exit-handler-68-template@testservice-failure-68-template.service.service" "inactive" "10"

systemd-analyze log-level info
echo OK >/testok

exit 0
