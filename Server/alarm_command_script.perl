#!/bin/sh
# first argument can be: hbfailure testalarm alarm
if [ "$1" = "testalarm" ]; then
	date
	echo $*
	echo "exiting the alarm_command_script script..."
	exit 0
fi
if [ "$1" = "hbfailure" ]; then
	date
	echo $*
	echo "ignoring heartbeat failure..."
	exit 0
fi
# --- for real alarms the code below will be executed
echo $*
