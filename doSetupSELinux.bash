#!/bin/bash

INSTDIR="$(dirname "$0")"
case "$INSTDIR" in
	/*)
		true
		;;
	*)
		INSTDIR="${PWD}/${INSTDIR}"
		;;
esac

chcon -Rv --type=httpd_sys_content_t "${INSTDIR}"
chcon -Rv --type=httpd_sys_script_exec_t "${INSTDIR}"/user-management.cgi
