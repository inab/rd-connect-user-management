#!/bin/sh

basedir="$(dirname "$0")"
case "$basedir" in
	/*)
		true
		;;
	*)
		basedir="$(realpath $basedir)"
		;;
esac
namedir="$(basename "$basedir")"

output_archive=/tmp/"${namedir}_$(date -I).tar.bz2"

echo "* Output archive: $output_archive"

cd "${basedir}/.." && \
tar -c -p --selinux --exclude="${namedir}/configs/user-management.ini" --exclude-vcs -f - "${namedir}" | bzip2 -9c > "$output_archive"
