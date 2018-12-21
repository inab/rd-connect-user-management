#!/bin/bash

umdir="$(dirname "$0")"
case "${umdir}" in
	/*)
		true
		;;
	*)
		umdir="${PWD}"/"${umdir}"
		;;
esac


plEnvDir="${umdir}/.plEnv"

export PERL_LOCAL_LIB_ROOT="${plEnvDir}:$PERL_LOCAL_LIB_ROOT"
export PERL_MB_OPT="--install_base ${plEnvDir}"
export PERL_MM_OPT="INSTALL_BASE='${plEnvDir}'"
export PERL5LIB="${plEnvDir}/lib/perl5:$PERL5LIB"
export PATH="${plEnvDir}/bin:$PATH"
#( echo ; echo ) | cpan
#(echo o conf prerequisites_policy follow;echo o conf commit) | cpan

# Is cpan already installed?
type -P cpanm >& /dev/null
if [ $? -ne 0 ] ; then
	perl -MExtUtils::MakeMaker -e 'exit 0'
	if [ $? -ne 0 ] ; then
		# It has a failing test in Docker build
		cpan -f ExtUtils::MakeMaker
	fi
	perl -Mlocal::lib -e 'exit 0'
	if [ $? -ne 0 ] ; then
		# Updated CPAN needs local::lib
		cpan -i local::lib
	fi
	# Updating CPAN
	cpan -i CPAN
	# Install cpanm
	cpan -i App::cpanminus
fi

cpanm -L "${plEnvDir}" --self-upgrade
cpanm -L "${plEnvDir}" --installdeps "${umdir}"
cpanm -L "${plEnvDir}" 'https://github.com/jmfernandez/Dancer2-Plugin-CSRF.git@1.02' 'https://github.com/jmfernandez/perl5-authen-cas-external.git@v0.80-fix'
