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


instEnvDir="${umdir}/.inst"
export PERL_LOCAL_LIB_ROOT="${instEnvDir}:$PERL_LOCAL_LIB_ROOT"
export PERL_MB_OPT="--install_base ${instEnvDir}"
export PERL_MM_OPT="INSTALL_BASE='${instEnvDir}'"
export PERL5LIB="${instEnvDir}/lib/perl5:$PERL5LIB"
export PATH="${instEnvDir}/bin:$PATH"
#( echo ; echo ) | cpan
#(echo o conf prerequisites_policy follow;echo o conf commit) | cpan

# Is carton already installed?
type -P carton >& /dev/null
if [ $? -ne 0 ] ; then
	perl -MExtUtils::MakeMaker -e 'exit 0'
	if [ $? -ne 0 ] ; then
		# It has a failing test in Docker build
		cpan -f ExtUtils::MakeMaker
	fi
	for m in local::lib LWP::Protocol::https ; do
		perl -M'${m}' -e 'exit 0'
		if [ $? -ne 0 ] ; then
			# Updated CPAN or Carton need this
			cpan -i "${m}"
		fi
	done
	for A in CPAN Carton ; do
		# Updating or installing
		cpan -i "$A"
	done
fi

plEnvDir="${umdir}/.plEnv"
export PERL_LOCAL_LIB_ROOT="${plEnvDir}:$PERL_LOCAL_LIB_ROOT"
export PERL_MB_OPT="--install_base ${plEnvDir}"
export PERL_MM_OPT="INSTALL_BASE='${plEnvDir}'"
export PERL5LIB="${plEnvDir}/lib/perl5:$PERL5LIB"
export PATH="${plEnvDir}/bin:$PATH"

#cpanm -L "${plEnvDir}" --self-upgrade
#cpanm -L "${plEnvDir}" --installdeps "${umdir}"
#cpanm -L "${plEnvDir}" 'https://github.com/jmfernandez/Dancer2-Plugin-CSRF.git@1.02' 'https://github.com/jmfernandez/perl5-authen-cas-external.git@v0.80-fix'

cd "${umdir}" && carton install -p "${plEnvDir}" --deployment
