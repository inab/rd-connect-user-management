#!/bin/sh

set -e

export PERL_LOCAL_LIB_ROOT="$PERL_LOCAL_LIB_ROOT:${HOME}/perl5"
export PERL_MB_OPT="--install_base ${HOME}/perl5"
export PERL_MM_OPT="INSTALL_BASE=""${HOME}""/perl5"
export PERL5LIB="${HOME}/perl5/lib/perl5:$PERL5LIB"
export PATH="${HOME}/perl5/bin:$PATH"
#( echo ; echo ) | cpan
#(echo o conf prerequisites_policy follow;echo o conf commit) | cpan

# It has a failing test

cpan -f ExtUtils::MakeMaker
cpan -i local::lib
# CPAN needs local::lib
cpan -i CPAN App::cpanminus

cpanm --installdeps .
