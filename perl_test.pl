#!/usr/bin/perl
# 
# I know that Digest::MD5::M4p works. Thus I can use it as a reference
# implementation. This perl script will hash the first command line
# param with the M4p version of MD5, and print it on stdout, so you
# can compare output.
#

use warnings;
use strict;
use Digest::MD5::M4p;

my $input = shift
  or die "a single command line param is needed\n";

my $hasher = Digest::MD5::M4p->new;
$hasher->add( $input );
print $hasher->hexdigest."\n";
