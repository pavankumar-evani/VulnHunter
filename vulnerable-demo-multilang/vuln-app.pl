#!/usr/bin/perl
# vuln-app.pl - a deliberately vulnerable demo Perl CGI script used ONLY to test
# VulnHunter's multi-language scanner coverage. DO NOT deploy this anywhere. It
# contains intentional security flaws for demonstration purposes only.
#
# Planted vulnerabilities (for scoring / demo reference):
#   1. Command injection via backticks with interpolated var -> CWE-78
#   2. eval() on untrusted input                              -> CWE-95
#   3. Hardcoded credential                                    -> CWE-798

use strict;
use warnings;
use CGI qw(:standard);

# VULN 3: Hardcoded credential (CWE-798) - should come from an environment variable
# or a secrets manager, not be committed in source.
my $DB_PASSWORD = "SuperSecretP@ss123";
my $DB_USER     = "vulnshop_admin";

my $cgi = CGI->new;

# VULN 1: Command injection (CWE-78) - the user-controlled "host" param is interpolated
# directly into a backtick shell command, letting an attacker inject shell metacharacters.
sub ping_host {
    my $host = $cgi->param('host') || '127.0.0.1';
    my $output = `ping -c 1 $host`;
    return $output;
}

# VULN 2: eval() on untrusted input (CWE-95) - a string built from user input is passed
# straight to Perl's string eval, allowing arbitrary code execution.
sub calc {
    my $expr = $cgi->param('expr') || '0';
    my $result = eval "$expr";
    return $result;
}

print $cgi->header('text/plain');

if (defined $cgi->param('host')) {
    print ping_host();
}

if (defined $cgi->param('expr')) {
    print calc();
}
