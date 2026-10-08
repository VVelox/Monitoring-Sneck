#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);

BEGIN {
    use_ok('Monitoring::Sneck') || print "Bail out!\n";
}

# Helper: write a temp config file with given content, return path
sub write_config {
    my ($content) = @_;
    my ( $fh, $filename ) = tempfile( UNLINK => 1, SUFFIX => '.conf' );
    print $fh $content;
    close $fh;
    return $filename;
}

#
# new() with missing config file
#
{
    my $sneck = Monitoring::Sneck->new( { config => '/nonexistent/path/sneck.conf' } );
    ok( defined $sneck, 'new returns object even with missing config' );
    is( $sneck->{good}, 0, 'good is false when config file missing' );
    is( $sneck->{to_return}{error}, 1, 'error flag set when config file missing' );
    like(
        $sneck->{to_return}{errorString},
        qr/Failed to read/,
        'errorString mentions read failure'
    );
}

#
# new() with valid minimal config (only comments and blank lines)
#
{
    my $cfg = write_config("# just a comment\n\n# another comment\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for comment-only config' );
    is( $sneck->{to_return}{error}, 0, 'no error for comment-only config' );
}

#
# Variable parsing
#
{
    my $cfg = write_config("FOO=bar\nBAZ=qux\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for variable config' );
    is( $sneck->{vars}{FOO}, 'bar', 'variable FOO parsed correctly' );
    is( $sneck->{vars}{BAZ}, 'qux', 'variable BAZ parsed correctly' );
}

#
# Variable with = in value
#
{
    my $cfg = write_config("CONNSTR=host=localhost port=5432\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for variable with = in value' );
    is( $sneck->{vars}{CONNSTR}, 'host=localhost port=5432', 'variable value with = preserved' );
}

#
# Redefined variable → error
#
{
    my $cfg = write_config("FOO=first\nFOO=second\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 0, 'good is false when variable redefined' );
    is( $sneck->{to_return}{error}, 1, 'error set when variable redefined' );
    like( $sneck->{to_return}{errorString}, qr/redefined/, 'errorString mentions redefined' );
}

#
# Check definition parsed
#
{
    my $cfg = write_config("mycheck|/bin/true\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true when check defined' );
    is( $sneck->{checks}{mycheck}, '/bin/true', 'check command stored correctly' );
}

#
# Redefined check → error
#
{
    my $cfg = write_config("mycheck|/bin/true\nmycheck|/bin/false\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 0, 'good is false when check redefined' );
    is( $sneck->{to_return}{error}, 1, 'error set when check redefined' );
}

#
# Unknown line → error
#
{
    my $cfg = write_config("this is not valid\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 0, 'good is false for unknown line' );
    is( $sneck->{to_return}{error}, 1, 'error set for unknown line' );
    like( $sneck->{to_return}{errorString}, qr/not a understood line/, 'errorString mentions unrecognized line' );
}

#
# Debug check (% prefix) parsed into checks hash
#
{
    my $cfg = write_config("%dbgcheck|/bin/true\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true when debug check defined' );
    ok( defined $sneck->{checks}{'%dbgcheck'}, 'debug check stored with % prefix' );
}

#
# env line sets %ENV
#
{
    my $cfg = write_config("env SNECK_TEST_VAR=hello_world\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for env line' );
    is( $ENV{SNECK_TEST_VAR}, 'hello_world', 'env line sets %ENV variable' );
}

#
# include option includes raw config in return
#
{
    my $content = "FOO=bar\n";
    my $cfg     = write_config($content);
    my $sneck   = Monitoring::Sneck->new( { config => $cfg, include => 1 } );
    is( $sneck->{good}, 1, 'good true with include option' );
    is( $sneck->{to_return}{data}{config}, $content, 'raw config included in return data' );
}

#
# include=0 does not include raw config
#
{
    my $cfg   = write_config("FOO=bar\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg, include => 0 } );
    ok( !defined $sneck->{to_return}{data}{config}, 'raw config not included when include=0' );
}

#
# leading whitespace is stripped from every line type
#
{
    my $cfg = write_config( "  \tFOO=bar\n"
            . "\t  ws_check|/bin/true\n"
            . "   # indented comment\n"
            . "\t%ws_dbg|/bin/true\n"
            . "  env SNECK_WS_TEST=ws\n" );
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true with leading whitespace' );
    is( $sneck->{vars}{FOO}, 'bar', 'indented variable parsed' );
    is( $sneck->{checks}{ws_check}, '/bin/true', 'indented check parsed' );
    ok( defined $sneck->{checks}{'%ws_dbg'}, 'indented debug check parsed' );
    is( $ENV{SNECK_WS_TEST}, 'ws', 'indented env line parsed' );
}

#
# leading whitespace is stripped from the check command
#
{
    my $cfg = write_config("spaced|   /bin/true\ntabbed|\t\t/bin/false\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{checks}{spaced}, '/bin/true',  'leading spaces stripped from check command' );
    is( $sneck->{checks}{tabbed}, '/bin/false', 'leading tabs stripped from check command' );
}

#
# env is case insensitive and allows an empty value
#
{
    my $cfg = write_config("ENV SNECK_UC_TEST=upper\nEnv SNECK_MC_TEST=mixed\nenv SNECK_EMPTY_TEST=\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for env case variants' );
    is( $ENV{SNECK_UC_TEST},    'upper', 'ENV line sets %ENV' );
    is( $ENV{SNECK_MC_TEST},    'mixed', 'Env line sets %ENV' );
    is( $ENV{SNECK_EMPTY_TEST}, '',      'env line with no value sets empty string' );
}

#
# variable with no value is an empty string
#
{
    my $cfg   = write_config("FOO=\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for empty variable' );
    is( $sneck->{vars}{FOO}, '', 'empty variable value is empty string' );
}

#
# empty config file
#
{
    my $cfg   = write_config('');
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for empty file' );
    is_deeply( $sneck->{checks}, {}, 'no checks for empty file' );
}

#
# config with no trailing newline
#
{
    my $cfg   = write_config("FOO=bar\nlast_check|/bin/true");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true with no trailing newline' );
    is( $sneck->{checks}{last_check}, '/bin/true', 'last line parsed with no trailing newline' );
}

#
# CRLF line endings
#
# This locks in the current behavior. The \r is not stripped, so it ends up in
# values and commands, and a blank CRLF line is not understood.
#
{
    my $cfg   = write_config("FOO=bar\r\ncrlf_check|/bin/true\r\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'good is true for CRLF config' );
    is( $sneck->{vars}{FOO}, "bar\r", 'CRLF variable value keeps the \r' );
    is( $sneck->{checks}{crlf_check}, "/bin/true\r", 'CRLF check command keeps the \r' );

    $cfg   = write_config("FOO=bar\r\n\r\n");
    $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 0, 'blank CRLF line is an error' );
}

#
# redefined check error message
#
{
    my $cfg   = write_config("mycheck|/bin/true\nmycheck|/bin/false\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    like(
        $sneck->{to_return}{errorString},
        qr/check "mycheck" is defined on the line "mycheck\|\/bin\/false"/,
        'errorString names the redefined check and line'
    );
}

#
# a check and a debug check may share a name
#
{
    my $cfg   = write_config("shared|/bin/true\n%shared|/bin/true\n");
    my $sneck = Monitoring::Sneck->new( { config => $cfg } );
    is( $sneck->{good}, 1, 'check and debug check can share a name' );
}

#
# default config path
#
{
    my $sneck = Monitoring::Sneck->new();
    is( $sneck->{config}, '/usr/local/etc/sneck.conf', 'default config path used with no args' );
    $sneck = Monitoring::Sneck->new( {} );
    is( $sneck->{config}, '/usr/local/etc/sneck.conf', 'default config path used with empty hash' );
}

done_testing();
