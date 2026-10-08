#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);

BEGIN {
    use_ok('Monitoring::Sneck::Config') || print "Bail out!\n";
}

sub write_config {
    my ($content) = @_;
    my ( $fh, $filename ) = tempfile( UNLINK => 1, SUFFIX => '.conf' );
    print $fh $content;
    close $fh;
    return $filename;
}

# Parses a config string.
sub parse_raw {
    my ($content) = @_;
    return Monitoring::Sneck::Config->new( { raw => $content } );
}

# Returns the errors as "line: message" strings for easy comparison.
sub error_list {
    my ($config) = @_;
    return [ map { $_->{line} . ': ' . $_->{message} } $config->errors ];
}

# Returns the warnings as "line: message" strings for easy comparison.
sub warning_list {
    my ($config) = @_;
    return [ map { $_->{line} . ': ' . $_->{message} } $config->warnings ];
}

#
# new() argument handling
#
{
    eval { Monitoring::Sneck::Config->new() };
    like( $@, qr/Neither file nor raw specified/, 'new dies with no args' );

    eval { Monitoring::Sneck::Config->new( {} ) };
    like( $@, qr/Neither file nor raw specified/, 'new dies with empty hash' );

    eval { Monitoring::Sneck::Config->new( { file => '/nonexistent/path/sneck.conf' } ) };
    like( $@, qr/^Failed to read in the config file "\/nonexistent\/path\/sneck\.conf"/, 'new dies on unreadable file' );

    my $content = "FOO=bar\n";
    my $cfg     = write_config($content);
    my $config  = Monitoring::Sneck::Config->new( { file => $cfg } );
    is( $config->file, $cfg,     'file returns the path' );
    is( $config->raw,  $content, 'raw returns the file contents' );
    is( $config->vars->{FOO}, 'bar', 'file is parsed' );

    $config = Monitoring::Sneck::Config->new( { file => $cfg, raw => "BAZ=qux\n" } );
    is( $config->raw, "BAZ=qux\n", 'raw used over file when both given' );
    ok( !exists $config->vars->{FOO}, 'file ignored when raw given' );

    $config = parse_raw("FOO=bar\n");
    ok( !defined $config->file, 'file is undef when created from raw' );
    is( $config->format, 'sneck', 'raw defaults to the sneck format' );

    $config = Monitoring::Sneck::Config->new( { file => $cfg } );
    is( $config->format, 'sneck', 'file without a YAML extension is the sneck format' );

    eval { Monitoring::Sneck::Config->new( { raw => "FOO=bar\n", format => 'ini' } ) };
    like( $@, qr/^Unknown format "ini"/, 'new dies on unknown format' );
}

#
# empty, comment-only, and blank configs
#
{
    foreach my $content ( '', "# comment\n\n   # indented comment\n", "\n\n  \n\t\n" ) {
        my $config = parse_raw($content);
        ok( $config->is_valid, 'valid: ' . join( '\n', split( /\n/, $content ) ) );
        is_deeply( $config->checks, {}, 'no checks' );
        is_deeply( $config->debugs, {}, 'no debugs' );
        is_deeply( $config->vars,   {}, 'no vars' );
        is_deeply( $config->env,    [], 'no env' );
        is_deeply( [ $config->errors ],   [], 'no errors' );
        is_deeply( [ $config->warnings ], [], 'no warnings' );
    }
}

#
# variables
#
{
    my $config = parse_raw("FOO=bar\nCONNSTR=host=localhost port=5432\nEMPTY=\n");
    ok( $config->is_valid, 'variables valid' );
    is_deeply(
        $config->vars,
        { FOO => 'bar', CONNSTR => 'host=localhost port=5432', EMPTY => '' },
        'variables parsed, = in value kept, empty value allowed'
    );

    $config = parse_raw("FOO=first\nFOO=second\n");
    ok( !$config->is_valid, 'redefined variable is invalid' );
    is_deeply( error_list($config), ['2: variable "FOO" is redefined'], 'redefined variable error' );
    is( $config->vars->{FOO}, 'first', 'first definition kept' );
}

#
# env lines
#
{
    delete $ENV{SNECK_CONFIG_T_ENV};
    my $config = parse_raw( "env SNECK_CONFIG_T_ENV=one\n"
            . "ENV PATH_ISH=/bin:/usr/bin\n"
            . "Env EMPTY_ONE=\n"
            . "env SNECK_CONFIG_T_ENV=two\n" );
    ok( $config->is_valid, 'env lines valid, redefining env allowed' );
    is_deeply(
        $config->env,
        [ [ 'SNECK_CONFIG_T_ENV', 'one' ], [ 'PATH_ISH', '/bin:/usr/bin' ], [ 'EMPTY_ONE', '' ], [ 'SNECK_CONFIG_T_ENV', 'two' ] ],
        'env lines kept in order, case insensitive, empty allowed'
    );
    ok( !exists $ENV{SNECK_CONFIG_T_ENV}, 'env lines not applied to %ENV' );
    is_deeply( $config->vars, {}, 'env lines are not variables' );
}

#
# checks and debug checks
#
{
    my $config = parse_raw( "plain|/bin/true\n"
            . "spaced|   /bin/true arg\n"
            . "tabbed|\t\t/bin/false\n"
            . "piped|/bin/echo a | /bin/cat\n"
            . "%dbg|/bin/true\n"
            . "%plain|/bin/echo debug\n" );
    ok( $config->is_valid, 'checks valid' );
    is_deeply(
        $config->checks,
        { plain => '/bin/true', spaced => '/bin/true arg', tabbed => '/bin/false', piped => '/bin/echo a | /bin/cat' },
        'checks parsed, leading whitespace stripped, later | kept'
    );
    is_deeply( $config->debugs, { dbg => '/bin/true', plain => '/bin/echo debug' }, 'debugs parsed without the %' );
}

#
# check errors
#
{
    my $config = parse_raw( "chk|/bin/true\n"
            . "chk|/bin/false\n"
            . "%dbg|/bin/true\n"
            . "%dbg|/bin/false\n"
            . "empty|\n"
            . "blank|   \t \n"
            . "%empty_dbg|\n"
            . "%%double|/bin/true\n" );
    ok( !$config->is_valid, 'check errors make config invalid' );
    is_deeply(
        error_list($config),
        [
            '2: check "chk" is redefined',
            '4: debug check "dbg" is redefined',
            '5: check "empty" has no command',
            '6: check "blank" has no command',
            '7: debug check "empty_dbg" has no command',
            '8: "%%double|/bin/true" is not a understood line',
        ],
        'every check error reported with its line'
    );
    is( $config->checks->{chk}, '/bin/true', 'first check definition kept' );
    is( $config->debugs->{dbg}, '/bin/true', 'first debug definition kept' );
}

#
# unknown lines, every error reported, error fields
#
{
    my $config = parse_raw("FOO=bar\nthis is not valid\nok|/bin/true\nFOO =bar\nname |cmd\n");
    ok( !$config->is_valid, 'unknown lines make config invalid' );
    is_deeply(
        error_list($config),
        [
            '2: "this is not valid" is not a understood line',
            '4: "FOO =bar" is not a understood line',
            '5: "name |cmd" is not a understood line',
        ],
        'every unknown line reported'
    );
    is_deeply( $config->checks, { ok => '/bin/true' }, 'good lines still parsed around errors' );

    $config = parse_raw("  \tbad line\n");
    my ($error) = $config->errors;
    is_deeply(
        $error,
        {
            where   => 'line 1',
            line    => 1,
            path    => undef,
            text    => "  \tbad line",
            message => '"bad line" is not a understood line'
        },
        'error hash has where, line, original text, and message'
    );
}

#
# leading whitespace on every line type
#
{
    my $config = parse_raw("  \tFOO=bar\n\t  chk|/bin/true\n   # comment\n\t%dbg|/bin/true\n  env WS=1\n");
    ok( $config->is_valid, 'leading whitespace valid' );
    is( $config->vars->{FOO},   'bar',       'indented variable' );
    is( $config->checks->{chk}, '/bin/true', 'indented check' );
    is( $config->debugs->{dbg}, '/bin/true', 'indented debug check' );
    is_deeply( $config->env, [ [ 'WS', '1' ] ], 'indented env' );
}

#
# CRLF line endings
#
{
    my $config = parse_raw("FOO=bar\r\n\r\n# comment\r\nchk|/bin/true\r\n%dbg|/bin/true\r\nenv E=1\r\n");
    ok( $config->is_valid, 'CRLF config valid, including blank CRLF line' );
    is( $config->vars->{FOO},   'bar',       'CRLF stripped from variable' );
    is( $config->checks->{chk}, '/bin/true', 'CRLF stripped from check' );
    is( $config->debugs->{dbg}, '/bin/true', 'CRLF stripped from debug check' );
    is_deeply( $config->env, [ [ 'E', '1' ] ], 'CRLF stripped from env' );

    $config = parse_raw("FOO=bar\r\nbad\r\n");
    is_deeply( error_list($config), ['2: "bad" is not a understood line'], 'CRLF line numbers and text correct' );
}

#
# no trailing newline
#
{
    my $config = parse_raw("FOO=bar\nlast|/bin/true");
    ok( $config->is_valid, 'no trailing newline valid' );
    is( $config->checks->{last}, '/bin/true', 'last line parsed' );
}

#
# undefined variable warnings
#
{
    my $config = parse_raw( "chk|/bin/echo %DEFINED_LATER%\n"
            . "date_check|/bin/date +%Y%m%d\n"
            . "%dbg|/bin/echo %NOPE% %NOPE%\n"
            . "pct|/check -w 80% -c 90%\n"
            . "DEFINED_LATER=yes\n" );
    ok( $config->is_valid, 'undefined variables do not make config invalid' );
    is_deeply(
        warning_list($config),
        [
            '2: check "date_check" uses undefined variable "Y"',
            '2: check "date_check" uses undefined variable "m"',
            '3: debug check "dbg" uses undefined variable "NOPE"',
        ],
        'undefined variables warned once each, variables defined later are fine'
    );
    my ($warning) = $config->warnings;
    is( $warning->{text}, 'date_check|/bin/date +%Y%m%d', 'warning has the original text' );
}

#
# substitute
#
{
    my $config = parse_raw( "MYVAR=world\n" . 'ODD=a$b\\c' . "\n" );
    is( $config->substitute('%MYVAR%'),         'world',       'single variable' );
    is( $config->substitute('%%MYVAR%%'),       'world',       'doubled % variable' );
    is( $config->substitute('%MYVAR% %MYVAR%'), 'world world', 'repeated variable' );
    is( $config->substitute('%NOPE%'),          '%NOPE%',      'undefined variable left as written' );
    is( $config->substitute('x %ODD% y'),       'x a$b\\c y',  'value with $ and \\ put in literally' );
    is( $config->substitute('no vars'),         'no vars',     'string with no variables unchanged' );
}

#
# accessors return copies
#
{
    my $config = parse_raw("FOO=bar\nchk|/bin/true\n%dbg|/bin/true\nenv E=1\n");
    $config->vars->{FOO}     = 'changed';
    $config->checks->{chk}   = 'changed';
    $config->debugs->{dbg}   = 'changed';
    $config->env->[0][1]     = 'changed';
    is( $config->vars->{FOO},   'bar',       'vars returns a copy' );
    is( $config->checks->{chk}, '/bin/true', 'checks returns a copy' );
    is( $config->debugs->{dbg}, '/bin/true', 'debugs returns a copy' );
    is( $config->env->[0][1],   '1',         'env returns a copy' );
}

done_testing();
