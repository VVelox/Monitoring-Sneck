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
# restarts, defaults and options
#
{
    my $config = parse_raw( "a|/bin/true\nb|/bin/true\n"
            . "\@plain|checks=a|/usr/sbin/service foo restart | /bin/cat\n"
            . "\@full|checks=a,b threshold=2 depends=plain cascade=1 ignore_unknown=0 ignore_errored=0"
            . " min_interval=0 max_retries=3 timeout=60|  /usr/sbin/service bar restart\n"
            . "\@tabbed|\tchecks=b\t\ttimeout=5 |/bin/true\n" );
    ok( $config->is_valid, 'restarts valid' ) or diag( explain( error_list($config) ) );
    is_deeply(
        $config->restarts,
        {
            plain => {
                command        => '/usr/sbin/service foo restart | /bin/cat',
                checks         => ['a'],
                depends        => [],
                threshold      => 1,
                cascade        => 0,
                ignore_unknown => 1,
                ignore_errored => 1,
                min_interval   => 180,
                max_retries    => 0,
                timeout        => 30,
            },
            full => {
                command        => '/usr/sbin/service bar restart',
                checks         => [ 'a', 'b' ],
                depends        => ['plain'],
                threshold      => 2,
                cascade        => 1,
                ignore_unknown => 0,
                ignore_errored => 0,
                min_interval   => 0,
                max_retries    => 3,
                timeout        => 60,
            },
            tabbed => {
                command        => '/bin/true',
                checks         => ['b'],
                depends        => [],
                threshold      => 1,
                cascade        => 0,
                ignore_unknown => 1,
                ignore_errored => 1,
                min_interval   => 180,
                max_retries    => 0,
                timeout        => 5,
            },
        },
        'restarts parsed with defaults filled in, later | kept in command'
    );

    my $restarts = $config->restarts;
    push( @{ $restarts->{full}{checks} }, 'changed' );
    $restarts->{full}{timeout} = 1;
    is_deeply( $config->restarts->{full}{checks}, [ 'a', 'b' ], 'restarts returns a deep copy of lists' );
    is( $config->restarts->{full}{timeout}, 60, 'restarts returns a copy' );
}

#
# restart errors found while parsing
#
{
    my $config = parse_raw( "a|/bin/true\nb|/bin/true\n"
            . "\@ok|checks=a|/bin/true\n"
            . "\@ok|checks=a|/bin/true\n"
            . "\@no_checks|threshold=1|/bin/true\n"
            . "\@empty_checks|checks=|/bin/true\n"
            . "\@bad_option|checks=a bogus=1|/bin/true\n"
            . "\@not_kv|checks=a oops|/bin/true\n"
            . "\@twice|checks=a checks=b|/bin/true\n"
            . "\@bad_names|checks=a,,b-c depends=x.y|/bin/true\n"
            . "\@dupe|checks=a,a|/bin/true\n"
            . "\@bools|checks=a cascade=2 ignore_unknown=yes ignore_errored=-1|/bin/true\n"
            . "\@numbers|checks=a threshold=0 min_interval=-1 max_retries=x timeout=0|/bin/true\n"
            . "\@too_high|checks=a,b threshold=3|/bin/true\n"
            . "\@no_command|checks=a|\n"
            . "\@blank_command|checks=a|   \n"
            . "\@one_pipe|checks=a\n" );
    ok( !$config->is_valid, 'restart errors make config invalid' );
    is_deeply(
        error_list($config),
        [
            '4: restart "ok" is redefined',
            '5: restart "no_checks" has no checks',
            '6: restart "empty_checks" has no checks',
            '7: restart "bad_option" has unknown option "bogus"',
            '8: restart "not_kv" option "oops" is not in the form key=value',
            '9: restart "twice" option "checks" is given more than once',
            '10: restart "bad_names" option "checks" has the invalid name ""',
            '10: restart "bad_names" option "checks" has the invalid name "b-c"',
            '10: restart "bad_names" option "depends" has the invalid name "x.y"',
            '11: restart "dupe" option "checks" lists "a" more than once',
            '12: restart "bools" option "cascade" must be 0 or 1',
            '12: restart "bools" option "ignore_unknown" must be 0 or 1',
            '12: restart "bools" option "ignore_errored" must be 0 or 1',
            '13: restart "numbers" option "max_retries" must be a whole number of at least 0',
            '13: restart "numbers" option "min_interval" must be a whole number of at least 0',
            '13: restart "numbers" option "threshold" must be a whole number of at least 1',
            '13: restart "numbers" option "timeout" must be a whole number of at least 1',
            '14: restart "too_high" threshold of 3 is more than its 2 checks',
            '15: restart "no_command" has no command',
            '16: restart "blank_command" has no command',
            '17: "@one_pipe|checks=a" is not a understood line',
        ],
        'every restart error reported with its line'
    );
    is_deeply( [ sort keys %{ $config->restarts } ], ['ok'], 'only the good restart kept' );
}

#
# restart errors found once everything is parsed
#
{
    my $config = parse_raw( "a|/bin/true\n%dbg|/bin/true\n"
            . "\@watches_missing|checks=a,nope|/bin/true\n"
            . "\@watches_debug|checks=dbg|/bin/true\n"
            . "\@bad_depend|checks=a depends=nope|/bin/true\n"
            . "\@self|checks=a depends=self|/bin/true\n"
            . "\@loop_a|checks=a depends=loop_b|/bin/true\n"
            . "\@loop_b|checks=a depends=loop_c|/bin/true\n"
            . "\@loop_c|checks=a depends=loop_a|/bin/true\n"
            . "\@into_loop|checks=a depends=loop_a|/bin/true\n" );
    is_deeply(
        error_list($config),
        [
            '3: restart "watches_missing" watches unknown check "nope"',
            '4: restart "watches_debug" watches unknown check "dbg", debug checks can not be watched',
            '5: restart "bad_depend" depends on unknown restart "nope"',
            '6: restart "self" has a dependency cycle: self -> self',
            '7: restart "loop_a" has a dependency cycle: loop_a -> loop_b -> loop_c -> loop_a',
            '8: restart "loop_b" has a dependency cycle: loop_b -> loop_c -> loop_a -> loop_b',
            '9: restart "loop_c" has a dependency cycle: loop_c -> loop_a -> loop_b -> loop_c',
        ],
        'unknown checks, unknown depends, and cycles reported, depending on a cycle is not itself a cycle'
    );
}

#
# a restart with its own errors still has its references checked, and is
# still known to restarts that depend on it
#
{
    my $config = parse_raw( "a|/bin/true\n"
            . "\@db|checks=a,nope depends=ghost timeout=0|/bin/true\n"
            . "\@app|checks=a depends=db|/bin/true\n"
            . "\@x|checks=a depends=y bogus=1|/bin/true\n"
            . "\@y|checks=a depends=x|/bin/true\n"
            . "\@not_kv|checks=a,missing oops|/bin/true\n"
            . "\@uses_not_kv|checks=a depends=not_kv|/bin/true\n"
            . "\@bad_again|checks=a timeout=0|/bin/true\n"
            . "\@bad_again|checks=a|/bin/true\n" );
    is_deeply(
        error_list($config),
        [
            '2: restart "db" option "timeout" must be a whole number of at least 1',
            '2: restart "db" watches unknown check "nope"',
            '2: restart "db" depends on unknown restart "ghost"',
            '4: restart "x" has unknown option "bogus"',
            '4: restart "x" has a dependency cycle: x -> y -> x',
            '5: restart "y" has a dependency cycle: y -> x -> y',
            '6: restart "not_kv" option "oops" is not in the form key=value',
            '6: restart "not_kv" watches unknown check "missing"',
            '8: restart "bad_again" option "timeout" must be a whole number of at least 1',
            '9: restart "bad_again" is redefined',
        ],
        'every error found in one pass, no false unknown restart errors'
    );
    is_deeply( [ sort keys %{ $config->restarts } ], [ 'app', 'uses_not_kv', 'y' ], 'restarts leaves out invalid ones' );
}

#
# restarts defined before the checks they watch, and undefined variable warnings
#
{
    my $config = parse_raw( "\@early|checks=late depends=later|/bin/echo %NOPE%\n"
            . "\@later|checks=late|/bin/true\n"
            . "late|/bin/true\n" );
    ok( $config->is_valid, 'restarts may come before what they reference' );
    is_deeply( warning_list($config), ['1: restart "early" uses undefined variable "NOPE"'], 'restart command warned about' );
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
