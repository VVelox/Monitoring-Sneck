#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON       qw(decode_json);
use Time::HiRes ();

BEGIN {
    use_ok('Monitoring::Sneck') || print "Bail out!\n";
}

if ( $^O eq 'MSWin32' ) {
    done_testing();
    exit 0;
}

my $perl       = $^X;
my $dir        = tempdir( CLEANUP => 1 );
my $log        = $dir . '/restart.log';
my $state_file = $dir . '/state.json';

# Writes a file with the given content.
sub write_file {
    my ( $file, $content ) = @_;
    open( my $fh, '>', $file ) or die( 'failed to write "' . $file . '"... ' . $! );
    print $fh $content;
    close($fh);
    return $file;
}

# Reads a file, returning undef if it does not exist.
sub read_file {
    my ($file) = @_;
    open( my $fh, '<', $file ) or return undef;
    local $/;
    my $content = <$fh>;
    close($fh);
    return $content;
}

# check.pl exits with the number in its flag file, or 0 if there is none.
my $check_script = write_file( $dir . '/check.pl', <<'END' );
my $flag = shift;
my $code = 0;
if ( open( my $fh, '<', $flag ) ) { $code = <$fh>; chomp($code); }
print "check output\n";
exit $code;
END

# restart.pl logs its name, then exits with the given code.
my $restart_script = write_file( $dir . '/restart.pl', <<'END' );
my ( $name, $log, $code, $sleep ) = @ARGV;
open( my $fh, '>>', $log ) or die($!);
print $fh $name . "\n";
close($fh);
print "restarted " . $name . "\n";
sleep($sleep) if $sleep;
exit $code;
END

# hang.pl prints some output, then writes a marker after 3 seconds.
my $hang_script = write_file( $dir . '/hang.pl', <<'END' );
my $marker = shift;
$| = 1;
print "partial output\n";
sleep 3;
open( my $fh, '>', $marker );
exit 0;
END

# daemon.pl starts a child that keeps stdout open for 5 seconds, then exits right away.
my $daemon_script = write_file( $dir . '/daemon.pl', <<'END' );
if ( !fork() ) {
    sleep 5;
    exit 0;
}
print "started\n";
exit 0;
END

# Sets what a check exits with on its next run. undef means ok.
sub set_check {
    my ( $name, $code ) = @_;
    my $flag = $dir . '/' . $name . '.flag';
    if ( defined($code) ) {
        write_file( $flag, $code );
    } else {
        unlink($flag);
    }
    return;
}

# Returns a config line for a check controlled by set_check.
sub check_line {
    my ($name) = @_;
    return $name . '|' . $perl . ' ' . $check_script . ' ' . $dir . '/' . $name . ".flag\n";
}

# Returns a config line for a restart that logs its name and exits with the given code.
sub restart_line {
    my ( $name, $options, $exit_code, $sleep ) = @_;
    return
          '@'
        . $name . '|'
        . $options . '|'
        . $perl . ' '
        . $restart_script . ' '
        . $name . ' '
        . $log . ' '
        . ( defined($exit_code) ? $exit_code : 0 )
        . ( $sleep ? ' ' . $sleep : '' ) . "\n";
}

# Returns the names logged by restarts since the last reset.
sub restarts_logged {
    my $content = read_file($log);
    return [] if !defined($content);
    return [ split( /\n/, $content ) ];
}

# Clears the restart log, state file, and check flags.
sub reset_all {
    unlink( $log, $state_file );
    unlink( glob( $dir . '/*.flag' ) );
    return;
}

# Creates a Monitoring::Sneck with restarts enabled and the test state file.
sub new_sneck {
    my ( $config, %args ) = @_;
    my $cfg = write_file( $dir . '/sneck.conf', $config );
    return Monitoring::Sneck->new( { config => $cfg, state_file => $state_file, restart => 1, %args } );
}

#
# no restarts configured
#
{
    reset_all();
    my $ret = new_sneck( check_line('c1') )->run;
    is_deeply( $ret->{data}{restarts}, {}, 'restarts empty when none configured' );
    is( $ret->{data}{restarted}, 0, 'restarted 0 when none configured' );
    ok( !-e $state_file, 'state file not created when none configured' );
}

#
# restarts disabled
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $ret = new_sneck( check_line('c1') . restart_line( 'r1', 'checks=c1' ), restart => 0 )->run;
    my $r1 = $ret->{data}{restarts}{r1};
    is( $r1->{reason},    'restarts disabled', 'reason when restarts disabled' );
    is( $r1->{triggered}, 1,                   'triggered still worked out when disabled' );
    is( $r1->{ran},       0,                   'not ran when disabled' );
    is_deeply( $r1->{failed_checks}, ['c1'], 'failed checks still listed when disabled' );
    is_deeply( restarts_logged(), [], 'nothing restarted when disabled' );
    ok( !-e $state_file, 'state file not touched when disabled' );
}

#
# what counts as failed
#
{
    reset_all();
    set_check( 'c_warn', 1 );
    set_check( 'c_crit', 2 );
    set_check( 'c_unk',  3 );
    set_check( 'c_err',  5 );
    my $config
        = check_line('c_warn')
        . check_line('c_crit')
        . check_line('c_unk')
        . check_line('c_err')
        . "c_missing|/nonexistent/sneck_check\n"
        . restart_line( 'r_warn',           'checks=c_warn' )
        . restart_line( 'r_crit',           'checks=c_crit' )
        . restart_line( 'r_unk',            'checks=c_unk' )
        . restart_line( 'r_unk_counted',    'checks=c_unk ignore_unknown=0' )
        . restart_line( 'r_err',            'checks=c_err' )
        . restart_line( 'r_err_counted',    'checks=c_err ignore_errored=0' )
        . restart_line( 'r_missing',        'checks=c_missing' )
        . restart_line( 'r_missing_counted', 'checks=c_missing ignore_errored=0' );
    my $ret = new_sneck($config)->run;
    my %triggered = map { $_ => $ret->{data}{restarts}{$_}{triggered} } keys( %{ $ret->{data}{restarts} } );
    is_deeply(
        \%triggered,
        {
            r_warn            => 0,
            r_crit            => 1,
            r_unk             => 0,
            r_unk_counted     => 1,
            r_err             => 0,
            r_err_counted     => 1,
            r_missing         => 0,
            r_missing_counted => 1,
        },
        'critical triggers, warning never does, unknown and errored only when not ignored'
    );
    is_deeply(
        restarts_logged(),
        [ 'r_crit', 'r_err_counted', 'r_missing_counted', 'r_unk_counted' ],
        'triggered restarts ran in name order'
    );
    is( $ret->{data}{restarted}, 4, 'restarted count' );
    is( $ret->{data}{restarts}{r_crit}{reason}, 'threshold', 'reason is threshold' );
    is( $ret->{data}{restarts}{r_warn}{reason}, 'not triggered', 'reason is not triggered' );
}

#
# threshold
#
{
    reset_all();
    my $config
        = check_line('a')
        . check_line('b')
        . check_line('c')
        . restart_line( 'r', 'checks=a,b,c threshold=2 min_interval=0' );
    my $sneck = new_sneck($config);

    set_check( 'a', 2 );
    my $ret = $sneck->run;
    is( $ret->{data}{restarts}{r}{triggered}, 0, 'one of three failing does not meet threshold 2' );
    is_deeply( $ret->{data}{restarts}{r}{failed_checks}, ['a'], 'failed checks listed below threshold' );
    is( $ret->{data}{restarts}{r}{threshold}, 2, 'threshold in output' );

    set_check( 'b', 2 );
    $ret = $sneck->run;
    is( $ret->{data}{restarts}{r}{triggered}, 1, 'two of three failing meets threshold 2' );
    is_deeply( $ret->{data}{restarts}{r}{failed_checks}, [ 'a', 'b' ], 'failed checks listed in config order' );
    is_deeply( restarts_logged(), ['r'], 'restart ran once threshold met' );
}

#
# depends only order restarts
#
{
    reset_all();
    my $config
        = check_line('app_check')
        . check_line('db_check')
        . restart_line( 'a_app', 'checks=app_check depends=z_db' )
        . restart_line( 'z_db',  'checks=db_check' );

    set_check( 'app_check', 2 );
    set_check( 'db_check',  2 );
    my $ret = new_sneck($config)->run;
    is_deeply( restarts_logged(), [ 'z_db', 'a_app' ], 'depend runs first when both trigger' );

    reset_all();
    set_check( 'app_check', 2 );
    $ret = new_sneck($config)->run;
    is_deeply( restarts_logged(), ['a_app'], 'passing depend is not restarted' );
    is( $ret->{data}{restarts}{z_db}{reason}, 'not triggered', 'passing depend reason' );

    reset_all();
    set_check( 'db_check', 2 );
    $ret = new_sneck($config)->run;
    is_deeply( restarts_logged(), ['z_db'], 'dependent not restarted without cascade' );
}

#
# cascade
#
{
    reset_all();
    set_check( 'db_check', 2 );
    my $config
        = check_line('app_check')
        . check_line('db_check')
        . restart_line( 'a_app', 'checks=app_check depends=z_db cascade=1' )
        . restart_line( 'z_db',  'checks=db_check' );
    my $ret = new_sneck($config)->run;
    is_deeply( restarts_logged(), [ 'z_db', 'a_app' ], 'cascade restarts dependent after depend' );
    is( $ret->{data}{restarts}{a_app}{reason},    'cascade from z_db', 'cascade reason' );
    is( $ret->{data}{restarts}{a_app}{triggered}, 0,                   'cascaded restart not triggered itself' );
    is( $ret->{data}{restarts}{a_app}{ran},       1,                   'cascaded restart ran' );
    is( $ret->{data}{restarted},                  2,                   'cascade counted in restarted' );

    reset_all();
    set_check( 'db_check', 2 );
    $config
        = check_line('app_check')
        . check_line('db_check')
        . restart_line( 'a_app', 'checks=app_check depends=z_db cascade=1' )
        . restart_line( 'z_db',  'checks=db_check', 1 );
    $ret = new_sneck($config)->run;
    is_deeply( restarts_logged(), ['z_db'], 'no cascade from a failed depend' );

    # cascade does not count towards max_retries
    reset_all();
    set_check( 'db_check', 2 );
    $config
        = check_line('app_check')
        . check_line('db_check')
        . restart_line( 'a_app', 'checks=app_check depends=z_db cascade=1 min_interval=0 max_retries=1' )
        . restart_line( 'z_db',  'checks=db_check min_interval=0' );
    my $sneck = new_sneck($config);
    $sneck->run foreach ( 1 .. 3 );
    is_deeply( restarts_logged(), [ ( 'z_db', 'a_app' ) x 3 ], 'cascade ignores max_retries' );
}

#
# failed depends
#
{
    reset_all();
    set_check( 'app_check', 2 );
    set_check( 'db_check',  2 );
    set_check( 'web_check', 2 );
    my $config
        = check_line('app_check')
        . check_line('db_check')
        . check_line('web_check')
        . restart_line( 'app', 'checks=app_check depends=db' )
        . restart_line( 'db',  'checks=db_check', 1 )
        . restart_line( 'web', 'checks=web_check depends=app' );
    my $ret = new_sneck($config)->run;
    is_deeply( restarts_logged(), ['db'], 'dependents of a failed restart do not run' );
    is( $ret->{data}{restarts}{app}{reason}, 'skipped, dependency db failed',  'skipped for failed depend' );
    is( $ret->{data}{restarts}{web}{reason}, 'skipped, dependency app failed', 'skip carries down the chain' );
    is( $ret->{data}{restarts}{db}{exit}, 1, 'failed restart exit stored' );
    is( $ret->{data}{alert}, 1, 'failed restart sets alert' );
    like( $ret->{data}{alertString}, qr/^restart "db" failed, exit 1: restarted db$/m, 'failed restart and its output in alertString' );
}

#
# a depend held back by cooldown is not a failure
#
{
    reset_all();
    set_check( 'app_check', 2 );
    set_check( 'db_check',  2 );
    my $config
        = check_line('app_check')
        . check_line('db_check')
        . restart_line( 'app', 'checks=app_check depends=db min_interval=0' )
        . restart_line( 'db',  'checks=db_check' );
    my $sneck = new_sneck($config);
    $sneck->run;
    my $ret = $sneck->run;
    is_deeply( restarts_logged(), [ 'db', 'app', 'app' ], 'dependent runs while depend is in cooldown' );
    like( $ret->{data}{restarts}{db}{reason}, qr/^cooldown, \d+ seconds left$/, 'depend reason is cooldown' );
}

#
# min_interval
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $sneck = new_sneck( check_line('c1') . restart_line( 'r1', 'checks=c1' ) );
    my $ret   = $sneck->run;
    is( $ret->{data}{restarts}{r1}{ran}, 1, 'first run restarts' );
    $ret = $sneck->run;
    is( $ret->{data}{restarts}{r1}{ran}, 0, 'second run held back by default min_interval' );
    like( $ret->{data}{restarts}{r1}{reason}, qr/^cooldown, (1[0-7][0-9]|180) seconds left$/, 'cooldown reason' );
    is_deeply( restarts_logged(), ['r1'], 'restarted once' );

    # pretend the last run was long enough ago
    write_file( $state_file, '{"restarts":{"r1":{"attempts":1,"last_run":' . ( time - 200 ) . '}}}' );
    $ret = $sneck->run;
    is( $ret->{data}{restarts}{r1}{ran}, 1, 'runs again once min_interval has passed' );

    reset_all();
    set_check( 'c1', 2 );
    $sneck = new_sneck( check_line('c1') . restart_line( 'r1', 'checks=c1 min_interval=0' ) );
    $sneck->run foreach ( 1 .. 3 );
    is_deeply( restarts_logged(), [ ('r1') x 3 ], 'min_interval=0 never holds back' );
}

#
# max_retries
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $sneck = new_sneck( check_line('c1') . restart_line( 'r1', 'checks=c1 min_interval=0 max_retries=2' ) );
    is( $sneck->run->{data}{restarts}{r1}{attempts}, 1, 'attempts 1' );
    is( $sneck->run->{data}{restarts}{r1}{attempts}, 2, 'attempts 2' );
    my $ret = $sneck->run;
    is( $ret->{data}{restarts}{r1}{reason},   'max retries reached', 'max retries reached' );
    is( $ret->{data}{restarts}{r1}{ran},      0,                     'not ran once max retries reached' );
    is( $ret->{data}{restarts}{r1}{attempts}, 2,                     'attempts stay at max' );
    is_deeply( restarts_logged(), [ 'r1', 'r1' ], 'restarted max_retries times' );

    set_check( 'c1', undef );
    $ret = $sneck->run;
    is( $ret->{data}{restarts}{r1}{attempts}, 0, 'attempts reset when checks recover' );

    set_check( 'c1', 2 );
    $ret = $sneck->run;
    is( $ret->{data}{restarts}{r1}{ran},      1, 'restarts again after recovering' );
    is( $ret->{data}{restarts}{r1}{attempts}, 1, 'attempts counting again' );

    reset_all();
    set_check( 'c1', 2 );
    $sneck = new_sneck( check_line('c1') . restart_line( 'r1', 'checks=c1 min_interval=0' ) );
    $sneck->run foreach ( 1 .. 5 );
    is_deeply( restarts_logged(), [ ('r1') x 5 ], 'max_retries=0 always retries' );
}

#
# state file problems
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $config = check_line('c1') . restart_line( 'r1', 'checks=c1' );

    write_file( $state_file, 'not json' );
    my $ret = new_sneck($config)->run;
    like( $ret->{data}{restart_state_error}, qr/^failed to read restart state file/, 'corrupt state file reported' );
    is( $ret->{data}{restarts}{r1}{ran}, 1, 'restarts still run with corrupt state file' );
    ok( eval { decode_json( read_file($state_file) ); 1 }, 'state file rewritten as valid JSON' );

    write_file( $state_file, '[]' );
    $ret = new_sneck($config)->run;
    is(
        $ret->{data}{restart_state_error},
        'restart state file "' . $state_file . '" is not in the expected format',
        'wrong shape state file reported'
    );

    reset_all();
    set_check( 'c1', 2 );
    $ret = new_sneck( $config, state_file => $dir . '/no/such/dir/state.json' )->run;
    like( $ret->{data}{restart_state_error}, qr/^failed to write restart state file/, 'unwritable state file reported' );
    is( $ret->{data}{restarts}{r1}{ran}, 1, 'restarts still run with unwritable state file' );

    reset_all();
    set_check( 'c1', 2 );
    write_file( $state_file, '{"restarts":{"gone":{"attempts":3,"last_run":1}}}' );
    $ret = new_sneck($config)->run;
    ok( !exists $ret->{data}{restart_state_error}, 'no state error for good state file' );
    my $state = decode_json( read_file($state_file) );
    ok( !exists $state->{restarts}{gone}, 'restarts no longer configured dropped from state' );
    is( $state->{restarts}{r1}{attempts}, 1, 'attempts saved' );
    like( $state->{restarts}{r1}{last_run}, qr/^\d+$/, 'last_run saved' );

    $ret = new_sneck($config)->run;
    ok( !exists $ret->{data}{restart_state_error}, 'restart_state_error cleared on next good run' );
}

#
# timeouts
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $marker = $dir . '/hang.marker';
    my $config = check_line('c1') . '@r1|checks=c1 timeout=1|' . $perl . ' ' . $hang_script . ' ' . $marker . "\n";
    my $start  = Time::HiRes::time;
    my $ret    = new_sneck($config)->run;
    my $r1     = $ret->{data}{restarts}{r1};
    is( $r1->{error},  'timed out after 1 seconds', 'timeout error' );
    is( $r1->{exit},   -1,                          'timeout exit is -1' );
    is( $r1->{output}, 'partial output',            'output from before the timeout kept' );
    ok( Time::HiRes::time - $start < 3, 'gave up on the restart at the timeout' );
    ok( !-e $marker, 'restart was still running when given up on' );
    is( $ret->{data}{alert}, 1, 'timed out restart sets alert' );
    like(
        $ret->{data}{alertString},
        qr/^restart "r1" failed, timed out after 1 seconds: partial output$/m,
        'timeout and output in alertString'
    );

    sleep 4;
    ok( -e $marker, 'timed out restart was left running, not killed' );
}

#
# a timed out restart is a failed depend
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $config
        = check_line('c1')
        . '@r1|checks=c1 timeout=1|'
        . $perl . ' '
        . $hang_script . ' '
        . $dir
        . "/hang2.marker\n"
        . restart_line( 'r2', 'checks=c1 depends=r1' );
    my $ret = new_sneck($config)->run;
    is( $ret->{data}{restarts}{r2}{reason}, 'skipped, dependency r1 failed', 'timed out depend skips dependents' );
    sleep 4;
}

#
# a restart that leaves a process holding its output open
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $config = check_line('c1') . '@r1|checks=c1|' . $perl . ' ' . $daemon_script . "\n";
    my $start  = Time::HiRes::time;
    my $ret    = new_sneck($config)->run;
    my $r1     = $ret->{data}{restarts}{r1};
    ok( Time::HiRes::time - $start < 3, 'did not wait on a process holding the pipes open' );
    is( $r1->{exit},   0,         'exit 0' );
    is( $r1->{output}, 'started', 'output captured' );
    ok( !exists $r1->{error}, 'no error' );
}

#
# restart command that can not be run
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $ret = new_sneck( check_line('c1') . "\@r1|checks=c1|/nonexistent/sneck_restart\n" )->run;
    my $r1  = $ret->{data}{restarts}{r1};
    is( $r1->{error}, 'failed to execute', 'failed exec error' );
    is( $r1->{exit},  -1,                  'failed exec exit is -1, same as checks' );
    like( $r1->{output}, qr/open3/, 'failed exec output has the open3 error' );
    like( $ret->{data}{alertString}, qr/^restart "r1" failed, failed to execute: open3/m, 'failed exec in alertString' );
}

#
# output fields and variable substitution
#
{
    reset_all();
    set_check( 'c1', 2 );
    my $ret = new_sneck( "NAME=r1\n"
            . check_line('c1')
            . '@r1|checks=c1|'
            . $perl . ' '
            . $restart_script
            . ' %NAME% '
            . $log
            . " 0\n" )->run;
    my $r1 = $ret->{data}{restarts}{r1};
    like( $r1->{command},     qr/ %NAME% /, 'command is before substitution' );
    like( $r1->{ran_command}, qr/ r1 /,     'ran_command is after substitution' );
    is( $r1->{output}, 'restarted r1', 'output captured and chomped' );
    is( $r1->{exit},   0,              'exit 0' );
    like( $r1->{run_time}, qr/^\d+\.\d+$/, 'run_time is decimal' );
    ok( !exists $r1->{error}, 'no error on success' );
    is( $ret->{data}{alert}, 1, 'alert from the critical check' );
    unlike( $ret->{data}{alertString}, qr/restart/, 'successful restart not in alertString' );
}

done_testing();
