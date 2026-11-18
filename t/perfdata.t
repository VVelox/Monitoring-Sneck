#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

BEGIN {
    use_ok('Monitoring::Sneck::Config') || print "Bail out!\n";
    use_ok('Monitoring::Sneck')         || print "Bail out!\n";
}

my $perl = $^X;
my $dir  = tempdir( CLEANUP => 1 );

# Writes a file with the given content.
sub write_file {
    my ( $file, $content ) = @_;
    open( my $fh, '>', $file ) or die( 'failed to write "' . $file . '"... ' . $! );
    print $fh $content;
    close($fh);
    return $file;
}

# Writes a config and runs it, returning the data section.
my $config_count = 0;
sub run_config {
    my ($content) = @_;
    $config_count++;
    my $file     = write_file( $dir . '/run' . $config_count . '.conf', $content );
    my $returned = Monitoring::Sneck->new(
        { config => $file, compliance_state_file => $dir . '/state' . $config_count . '.json' } )->run;
    is( $returned->{error}, 0, 'config ' . $config_count . ' ran without error' )
        || diag( $returned->{errorString} );
    return $returned->{data};
}

# output.pl prints the contents of the file named by its second arg, then exits with its first.
my $output_script = write_file( $dir . '/output.pl', <<'END' );
my ( $code, $file ) = @ARGV;
open( my $fh, '<', $file ) or die($!);
print <$fh>;
exit $code;
END

# Returns a check command that prints the output and exits with the code.
my $output_count = 0;
sub output_check {
    my ( $code, $output ) = @_;
    $output_count++;
    my $file = write_file( $dir . '/output' . $output_count . '.txt', $output );
    return $perl . ' ' . $output_script . ' ' . $code . ' ' . $file;
}

#
# parsing
#
{
    my $parsed = Monitoring::Sneck->_parse_perfdata("HTTP OK - 200 | time=0.5s;1;2;0 'page size'=512B");
    is_deeply(
        $parsed,
        {
            text     => 'HTTP OK - 200',
            errors   => [],
            perfdata => {
                time        => { value => 0.5, uom => 's', warning => '1',  critical => '2',  min => 0,     max => undef },
                'page size' => { value => 512, uom => 'B', warning => undef, critical => undef, min => undef, max => undef },
            },
        },
        'single line with a quoted label'
    );

    $parsed = Monitoring::Sneck->_parse_perfdata("no perfdata here\nsecond line");
    is_deeply( $parsed, { text => "no perfdata here\nsecond line", errors => [], perfdata => {} }, 'no perfdata' );

    $parsed = Monitoring::Sneck->_parse_perfdata(undef);
    is_deeply( $parsed, { text => '', errors => [], perfdata => {} }, 'undef output' );

    $parsed = Monitoring::Sneck->_parse_perfdata("DISK OK | a=1\nlong text\nmore | b=2;\@5:10;~:20\nc=U;;;0;100");
    is( $parsed->{text}, "DISK OK\nlong text\nmore", 'multi line text has the perfdata removed' );
    is_deeply(
        $parsed->{perfdata},
        {
            a => { value => 1,     uom => '', warning => undef,   critical => undef,  min => undef, max => undef },
            b => { value => 2,     uom => '', warning => '@5:10', critical => '~:20', min => undef, max => undef },
            c => { value => undef, uom => '', warning => undef,   critical => undef,  min => 0,     max => 100 },
        },
        'multi line perfdata, ranges as given, and U is undef'
    );

    $parsed = Monitoring::Sneck->_parse_perfdata("OK | 'it''s'=-1.5e2KB 'a=b'=3c");
    is( $parsed->{perfdata}{"it's"}{value}, -150, 'escaped quote in label and exponent value' );
    is( $parsed->{perfdata}{"it's"}{uom},   'KB', 'unit as given' );
    is( $parsed->{perfdata}{'a=b'}{uom},    'c',  'quoted label may hold =' );

    $parsed = Monitoring::Sneck->_parse_perfdata("OK | junk bad=abc good=1;;;x dup=1 dup=2");
    is_deeply(
        $parsed->{errors},
        [ 'no label=value in "junk"', 'bad value for "bad"', 'bad min for "good"', 'label "dup" repeated' ],
        'parse problems are reported'
    );
    ok( !exists( $parsed->{perfdata}{bad} ), 'item with a bad value is left out' );
    is( $parsed->{perfdata}{good}{value}, 1,     'item with a bad min is kept' );
    is( $parsed->{perfdata}{good}{min},   undef, 'bad min is undef' );
    is( $parsed->{perfdata}{dup}{value},  2,     'repeated label keeps the last' );
}

#
# options
#
{
    for my $name ( 'perfdata', 'strip_perfdata' ) {
        my ( $value, $error ) = Monitoring::Sneck::Config->validate_option( $name, 1 );
        is( $value, 1, $name . ' takes 1' );
        ( $value, $error ) = Monitoring::Sneck::Config->validate_option( $name, 2 );
        is( $error, 'option "' . $name . '" must be 0 or 1', $name . ' must be 0 or 1' );
    }
    SKIP: {
        skip( 'YAML::XS not installed', 1 ) if !eval { require YAML::XS; 1 };
        my $config = Monitoring::Sneck::Config->new(
            { format => 'yaml', raw => "options:\n  perfdata: false\n  strip_perfdata: true\n" } );
        is_deeply(
            [ $config->options->{perfdata}, $config->options->{strip_perfdata} ],
            [ 0, 1 ],
            'YAML takes true and false for them'
        );
    }
}

#
# running
#
{
    my $data = run_config( 'chk|' . output_check( 2, "CRIT - slow | time=5s;1;2\n" ) . "\n"
            . '%dbg|' . output_check( 0, "x | y=1\n" ) . "\n"
            . '!comp||' . output_check( 1, "WARN | z=3\n" ) . "\n" );
    is_deeply(
        $data->{checks}{chk}{perfdata},
        { time => { value => 5, uom => 's', warning => '1', critical => '2', min => undef, max => undef } },
        'checks get perfdata by default'
    );
    is( $data->{debugs}{dbg}{perfdata}{y}{value},     1, 'debugs get perfdata' );
    is( $data->{compliance}{comp}{perfdata}{z}{value}, 3, 'compliance checks get perfdata' );
    is( $data->{checks}{chk}{output}, 'CRIT - slow | time=5s;1;2', 'output is left as is' );
    is( $data->{alertString},         "CRIT - slow | time=5s;1;2\n", 'alertString keeps perfdata by default' );
    ok( !exists( $data->{checks}{chk}{perfdata_error} ), 'no perfdata_error when it parses' );

    $data = run_config( 'chk|' . output_check( 0, "OK | junk\n" ) . "\n" );
    is( $data->{checks}{chk}{perfdata_error}, 'no label=value in "junk"', 'perfdata_error is set' );
    is( $data->{ok}, 1, 'perfdata_error does not change the counts' );

    $data = run_config( "\$perfdata=0\nchk|" . output_check( 0, "OK | a=1\n" ) . "\n" );
    ok( !exists( $data->{checks}{chk}{perfdata} ), 'perfdata=0 leaves it out' );

    $data = run_config( "\$strip_perfdata=1\n\$perfdata=0\n\$compliance_alert=1\n"
            . 'chk|' . output_check( 2, "CRIT - slow | time=5s\n" ) . "\n"
            . '!comp||' . output_check( 1, "WARN | z=3\n" ) . "\n" );
    is( $data->{alertString},            "CRIT - slow\n[comp] WARN\n", 'strip_perfdata strips alertString' );
    is( $data->{compliance_alertString}, "[comp] WARN\n",              'strip_perfdata strips compliance_alertString' );
    is( $data->{checks}{chk}{output},    'CRIT - slow | time=5s',      'strip_perfdata leaves output as is' );
}

done_testing();
