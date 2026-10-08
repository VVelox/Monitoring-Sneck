#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile tempdir);
use File::Spec ();
use JSON       qw(decode_json);
use MIME::Base64           qw(decode_base64);
use IO::Uncompress::Gunzip qw(gunzip);

if ( $^O eq 'MSWin32' ) {
    plan skip_all => 'list form pipe open not supported on Windows';
}
my $perl   = $^X;
my $lib    = File::Spec->rel2abs('lib');
my $script = File::Spec->rel2abs( File::Spec->catfile( 'src_bin', 'sneck' ) );
my $dir    = tempdir( CLEANUP => 1 );

# Writes a config file to the temp dir and returns the path.
sub write_config {
    my ($content) = @_;
    my ( $fh, $filename ) = tempfile( DIR => $dir, SUFFIX => '.conf' );
    print $fh $content;
    close $fh;
    return $filename;
}

# Runs sneck with the given args.
#
# Returns the stdout and exit code. stderr is left alone.
#
#     my ( $stdout, $exit_code ) = run_sneck( '-c', '-C', $cache );
sub run_sneck {
    my @args = @_;
    open( my $pipe, '-|', $perl, '-I' . $lib, $script, @args ) or die( 'failed to run sneck... ' . $! );
    my $stdout = do { local $/; <$pipe> };
    close($pipe);
    return ( defined($stdout) ? $stdout : '', $? >> 8 );
}

# Reads a whole file and returns its contents.
sub slurp {
    my ($file) = @_;
    open( my $fh, '<', $file ) or die( 'failed to open "' . $file . '"... ' . $! );
    local $/;
    my $content = <$fh>;
    close($fh);
    return $content;
}

# Decodes the contents of a .snmp cache file.
#
# Takes the base64 string as read from the file and returns the gunzipped JSON.
#
#     my $json = snmp_decode( slurp( $cache . '.snmp' ) );
sub snmp_decode {
    my ($snmp_content) = @_;
    my $compressed = decode_base64($snmp_content);
    my $uncompressed;
    gunzip( \$compressed => \$uncompressed ) or die('gunzip failed');
    return $uncompressed;
}

my $ok_check ="ok_check|$perl -e 'exit 0'\n";

#
# -c with a missing cache file
#
{
    my $cache = File::Spec->catfile( $dir, 'missing.cache' );
    my ( $stdout, $exit_code ) = run_sneck( '-c', '-C', $cache );
    is( $exit_code, 3, '-c with missing cache exits 3' );
    my $decoded = eval { decode_json($stdout) };
    ok( defined $decoded, '-c with missing cache prints JSON' );
    is( $decoded->{error},         1, '-c with missing cache sets error' );
    is( $decoded->{data}{alert},   1, '-c with missing cache sets alert' );
    like( $decoded->{errorString}, qr/\Q$cache\E"/, '-c with missing cache names the cache file' );

    ( $stdout, $exit_code ) = run_sneck( '-c', '-b', '-C', $cache );
    is( $exit_code, 3, '-c -b with missing cache exits 3' );
    like( $stdout, qr/\Q$cache\E\.snmp/, '-c -b with missing cache names the .snmp file' );
}

#
# -u writes both cache files and -c / -c -b read them back
#
{
    my $cfg   = write_config($ok_check);
    my $cache = File::Spec->catfile( $dir, 'update.cache' );

    my ( $stdout, $exit_code ) = run_sneck( '-u', '-f', $cfg, '-C', $cache );
    is( $exit_code, 0, '-u exits 0' );
    ok( -f $cache,           '-u writes the cache file' );
    ok( -f $cache . '.snmp', '-u writes the .snmp cache file' );

    my $cache_content = slurp($cache);
    is( $stdout, $cache_content, '-u prints what it wrote to the cache file' );
    my $decoded = decode_json($cache_content);
    is( $decoded->{data}{ok}, 1, 'cache file holds the check results' );

    my $snmp_content = slurp( $cache . '.snmp' );
    like( $snmp_content, qr/^[A-Za-z0-9+\/=]+\n$/, '.snmp cache is one line of base64' );
    is( snmp_decode($snmp_content) . "\n", $cache_content, '.snmp cache decompresses to the raw JSON' );

    ( $stdout, $exit_code ) = run_sneck( '-c', '-C', $cache );
    is( $exit_code, 0,              '-c exits 0' );
    is( $stdout,    $cache_content, '-c prints the cache file' );

    ( $stdout, $exit_code ) = run_sneck( '-c', '-b', '-C', $cache );
    is( $exit_code, 0,             '-c -b exits 0' );
    is( $stdout,    $snmp_content, '-c -b prints the .snmp cache file' );
}

#
# -u with a tiny result still writes the .snmp cache as gzip+base64
#
{
    my $cfg   = write_config("# nothing\n");
    my $cache = File::Spec->catfile( $dir, 'small.cache' );
    run_sneck( '-u', '-f', $cfg, '-C', $cache );
    my $snmp_content = slurp( $cache . '.snmp' );
    like( $snmp_content, qr/^[A-Za-z0-9+\/=]+\n$/, 'tiny .snmp cache is still base64' );
    is( snmp_decode($snmp_content) . "\n", slurp($cache), 'tiny .snmp cache decompresses to the raw JSON' );
}

#
# -u -p still writes the .snmp cache as gzip+base64
#
{
    my $cfg   = write_config($ok_check);
    my $cache = File::Spec->catfile( $dir, 'pretty.cache' );
    run_sneck( '-u', '-p', '-f', $cfg, '-C', $cache );
    my $snmp_content = slurp( $cache . '.snmp' );
    like( $snmp_content, qr/^[A-Za-z0-9+\/=]+\n$/, 'pretty .snmp cache is still base64' );
    is( snmp_decode($snmp_content), slurp($cache), 'pretty .snmp cache decompresses to the raw JSON' );
}

#
# -q prints nothing but still updates the cache
#
{
    my $cfg   = write_config($ok_check);
    my $cache = File::Spec->catfile( $dir, 'quiet.cache' );
    my ( $stdout, $exit_code ) = run_sneck( '-u', '-q', '-f', $cfg, '-C', $cache );
    is( $exit_code, 0,  '-q exits 0' );
    is( $stdout,    '', '-q prints nothing' );
    ok( -f $cache, '-q still writes the cache file' );
}

#
# no flags prints single line JSON
#
{
    my $cfg = write_config($ok_check);
    my ( $stdout, $exit_code ) = run_sneck( '-f', $cfg );
    is( $exit_code, 0, 'no flags exits 0' );
    like( $stdout, qr/^\{[^\n]*\}\n$/, 'no flags prints one line of JSON' );
    is( decode_json($stdout)->{data}{ok}, 1, 'no flags JSON holds the results' );
    ok( !exists decode_json($stdout)->{data}{config}, 'config not included without -i' );
}

#
# -p pretty prints
#
{
    my $cfg = write_config($ok_check);
    my ( $stdout, $exit_code ) = run_sneck( '-p', '-f', $cfg );
    is( $exit_code, 0, '-p exits 0' );
    like( $stdout, qr/^\{\n\s+"data"/, '-p prints indented JSON' );
    is( decode_json($stdout)->{data}{ok}, 1, '-p JSON holds the results' );
}

#
# -i includes the config
#
{
    my $cfg = write_config($ok_check);
    my ( $stdout, $exit_code ) = run_sneck( '-i', '-f', $cfg );
    is( $exit_code, 0, '-i exits 0' );
    is( decode_json($stdout)->{data}{config}, $ok_check, '-i includes the config' );
}

#
# -t with a valid config
#
{
    my $cfg = write_config($ok_check);
    my ( $stdout, $exit_code ) = run_sneck( '-t', '-f', $cfg );
    is( $exit_code, 0,                        '-t with valid config exits 0' );
    is( $stdout,    'config OK: ' . $cfg . "\n", '-t with valid config prints OK' );
}

#
# -t with only warnings
#
{
    my $cfg = write_config("date_check|/bin/date +%Y%m%d\n");
    my ( $stdout, $exit_code ) = run_sneck( '-t', '-f', $cfg );
    is( $exit_code, 0, '-t with only warnings exits 0' );
    is(
        $stdout,
        'warning: line 1: check "date_check" uses undefined variable "Y"' . "\n"
            . 'warning: line 1: check "date_check" uses undefined variable "m"' . "\n"
            . 'config OK: ' . $cfg . "\n",
        '-t prints warnings then OK'
    );
}

#
# -t with errors and warnings
#
{
    my $cfg = write_config("FOO=bar\nbad line\nchk|/bin/echo %NOPE%\nempty|\n");
    my ( $stdout, $exit_code ) = run_sneck( '-t', '-f', $cfg );
    is( $exit_code, 1, '-t with errors exits 1' );
    is(
        $stdout,
        'error: line 2: "bad line" is not a understood line' . "\n"
            . 'error: line 4: check "empty" has no command' . "\n"
            . 'warning: line 3: check "chk" uses undefined variable "NOPE"' . "\n",
        '-t prints every error then warnings'
    );
}

#
# -t with a missing config
#
{
    my $cfg = File::Spec->catfile( $dir, 'missing.conf' );
    my ( $stdout, $exit_code ) = run_sneck( '-t', '-f', $cfg );
    is( $exit_code, 1, '-t with missing config exits 1' );
    like( $stdout, qr/^error: Failed to read in the config file "\Q$cfg\E"/, '-t with missing config prints the error' );
}

#
# -t with a YAML config
#
SKIP: {
    skip( 'YAML::XS not installed', 4 ) if !eval { require YAML::XS; 1 };

    my ( $fh, $cfg ) = tempfile( DIR => $dir, SUFFIX => '.yaml' );
    print $fh "checks:\n  ok_check: /bin/true\n";
    close $fh;
    my ( $stdout, $exit_code ) = run_sneck( '-t', '-f', $cfg );
    is( $exit_code, 0,                           '-t with valid YAML config exits 0' );
    is( $stdout,    'config OK: ' . $cfg . "\n", '-t with valid YAML config prints OK' );

    ( $fh, $cfg ) = tempfile( DIR => $dir, SUFFIX => '.yml' );
    print $fh "checks:\n  empty: ''\n  date_check: /bin/date +%Y%m%d\nbogus: 1\n";
    close $fh;
    ( $stdout, $exit_code ) = run_sneck( '-t', '-f', $cfg );
    is( $exit_code, 1, '-t with invalid YAML config exits 1' );
    is(
        $stdout,
        'error: bogus: unknown top level key "bogus"' . "\n"
            . 'error: checks.empty: check "empty" has no command' . "\n"
            . 'warning: checks.date_check: check "date_check" uses undefined variable "Y"' . "\n"
            . 'warning: checks.date_check: check "date_check" uses undefined variable "m"' . "\n",
        '-t prints YAML errors and warnings with paths'
    );
}

#
# -v and -h
#
{
    my ( $stdout, $exit_code ) = run_sneck('-v');
    is( $exit_code, 255, '-v exits 255' );
    like( $stdout, qr/^sneck v\. \d+\.\d+\.\d+$/, '-v prints the version' );

    ( $stdout, $exit_code ) = run_sneck('--version');
    is( $exit_code, 255, '--version exits 255' );

    ( $stdout, $exit_code ) = run_sneck('-h');
    is( $exit_code, 255, '-h exits 255' );
    like( $stdout, qr/SYNOPSIS/, '-h prints the POD' );

    ( $stdout, $exit_code ) = run_sneck('--help');
    is( $exit_code, 255, '--help exits 255' );
}

done_testing();
