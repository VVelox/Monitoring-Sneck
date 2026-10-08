package Monitoring::Sneck::Config;

use 5.006;
use strict;
use warnings;
use File::Slurp qw(read_file);

=head1 NAME

Monitoring::Sneck::Config - parses and validates sneck config files

=head1 VERSION

Version 1.5.0

=cut

our $VERSION = '1.5.0';

=head1 SYNOPSIS

    use Monitoring::Sneck::Config;

    my $config;
    eval { $config = Monitoring::Sneck::Config->new( { file => '/usr/local/etc/sneck.conf' } ); };
    if ($@) {
        die($@);
    }

    if ( !$config->is_valid ) {
        foreach my $error ( $config->errors ) {
            print 'line ' . $error->{line} . ': ' . $error->{message} . "\n";
        }
    }

    foreach my $name ( sort keys %{ $config->checks } ) {
        print $name . ' runs ' . $config->substitute( $config->checks->{$name} ) . "\n";
    }

=head1 CONFIG FORMAT

Each line has leading spaces and tabs removed before it is looked at. A
trailing \r is also removed, so files with CRLF line endings work.

Blank lines are ignored.

Lines starting with # are comments and are ignored.

Lines matching /^[Ee][Nn][Vv]\ [A-Za-z0-9\_]+\=/ set environment
variables. The name is between the space and the first =, the value is
everything after it. The value may be empty. These may be set more than
once, with the last one winning.

Lines matching /^[A-Za-z0-9\_]+\=/ are variables. The name is before the
first =, the value is everything after it. The value may be empty.

Lines matching /^[A-Za-z0-9\_]+\|/ are checks. The name is before the
first |, the command is everything after it with leading whitespace
removed. The command may not be empty.

Lines matching /^\%[A-Za-z0-9\_]+\|/ are debug checks. These are the same
as checks, but are not counted towards any of the counts. They exist
purely for debugging. The leading % is not part of the name, so a check
and a debug check may share a name.

Any other sort of line is an error.

Variables are used in commands in the form /%+variable_name%+/. A
reference to a variable that is not defined is left as written and
produces a warning, as it may just be part of the command, such as
'date +%Y%m%d'.

Variable, check, and debug check names may not be redefined.

=head2 EXAMPLE CONFIG

    env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
    # this is a comment
    GEOM_DEV=foo
    geom_foo|/usr/local/libexec/nagios/check_geom mirror %GEOM_DEV%
    does_not_exist|/bin/this_will_error yup... that it will

    does_not_exist_2|/usr/bin/env /bin/this_will_also_error

    #includes route info
    %routes|netstat -rn

The first line sets the environment variable PATH.

The second is ignored as it is a comment.

The third sets the variable GEOM_DEV to 'foo'.

The fourth creates a check named geom_foo that calls check_geom with
the value of the variable GEOM_DEV.

The fifth is an example of a check that calls a file that does not
exist.

The sixth line is ignored as it is blank.

The seventh is an example of another command erroring.

The eighth is ignored as it is a comment.

The ninth creates a debug check named routes.

When it is run, errors for the fifth and seventh lines are printed to
STDERR. For this reason, use '2> /dev/null' when calling it from snmpd
or '2> /dev/null > /dev/null' when calling it from cron.

=head1 METHODS

=head2 new

Reads and parses a config.

One argument is taken and that is a hash ref.

    - file :: Path to the config file to read.

    - raw :: The config as a string. Used instead of file if both
      are given.

Dies if neither is given or if the file can not be read. Problems with
the config itself never die. Check them via is_valid and errors.

    my $config;
    eval { $config = Monitoring::Sneck::Config->new( { file => $file } ); };
    if ($@) {
        die($@);
    }

    my $config = Monitoring::Sneck::Config->new( { raw => "FOO=bar\nfoo_check|/bin/echo %FOO%\n" } );

=cut

sub new {
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	my $self = {
		file     => $args{file},
		raw      => undef,
		vars     => {},
		env      => [],
		checks   => {},
		debugs   => {},
		errors   => [],
		warnings => [],
	};
	bless $self;

	if ( defined( $args{raw} ) ) {
		$self->{raw} = $args{raw};
	} elsif ( defined( $args{file} ) ) {
		eval { $self->{raw} = read_file( $args{file} ); };
		if ($@) {
			die( 'Failed to read in the config file "' . $args{file} . '"... ' . $@ );
		}
	} else {
		die('Neither file nor raw specified');
	}

	$self->_parse;

	return $self;
} ## end sub new

=head2 file

Returns the path to the config file read or undef if it was created
from a string.

    my $file = $config->file;

=cut

sub file {
	return $_[0]->{file};
}

=head2 raw

Returns the raw config as a string, exactly as read.

    my $raw = $config->raw;

=cut

sub raw {
	return $_[0]->{raw};
}

=head2 is_valid

Returns 1 if the config has no errors, otherwise 0. Warnings do not
affect this.

    if ( !$config->is_valid ) {
        warn('config has errors');
    }

=cut

sub is_valid {
	if ( defined( $_[0]->{errors}[0] ) ) {
		return 0;
	}
	return 1;
}

=head2 errors

Returns a list of errors found in the config, in line order. Each is a
hash ref as below.

    - line :: The line number, starting at 1.

    - text :: The line as it appears in the file.

    - message :: A description of the problem.

    foreach my $error ( $config->errors ) {
        print 'line ' . $error->{line} . ': ' . $error->{message} . "\n";
    }

=cut

sub errors {
	return @{ $_[0]->{errors} };
}

=head2 warnings

Returns a list of warnings found in the config, in line order. Same
format as errors.

    foreach my $warning ( $config->warnings ) {
        print 'line ' . $warning->{line} . ': ' . $warning->{message} . "\n";
    }

=cut

sub warnings {
	return @{ $_[0]->{warnings} };
}

=head2 vars

Returns a hash ref of the variables, with the names as keys. This is a
copy, so changing it does not change the config.

    my $value = $config->vars->{GEOM_DEV};

=cut

sub vars {
	return { %{ $_[0]->{vars} } };
}

=head2 env

Returns a array ref of environment variables to set, in the order they
appear in the config. Each item is a array ref of the name and value.
This is a copy, so changing it does not change the config.

Nothing is set in %ENV by this module. That is left to the caller.

    foreach my $env ( @{ $config->env } ) {
        $ENV{ $env->[0] } = $env->[1];
    }

=cut

sub env {
	return [ map { [ @{$_} ] } @{ $_[0]->{env} } ];
}

=head2 checks

Returns a hash ref of the checks, with the names as keys and the
commands, before variable substitution, as values. This is a copy, so
changing it does not change the config.

    my $command = $config->checks->{geom_foo};

=cut

sub checks {
	return { %{ $_[0]->{checks} } };
}

=head2 debugs

Returns a hash ref of the debug checks. Same format as checks. The
names do not include the leading %.

    my $command = $config->debugs->{routes};

=cut

sub debugs {
	return { %{ $_[0]->{debugs} } };
}

=head2 substitute

Takes a string, usually a check command, and returns it with the
variables put in place. Variables are put in place in sorted name
order. Undefined variables are left as written.

    my $ran = $config->substitute( $config->checks->{geom_foo} );

=cut

sub substitute {
	my $self   = $_[0];
	my $string = $_[1];

	foreach my $var_name ( sort( keys( %{ $self->{vars} } ) ) ) {
		my $value = $self->{vars}{$var_name};
		$string =~ s/%+$var_name%+/$value/g;
	}

	return $string;
}

# Parses $self->{raw}, filling in vars, env, checks, debugs, errors, and
# warnings. Called once by new. Takes no args and returns nothing.
#
# Lines are numbered from 1 so errors and warnings can point at them. All
# lines are looked at, so every error is reported, not just the first.
#
# Example...
#
#     $self->{raw} = "FOO=bar\nbad line\n";
#     $self->_parse;
#     # $self->{vars} is { FOO => 'bar' }
#     # $self->{errors} is [ { line => 2, text => 'bad line', message => '"bad line" is not a understood line' } ]
sub _parse {
	my $self = $_[0];

	# line number each command was defined on, for undefined variable warnings
	my %command_lines;

	my $line_number = 0;
	foreach my $text ( split( /\n/, $self->{raw} ) ) {
		$line_number++;
		$text =~ s/\r$//;

		my $line = $text;
		$line =~ s/^[\ \t]*//;

		if ( $line eq '' || $line =~ /^#/ ) {
			# blank or comment
			next;
		} elsif ( $line =~ /^[Ee][Nn][Vv]\ ([A-Za-z0-9\_]+)\=(.*)$/ ) {
			push( @{ $self->{env} }, [ $1, $2 ] );
		} elsif ( $line =~ /^([A-Za-z0-9\_]+)\=(.*)$/ ) {
			my ( $name, $value ) = ( $1, $2 );
			if ( defined( $self->{vars}{$name} ) ) {
				$self->_add_problem( 'errors', $line_number, $text, 'variable "' . $name . '" is redefined' );
				next;
			}
			$self->{vars}{$name} = $value;
		} elsif ( $line =~ /^(\%?)([A-Za-z0-9\_]+)\|(.*)$/ ) {
			my ( $type, $name, $command ) = ( 'checks', $2, $3 );
			my $label = 'check';
			if ( $1 eq '%' ) {
				$type  = 'debugs';
				$label = 'debug check';
			}

			$command =~ s/^[\ \t]*//;
			if ( $command =~ /^[\ \t]*$/ ) {
				$self->_add_problem( 'errors', $line_number, $text, $label . ' "' . $name . '" has no command' );
				next;
			}

			if ( defined( $self->{$type}{$name} ) ) {
				$self->_add_problem( 'errors', $line_number, $text, $label . ' "' . $name . '" is redefined' );
				next;
			}

			$self->{$type}{$name} = $command;
			$command_lines{$type}{$name} = [ $line_number, $text, $label ];
		} else {
			$self->_add_problem( 'errors', $line_number, $text, '"' . $line . '" is not a understood line' );
		}
	} ## end foreach my $text ( split( /\n/, $self->{raw} ) )

	# variables may be defined after the checks that use them, so look for
	# undefined ones once everything is parsed
	foreach my $type ( 'checks', 'debugs' ) {
		foreach my $name ( keys( %{ $self->{$type} } ) ) {
			my ( $command_line_number, $command_text, $label ) = @{ $command_lines{$type}{$name} };
			my %seen;
			while ( $self->{$type}{$name} =~ /%+([A-Za-z0-9\_]+)(?=%)/g ) {
				my $var_name = $1;
				if ( !defined( $self->{vars}{$var_name} ) && !$seen{$var_name} ) {
					$seen{$var_name} = 1;
					$self->_add_problem( 'warnings', $command_line_number, $command_text,
						$label . ' "' . $name . '" uses undefined variable "' . $var_name . '"' );
				}
			}
		} ## end foreach my $name ( keys( %{ $self->{$type} } ) )
	} ## end foreach my $type ( 'checks', 'debugs' )

	# keep errors and warnings in line order
	@{ $self->{errors} }   = sort { $a->{line} <=> $b->{line} } @{ $self->{errors} };
	@{ $self->{warnings} } = sort { $a->{line} <=> $b->{line} || $a->{message} cmp $b->{message} } @{ $self->{warnings} };

	return;
} ## end sub _parse

# Records a error or warning. Used by _parse. Returns nothing.
#
# Args...
#
#     - kind :: Either 'errors' or 'warnings'.
#
#     - line :: The line number, starting at 1.
#
#     - text :: The line as it appears in the file.
#
#     - message :: A description of the problem.
#
# Example...
#
#     $self->_add_problem( 'errors', 4, 'foo bar', '"foo bar" is not a understood line' );
#     # $self->{errors} now ends with
#     # { line => 4, text => 'foo bar', message => '"foo bar" is not a understood line' }
sub _add_problem {
	my ( $self, $kind, $line, $text, $message ) = @_;
	push( @{ $self->{$kind} }, { line => $line, text => $text, message => $message } );
	return;
}

=head1 BUGS

Please report any bugs or feature requests to C<bug-monitoring-sneck at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Monitoring-Sneck>.

=cut

1;    # End of Monitoring::Sneck::Config
