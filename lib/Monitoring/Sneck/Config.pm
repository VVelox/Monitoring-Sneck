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
            print $error->{where} . ': ' . $error->{message} . "\n";
        }
    }

    foreach my $name ( sort keys %{ $config->checks } ) {
        print $name . ' runs ' . $config->substitute( $config->checks->{$name} ) . "\n";
    }

=head1 CONFIG FORMAT

Two formats are supported, the sneck format and YAML. Files ending in
.yaml or .yml are read as YAML, anything else as the sneck format. This
can be overridden via the format arg to new.

The following applies to both.

Names of variables, environment variables, checks, and debug checks are
made up of A-Z, a-z, 0-9, and _.

Variables are used in commands in the form /%+variable_name%+/. A
reference to a variable that is not defined is left as written and
produces a warning, as it may just be part of the command, such as
'date +%Y%m%d'.

Debug checks are the same as checks, but are not counted towards any of
the counts. They exist purely for debugging. A check and a debug check
may share a name.

Commands may not be empty.

Environment variables are only set if the whole config is valid.

=head2 SNECK FORMAT

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
removed.

Lines matching /^\%[A-Za-z0-9\_]+\|/ are debug checks. The leading % is
not part of the name.

Any other sort of line is an error.

Variable, check, and debug check names may not be redefined.

=head3 EXAMPLE SNECK CONFIG

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

=head2 YAML FORMAT

This needs L<YAML::XS>, which is optional and only loaded when a YAML
config is used.

The top level is a mapping with up to four keys, each of which is a
mapping of names to values.

    - env :: Environment variables to set. Set in sorted name order.

    - vars :: Variables.

    - checks :: Checks, with the command as the value.

    - debugs :: Debug checks, with the command as the value.

Any other top level key is an error. Any section may be left out or
empty. An empty file is a valid config with nothing in it.

Values must be strings or numbers. An empty value, such as 'FOO:' or
'FOO: ~', is an empty string for env and vars and an error for checks
and debugs.

YAML::XS turns some unquoted values into something else. 'true' becomes
1 and 'false' becomes a empty string. Quote values like those.

YAML::XS keeps the last of any duplicate keys without saying anything,
so redefinitions can not be caught like they are in the sneck format.

=head3 EXAMPLE YAML CONFIG

    env:
      PATH: /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
    vars:
      GEOM_DEV: foo
    checks:
      geom_foo: /usr/local/libexec/nagios/check_geom mirror %GEOM_DEV%
      does_not_exist: /bin/this_will_error yup... that it will
    debugs:
      routes: netstat -rn

=head1 METHODS

=head2 new

Reads and parses a config.

One argument is taken and that is a hash ref.

    - file :: Path to the config file to read.

    - raw :: The config as a string. Used instead of file if both
      are given.

    - format :: Either 'sneck' or 'yaml'. If not given, a file ending
      in .yaml or .yml is 'yaml' and anything else, including raw, is
      'sneck'.

Dies if neither file nor raw is given, the file can not be read, the
format is unknown, or the format is 'yaml' and YAML::XS can not be
loaded. Problems with the config itself never die. Check them via
is_valid and errors.

    my $config;
    eval { $config = Monitoring::Sneck::Config->new( { file => $file } ); };
    if ($@) {
        die($@);
    }

    my $config = Monitoring::Sneck::Config->new( { raw => "FOO=bar\nfoo_check|/bin/echo %FOO%\n" } );

    my $config = Monitoring::Sneck::Config->new( { raw => "checks:\n  foo_check: /bin/true\n", format => 'yaml' } );

=cut

sub new {
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	my $self = {
		file     => $args{file},
		raw      => undef,
		format   => 'sneck',
		vars     => {},
		env      => [],
		checks   => {},
		debugs   => {},
		errors   => [],
		warnings => [],
	};
	bless $self;

	if ( defined( $args{format} ) ) {
		if ( $args{format} ne 'sneck' && $args{format} ne 'yaml' ) {
			die( 'Unknown format "' . $args{format} . '"' );
		}
		$self->{format} = $args{format};
	} elsif ( !defined( $args{raw} )
		&& defined( $args{file} )
		&& $args{file} =~ /\.[Yy][Aa]?[Mm][Ll]$/ )
	{
		$self->{format} = 'yaml';
	}

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

	if ( $self->{format} eq 'yaml' ) {
		if ( !eval { require YAML::XS; 1 } ) {
			die( 'YAML::XS is required for YAML configs... ' . $@ );
		}
		$self->_parse_yaml;
	} else {
		$self->_parse_sneck;
	}

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

=head2 format

Returns the format the config was parsed as, either 'sneck' or 'yaml'.

    my $format = $config->format;

=cut

sub format {
	return $_[0]->{format};
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

Returns a list of errors found in the config. Each is a hash ref as
below.

    - where :: Where the problem is, for printing. For the sneck format
      this is 'line N'. For YAML this is the path to the problem, such
      as 'checks.foo', or 'YAML' for a YAML syntax error.

    - line :: The line number, starting at 1. Undef for YAML.

    - path :: The path to the problem, such as 'checks.foo'. Undef for
      the sneck format.

    - text :: The line as it appears in the file. Undef for YAML.

    - message :: A description of the problem.

For the sneck format these are in line order. For YAML they are in
section order, env, vars, checks, then debugs, then by name.

    foreach my $error ( $config->errors ) {
        print $error->{where} . ': ' . $error->{message} . "\n";
    }

=cut

sub errors {
	return @{ $_[0]->{errors} };
}

=head2 warnings

Returns a list of warnings found in the config. Same format and order
as errors.

    foreach my $warning ( $config->warnings ) {
        print $warning->{where} . ': ' . $warning->{message} . "\n";
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
should be set. Each item is a array ref of the name and value. This is
a copy, so changing it does not change the config.

For the sneck format, the order is the order they appear in the config.
For YAML, it is sorted by name.

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
names do not include the leading % used by the sneck format.

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

# Parses $self->{raw} as the sneck format, filling in vars, env, checks,
# debugs, errors, and warnings. Called once by new. Takes no args and
# returns nothing.
#
# Lines are numbered from 1 so errors and warnings can point at them. All
# lines are looked at, so every error is reported, not just the first.
# Errors and warnings are sorted into line order at the end.
#
# Example...
#
#     $self->{raw} = "FOO=bar\nbad line\n";
#     $self->_parse_sneck;
#     # $self->{vars} is { FOO => 'bar' }
#     # $self->{errors} is [ { where => 'line 2', line => 2, path => undef, text => 'bad line',
#     #                        message => '"bad line" is not a understood line' } ]
sub _parse_sneck {
	my $self = $_[0];

	# where each command was defined, for undefined variable warnings
	my %command_locations;

	my $line_number = 0;
	foreach my $text ( split( /\n/, $self->{raw} ) ) {
		$line_number++;
		$text =~ s/\r$//;

		my $line = $text;
		$line =~ s/^[\ \t]*//;

		my $location = { line => $line_number, text => $text };

		if ( $line eq '' || $line =~ /^#/ ) {
			# blank or comment
			next;
		} elsif ( $line =~ /^[Ee][Nn][Vv]\ ([A-Za-z0-9\_]+)\=(.*)$/ ) {
			push( @{ $self->{env} }, [ $1, $2 ] );
		} elsif ( $line =~ /^([A-Za-z0-9\_]+)\=(.*)$/ ) {
			my ( $name, $value ) = ( $1, $2 );
			if ( defined( $self->{vars}{$name} ) ) {
				$self->_add_problem( 'errors', $location, 'variable "' . $name . '" is redefined' );
				next;
			}
			$self->{vars}{$name} = $value;
		} elsif ( $line =~ /^(\%?)([A-Za-z0-9\_]+)\|(.*)$/ ) {
			my ( $type, $name, $command ) = ( 'checks', $2, $3 );
			if ( $1 eq '%' ) {
				$type = 'debugs';
			}

			if ( defined( $self->{$type}{$name} ) ) {
				$self->_add_problem( 'errors', $location, $self->_type_label($type) . ' "' . $name . '" is redefined' );
				next;
			}

			if ( $self->_add_command( $type, $name, $command, $location ) ) {
				$command_locations{$type}{$name} = $location;
			}
		} else {
			$self->_add_problem( 'errors', $location, '"' . $line . '" is not a understood line' );
		}
	} ## end foreach my $text ( split( /\n/, $self->{raw} ) )

	$self->_warn_undefined_vars( \%command_locations );

	# keep errors and warnings in line order
	@{ $self->{errors} }   = sort { $a->{line} <=> $b->{line} } @{ $self->{errors} };
	@{ $self->{warnings} } = sort { $a->{line} <=> $b->{line} || $a->{message} cmp $b->{message} } @{ $self->{warnings} };

	return;
} ## end sub _parse_sneck

# Parses $self->{raw} as YAML, filling in vars, env, checks, debugs,
# errors, and warnings. Called once by new after YAML::XS has been loaded.
# Takes no args and returns nothing.
#
# YAML::XS gives no line numbers for keys, so problems point at a path
# such as 'checks.foo' instead. A YAML syntax error is a single error with
# the path 'YAML'. Sections are handled in the order env, vars, checks,
# debugs, and names within them in sorted order, so problems come out in
# a stable order.
#
# Example...
#
#     $self->{raw} = "vars:\n  FOO: bar\nchecks:\n  foo_check: /bin/echo %FOO%\nbogus: 1\n";
#     $self->_parse_yaml;
#     # $self->{vars} is { FOO => 'bar' }
#     # $self->{checks} is { foo_check => '/bin/echo %FOO%' }
#     # $self->{errors} is [ { where => 'bogus', line => undef, path => 'bogus', text => undef,
#     #                        message => 'unknown top level key "bogus"' } ]
sub _parse_yaml {
	my $self = $_[0];

	my @documents;
	eval {
		# never let a config create perl objects
		no warnings 'once';
		local $YAML::XS::LoadBlessed = 0;
		@documents = YAML::XS::Load( $self->{raw} );
	};
	if ($@) {
		my $yaml_error = $@;
		$yaml_error =~ s/\s+/ /g;
		$yaml_error =~ s/^\s+|\s+$//g;
		$self->_add_problem( 'errors', { path => 'YAML' }, $yaml_error );
		return;
	}

	# an empty file or one with only comments is an empty config
	if ( !defined( $documents[0] ) ) {
		return;
	}

	if ( defined( $documents[1] ) ) {
		$self->_add_problem( 'errors', { path => 'YAML' }, 'only one YAML document is allowed' );
		return;
	}

	my $config = $documents[0];
	if ( ref($config) ne 'HASH' ) {
		$self->_add_problem( 'errors', { path => 'YAML' }, 'the top level must be a mapping' );
		return;
	}

	my %known_sections = ( env => 1, vars => 1, checks => 1, debugs => 1 );
	foreach my $key ( sort( keys( %{$config} ) ) ) {
		if ( !$known_sections{$key} ) {
			$self->_add_problem( 'errors', { path => $key }, 'unknown top level key "' . $key . '"' );
		}
	}

	# where each command was defined, for undefined variable warnings
	my %command_locations;

	foreach my $section ( 'env', 'vars', 'checks', 'debugs' ) {
		my $items = $config->{$section};
		if ( !defined($items) ) {
			next;
		}
		if ( ref($items) ne 'HASH' ) {
			$self->_add_problem( 'errors', { path => $section }, 'must be a mapping' );
			next;
		}

		foreach my $name ( sort( keys( %{$items} ) ) ) {
			my $location = { path => $section . '.' . $name };
			my $value    = $items->{$name};

			if ( $name !~ /^[A-Za-z0-9\_]+$/ ) {
				$self->_add_problem( 'errors', $location, 'name "' . $name . '" may only contain A-Z, a-z, 0-9, and _' );
				next;
			}

			if ( ref($value) ) {
				$self->_add_problem( 'errors', $location, 'value must be a string or number' );
				next;
			}

			if ( $section eq 'env' ) {
				push( @{ $self->{env} }, [ $name, defined($value) ? $value : '' ] );
			} elsif ( $section eq 'vars' ) {
				$self->{vars}{$name} = defined($value) ? $value : '';
			} else {
				if ( $self->_add_command( $section, $name, $value, $location ) ) {
					$command_locations{$section}{$name} = $location;
				}
			}
		} ## end foreach my $name ( sort( keys( %{$items} ) ) )
	} ## end foreach my $section ( 'env', 'vars', 'checks', 'debugs' )

	$self->_warn_undefined_vars( \%command_locations );

	return;
} ## end sub _parse_yaml

# Adds a check or debug check after making sure it has a command. Leading
# spaces and tabs are removed from the command first. Used by both
# parsers. Records a error if the command is empty.
#
# Args...
#
#     - type :: Either 'checks' or 'debugs'.
#
#     - name :: The name of the check, without any leading %.
#
#     - command :: The command, possibly undef for YAML.
#
#     - location :: Hash ref of where it was defined, as taken by
#       _add_problem.
#
# Returns 1 if it was added or 0 if the command was empty.
#
# Example...
#
#     $self->_add_command( 'checks', 'foo', '  /bin/true', { line => 3, text => 'foo|  /bin/true' } );
#     # returns 1 and $self->{checks}{foo} is '/bin/true'
#
#     $self->_add_command( 'debugs', 'bar', undef, { path => 'debugs.bar' } );
#     # returns 0 and adds the error 'debug check "bar" has no command'
sub _add_command {
	my ( $self, $type, $name, $command, $location ) = @_;

	if ( !defined($command) ) {
		$command = '';
	}
	$command =~ s/^[\ \t]*//;

	if ( $command =~ /^\s*$/ ) {
		$self->_add_problem( 'errors', $location, $self->_type_label($type) . ' "' . $name . '" has no command' );
		return 0;
	}

	$self->{$type}{$name} = $command;
	return 1;
} ## end sub _add_command

# Records a warning for each undefined variable used by each check and
# debug check. Each variable is only warned about once per command. Used
# by both parsers once everything is parsed, as variables may be defined
# after the checks that use them.
#
# Args...
#
#     - command_locations :: Hash ref of 'checks' and 'debugs', each a hash
#       ref of names to locations as taken by _add_problem.
#
# Returns nothing.
#
# Example...
#
#     $self->{checks}{foo} = '/bin/echo %NOPE%';
#     $self->_warn_undefined_vars( { checks => { foo => { line => 3, text => 'foo|/bin/echo %NOPE%' } } } );
#     # adds the warning 'check "foo" uses undefined variable "NOPE"' for line 3
sub _warn_undefined_vars {
	my ( $self, $command_locations ) = @_;

	foreach my $type ( 'checks', 'debugs' ) {
		foreach my $name ( sort( keys( %{ $self->{$type} } ) ) ) {
			my %seen;
			while ( $self->{$type}{$name} =~ /%+([A-Za-z0-9\_]+)(?=%)/g ) {
				my $var_name = $1;
				if ( !defined( $self->{vars}{$var_name} ) && !$seen{$var_name} ) {
					$seen{$var_name} = 1;
					$self->_add_problem( 'warnings', $command_locations->{$type}{$name},
						$self->_type_label($type) . ' "' . $name . '" uses undefined variable "' . $var_name . '"' );
				}
			}
		} ## end foreach my $name ( sort( keys( %{ $self->{$type} } ) ) )
	} ## end foreach my $type ( 'checks', 'debugs' )

	return;
} ## end sub _warn_undefined_vars

# Returns the label used in messages for a type.
#
# Args...
#
#     - type :: Either 'checks' or 'debugs'.
#
# Returns 'check' for 'checks' and 'debug check' for 'debugs'.
#
# Example...
#
#     my $label = $self->_type_label('debugs');
#     # $label is 'debug check'
sub _type_label {
	if ( $_[1] eq 'debugs' ) {
		return 'debug check';
	}
	return 'check';
}

# Records a error or warning. Returns nothing.
#
# Args...
#
#     - kind :: Either 'errors' or 'warnings'.
#
#     - location :: Hash ref of where the problem is. For the sneck format
#       this has 'line', the line number starting at 1, and 'text', the
#       line as it appears in the file. For YAML this has 'path', such as
#       'checks.foo' or 'YAML'.
#
#     - message :: A description of the problem.
#
# The recorded hash ref has where, line, path, text, and message, as
# described in the POD for errors.
#
# Example...
#
#     $self->_add_problem( 'errors', { line => 4, text => 'foo bar' }, '"foo bar" is not a understood line' );
#     # $self->{errors} now ends with
#     # { where => 'line 4', line => 4, path => undef, text => 'foo bar',
#     #   message => '"foo bar" is not a understood line' }
#
#     $self->_add_problem( 'errors', { path => 'checks.foo' }, 'check "foo" has no command' );
#     # $self->{errors} now ends with
#     # { where => 'checks.foo', line => undef, path => 'checks.foo', text => undef,
#     #   message => 'check "foo" has no command' }
sub _add_problem {
	my ( $self, $kind, $location, $message ) = @_;

	my $where = $location->{path};
	if ( defined( $location->{line} ) ) {
		$where = 'line ' . $location->{line};
	}

	push(
		@{ $self->{$kind} },
		{
			where   => $where,
			line    => $location->{line},
			path    => $location->{path},
			text    => $location->{text},
			message => $message,
		}
	);
	return;
} ## end sub _add_problem

=head1 BUGS

Please report any bugs or feature requests to C<bug-monitoring-sneck at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Monitoring-Sneck>.

=cut

1;    # End of Monitoring::Sneck::Config
