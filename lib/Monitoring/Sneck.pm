package Monitoring::Sneck;

use 5.006;
use strict;
use warnings;
use Sys::Hostname qw(hostname);
use IPC::Open3    qw(open3);
use Symbol        qw(gensym);
use IO::Select;
use Time::HiRes qw(time);
use Monitoring::Sneck::Config ();

=head1 NAME

Monitoring::Sneck - a boopable LibreNMS JSON style SNMP extend for remotely running nagios style checks

=head1 VERSION

Version 1.5.0

=cut

our $VERSION = '1.5.0';

=head1 SYNOPSIS

    use Monitoring::Sneck;

    my $file='/usr/local/etc/sneck.conf';

    my $sneck=Monitoring::Sneck->new({config=>$file});

=head1 USAGE

Not really meant to be used as a library. The library is more of
to support the script.

=head1 CONFIG FORMAT

See L<Monitoring::Sneck::Config> for the config format and a example.

=head1 USAGE

snmpd should be configured as below.

    extend sneck /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /usr/local/bin/sneck -c

Then just setup a entry in like cron such as below.

    */5 * * * * /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /usr/local/bin/sneck -u 2> /dev/null > /dev/null

Most likely want to run it once per polling interval.

You can use it in a non-cached manner with out cron, but this will result in a
longer polling time for LibreNMS or the like when it queries it.

=head1 RETURN HASH

The data section of the return hash is as below.

    - $hash{data}{alert} :: 0/1 boolean for if there is a aloert or not.

    - $hash{data}{ok} :: Count of the number of ok checks.

    - $hash{data}{warning} :: Count of the number of warning checks.

    - $hash{data}{critical} :: Count of the number of critical checks.

    - $hash{data}{unknown} :: Count of the number of unkown checks.

    - $hash{data}{errored} :: Count of the number of errored checks.

    - $hash{data}{alertString} :: The cumulative outputs of anything
      that returned a warning, critical, or unknown.

    - $hash{data}{vars} :: A hash with the variables to use.

    - $hash{data}{time} :: Time since epoch.

    - $hash{data}{hostname} :: The hostname the check was ran on.

    - $hash{data}{config} :: The raw config file if told to include it.

    - $hash{data}{run_time} :: How long it took to run all checks.

For below '$name' is the name of the check in question.

    - $hash{data}{checks}{$name} :: A hash with info on the checks ran.

    - $hash{data}{checks}{$name}{check} :: The command pre-variable substitution.

    - $hash{data}{checks}{$name}{ran} :: The command ran.

    - $hash{data}{checks}{$name}{output} :: The output of the check.

    - $hash{data}{checks}{$name}{exit} :: The exit code. If it died on a
      signal, this is 128 plus the signal number. If it could not be
      executed, this is -1.

    - $hash{data}{checks}{$name}{error} :: Only present it died on a
      signal or could not be executed. Provides a brief description.

    - $hash{data}{checks}{$name}{run_time} :: How long it took to run the checks.

For below '$name' is the name of the debug checks in question.

    - $hash{data}{debugs}{$name} :: A hash with info on the checks ran.

    - $hash{data}{debugs}{$name}{check} :: The command pre-variable substitution.

    - $hash{data}{debugs}{$name}{ran} :: The command ran.

    - $hash{data}{debugs}{$name}{output} :: The output of the check.

    - $hash{data}{debugs}{$name}{exit} :: The exit code. Same as for checks.

    - $hash{data}{debugs}{$name}{error} :: Only present it died on a
      signal or could not be executed. Provides a brief description.

    - $hash{data}{checks}{$name}{run_time} :: How long it took to run the debug.

=head1 METHODS

=head2 new

Initiates the object.

One argument is taken and that is a hash ref. If the key 'config'
is present, that will be the config file used. Otherwise
'/usr/local/etc/sneck.conf' is used. The key 'include' is a Perl
boolean for if the raw config should be included in the JSON.

This function should always work as long as it can read the config.
If there is an error with parsing or the like, it will be reported
in the expected format when $sneck->run is called.

This is meant to be rock solid and always work, meaning LibreNMS
style JSON is always returned(provided Perl and the other modules
are working).

If 'debug' is true, when run is called, debugging info will be
printed.

    my $sneck;
    eval{
        $sneck=Monitoring::Sneck->new({config=>$file, include=>0, debug=>0});
    };
    if ($@){
        die($@);
    }

=cut

sub new {
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	# init the object

	my $self = {

		config    => '/usr/local/etc/sneck.conf',
		to_return => {
			error       => 0,
			errorString => '',
			data        => {
				hostname    => hostname,
				ok          => 0,
				warning     => 0,
				critical    => 0,
				unknown     => 0,
				errored     => 0,
				alert       => 0,
				alertString => '',
				checks      => {},
				debugs      => {},
			},
			version => 1,
		},
		parsed_config => undef,
		good          => 1,
		debug         => 0,
	};
	bless $self;

	if ( defined( $args{config} ) ) {
		$self->{config} = $args{config};
	}

	if ( defined( $args{debug} ) ) {
		$self->{debug} = $args{debug};
	}

	my $parsed_config;
	eval { $parsed_config = Monitoring::Sneck::Config->new( { file => $self->{config} } ); };
	if ($@) {
		$self->{good}                   = 0;
		$self->{to_return}{error}       = 1;
		$self->{to_return}{errorString} = $@;
		return $self;
	}

	# include the config file if requested
	if ( defined( $args{include} )
		&& $args{include} )
	{
		$self->{to_return}{data}{config} = $parsed_config->raw;
	}

	if ( !$parsed_config->is_valid ) {
		$self->{good}                   = 0;
		$self->{to_return}{error}       = 1;
		$self->{to_return}{errorString} = join( '; ',
			map { $_->{where} . ': ' . $_->{message} } $parsed_config->errors );
		return $self;
	}

	# only touch %ENV once the whole config is known to be good
	foreach my $env ( @{ $parsed_config->env } ) {
		$ENV{ $env->[0] } = $env->[1];
	}

	$self->{parsed_config} = $parsed_config;

	$self;
} ## end sub new

=head2 run

This runs the checks and returns the return hash.

    my $return=$sneck->run;

=cut

sub run {
	my $self = $_[0];

	my $run_start_time = Time::HiRes::time;
	if ( $self->{debug} ) {
		warn( 'run started at ' . $run_start_time );
	}

	# if something went wrong with new, just return
	if ( !$self->{good} ) {
		if ( $self->{debug} ) {
			warn('$self->{good} false... returning $self->{to_return}');
		}
		return $self->{to_return};
	}

	# reset the results so calling run more than once does not accumulate
	$self->{to_return}{data}{ok}          = 0;
	$self->{to_return}{data}{warning}     = 0;
	$self->{to_return}{data}{critical}    = 0;
	$self->{to_return}{data}{unknown}     = 0;
	$self->{to_return}{data}{errored}     = 0;
	$self->{to_return}{data}{alert}       = 0;
	$self->{to_return}{data}{alertString} = '';
	$self->{to_return}{data}{checks}      = {};
	$self->{to_return}{data}{debugs}      = {};

	# set the time it ran
	$self->{to_return}{data}{time} = time;
	#make sure it is a int
	$self->{to_return}{data}{time} =~ s/\..*$//;

	# debugs first, then checks, each in name order
	my $parsed_config = $self->{parsed_config};
	my @to_run;
	foreach my $type ( 'debugs', 'checks' ) {
		my $commands = $parsed_config->$type;
		foreach my $name ( sort( keys( %{$commands} ) ) ) {
			push( @to_run, [ $type, $name, $commands->{$name} ] );
		}
	}

	foreach my $item (@to_run) {
		my ( $type, $name, $check ) = @{$item};

		my $check_start_time = Time::HiRes::time;
		if ( $self->{debug} ) {
			warn( $name . ' processing started at ' . $check_start_time );
		}

		if ( $self->{debug} ) {
			warn( $name . ' is of type ' . $type );
		}

		$self->{to_return}{data}{$type}{$name} = { check => $check };

		if ( $self->{debug} ) {
			warn( $name . ' check string: "' . $check . '"' );
		}

		# put the variables in place
		$check = $parsed_config->substitute($check);
		$self->{to_return}{data}{$type}{$name}{ran} = $check;
		if ( $self->{debug} ) {
			warn( $name . ' check string post variable replacement: "' . $check . '"' );
		}

		my $exit_code;
		eval {
			my $check_pid = open3( my $std_in, my $std_out, my $std_err = gensym, $check );
			if ( $self->{debug} ) {
				warn( $name . ' open3 called' );
			}

			my $s = IO::Select->new();
			$s->add($std_out);
			$s->add($std_err);
			my $output = '';
			while ( my @ready = $s->can_read ) {
				foreach my $handle (@ready) {
					if ( sysread( $handle, my $buf, 4096 ) ) {
						$output = $output . $buf;
					} else {
						$s->remove($handle);
					}
				}
			}

			if ( $self->{debug} ) {
				warn( $name . ' IO::Select for open3 done... output is... "' . $output . '"' );
			}

			# call wait pid so we can get the exit code
			waitpid( $check_pid, 0 );
			$exit_code = $?;
			$self->{to_return}{data}{$type}{$name}{output} = $output;
			if ( defined( $self->{to_return}{data}{$type}{$name}{output} ) ) {
				chomp( $self->{to_return}{data}{$type}{$name}{output} );
			}
		};
		if ($@) {
			$exit_code = -1;
			$self->{to_return}{data}{$type}{$name}{output} = $@;
			chomp( $self->{to_return}{data}{$type}{$name}{output} );
		}

		# handle the exit code
		if ( $exit_code == -1 ) {
			$self->{to_return}{data}{$type}{$name}{error} = 'failed to execute';
		} elsif ( $exit_code & 127 ) {
			$self->{to_return}{data}{$type}{$name}{error} = sprintf(
				"child died with signal %d, %s coredump\n",
				( $exit_code & 127 ),
				( $exit_code & 128 ) ? 'with' : 'without'
			);
			# use the shell convention of 128 + signal so a signal death is never
			# mistaken for a nagios exit code of 0 to 3 and is counted as errored
			$exit_code = 128 + ( $exit_code & 127 );
		} else {
			$exit_code = $exit_code >> 8;
		}
		$self->{to_return}{data}{$type}{$name}{exit} = $exit_code;

		if ( $self->{debug} ) {
			warn( $name . ' exit code is ' . $exit_code );
		}

		# anything other than 0, 1, 2, or 3 is a error
		if ( $type eq 'checks' ) {
			if ( $self->{to_return}{data}{checks}{$name}{exit} == 0 ) {
				$self->{to_return}{data}{ok}++;
				if ( $self->{debug} ) {
					warn( $name . ' is ok' );
				}
			} elsif ( $self->{to_return}{data}{checks}{$name}{exit} == 1 ) {
				$self->{to_return}{data}{warning}++;
				$self->{to_return}{data}{alert} = 1;
				if ( $self->{debug} ) {
					warn( $name . ' is warning' );
				}
			} elsif ( $self->{to_return}{data}{checks}{$name}{exit} == 2 ) {
				$self->{to_return}{data}{critical}++;
				$self->{to_return}{data}{alert} = 1;
				if ( $self->{debug} ) {
					warn( $name . ' is critical' );
				}
			} elsif ( $self->{to_return}{data}{checks}{$name}{exit} == 3 ) {
				$self->{to_return}{data}{unknown}++;
				$self->{to_return}{data}{alert} = 1;
				if ( $self->{debug} ) {
					warn( $name . ' is unknown' );
				}
			} else {
				$self->{to_return}{data}{errored}++;
				$self->{to_return}{data}{alert} = 1;
				if ( $self->{debug} ) {
					warn( $name . ' is errored' );
				}
			}

			# add it to the alert string if it is a warning
			if ( $exit_code == 1 || $exit_code == 2 || $exit_code == 3 ) {
				$self->{to_return}{data}{alertString}
					= $self->{to_return}{data}{alertString} . $self->{to_return}{data}{checks}{$name}{output} . "\n";
			}
		} ## end if ( $type eq 'checks' )

		# figure out how long the run took
		my $check_stop_time = Time::HiRes::time;
		if ( $self->{debug} ) {
			warn( $name . ' finished at ' . $check_stop_time );
		}
		my $check_time = $check_stop_time - $check_start_time;
		# round to the 9th place to avoid scientific notation
		$self->{to_return}{data}{$type}{$name}{run_time} = sprintf( '%.9f', $check_time );
	} ## end foreach my $item (@to_run)

	$self->{to_return}{data}{vars} = $parsed_config->vars;

	# figure out how long the run took
	my $run_stop_time = Time::HiRes::time;
	if ( $self->{debug} ) {
		warn( 'run finished at ' . $run_stop_time );
	}

	my $run_time = $run_stop_time - $run_start_time;
	if ( $self->{debug} ) {
		warn( 'run time was ' . $run_time );
	}

	# round to the 9th place to avoid scientific notation
	$self->{to_return}{data}{run_time} = sprintf( '%.9f', $run_time );

	if ( $self->{debug} ) {
		warn('run is returning now');
	}
	return $self->{to_return};
} ## end sub run

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-monitoring-sneck at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Monitoring-Sneck>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Monitoring::Sneck


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Monitoring-Sneck>

=item * Search CPAN

L<https://metacpan.org/release/Monitoring-Sneck>

=item * Github

l<https://github.com/VVelox/Monitoring-Sneck>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Monitoring::Sneck
