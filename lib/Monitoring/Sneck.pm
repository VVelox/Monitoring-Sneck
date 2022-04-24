package Monitoring::Sneck;

use 5.006;
use strict;
use warnings;
use File::Slurp;

=head1 NAME

Monitoring::Sneck - a boopable LibreNMS JSON style SNMP extend for remotely running nagios style checks

=head1 VERSION

Version 0.0.0

=cut

our $VERSION = '0.0.0';

=head1 SYNOPSIS

    use Monitoring::Sneck;

    my $file='/usr/local/etc/sneck.conf';

    my $sneck=Monitoring::Sneck->new({config=>$file});

=head1 METHODS

=head2 new

Initiates the object.

One argument is taken and that is a hash ref. If the key 'config'
is present, that will be the config file used. Otherwise
'/usr/local/etc/sneck.conf' is used.

    my $sneck=Monitoring::Sneck->new({config=>$file});

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
			data => { ok => 0, warning => 0, critical => 0, unknown => 0, erroed=>0, alert => 0, alertString => '', checks => {} },
			version => 1,
		},
		checks => {},
		vars   => {},
		good   => 1,
	};
	bless $self;

	my $config_raw;
	eval { my $config_raw = read_file( $self->{config} ); };
	if ($@) {
		$self->{good}                   = 0;
		$self->{to_return}{error}       = 1;
		$self->{to_return}{errorString} = 'Failed to read in the config file "' . $self->{conffig} . '"... ' . $@;
		$self->{checks}                 = {};
		return $self;
	}

	# split the file and ignore any comments
	my @config_split = grep( !/^[\t\ ]*#/, split( /\n/, $config_raw ) );
	my $found_items  = 0;
	foreach my $line (@config_split) {
		$line =~ s/^[\ \t]*//;
		if ( $line =~ /^[A-Za-z0-9\_]+]\=/ ) {

			# we found a variable

			my ( $name, $value ) = split( /\|=/, $line, 2 );

			# make sure we have a value
			if ( !defined($value) ) {
				$self->{good} = 0;
				$self->{to_return}{error} = 1;
				$self->{to_return}{errorString}
					= '"' . $line . '" seems to be a variable, but just a variable and no value';
				return $self;
			}

			# remove any white space from the end of the name
			$name =~ s/[\t\ ]*$//;

			# check to make sure it is not already defined
			if ( defiend( $self->{vars}{$name} ) ) {
				$self->{good}                   = 0;
				$self->{to_return}{error}       = 1;
				$self->{to_return}{errorString} = 'variable "' . $name . '" is redefined on the line "' . $line . '"';
				return $self;
			}

			$self->{vars}{$name} = $value;
		}
		elsif ( $line =~ /^[A-Za-z0-9\_]+]\|/ ) {

			# we found a item to add
			my ( $name, $check ) = split( /\|/, $line, 2 );

			# make sure we have a check
			if ( !defined($check) ) {
				$self->{good} = 0;
				$self->{to_return}{error} = 1;
				$self->{to_return}{errorString}
					= '"' . $line . '" seems to be a check, but just contains a check name and no check';
				return $self;
			}

			# remove any white space from the end of the name
			$name =~ s/[\t\ ]*$//;

			# check to make sure it is not already defined
			if ( defiend( $self->{checks}{$name} ) ) {
				$self->{good}                   = 0;
				$self->{to_return}{error}       = 1;
				$self->{to_return}{errorString} = 'check "' . $name . '" is defined on the line "' . $line . '"';
				return $self;
			}

			# remove any white space from the start of the check
			$check =~ s/^[\t\ ]*//;

			$self->{checks}{$name} = $check;

			$found_items++;
		}
		elsif ( $line =~ /^$/ ) {

			# just ignore empty lines so we don't error on them
		}
		else {
			# we did not get a match for this line
			$self->{good}                   = 0;
			$self->{to_return}{error}       = 1;
			$self->{to_return}{errorString} = '"' . $line . '" is not a understood line';
			return $self;
		}
	}

	$self;
}

=head2 run

This runs the checks and returns the return hash.

    my $return=$sneck->run;

=cut

sub run {
	my $self = $_[0];

	# if something went wrong with new, just return
	if ( !$self->{good} ) {
		return $self->{to_return};
	}

	my @vars   = keys( %{ $self->{vars} } );
	my @checks = keys( %{ $self->{checks} } );
	foreach my $name (@checks) {
		my $check = $self->{checks}{$name};
		$self->{to_return}{checks}{$name} = { check => $check };

		# put the variables in place
		foreach my $var_name (@vars) {
			my $value = $self->{vars}{$var_name};
			$check =~ s/%%%$var_name%%%/$value/g;
		}
		$self->{to_return}{checks}{$name}{ran} = $check;

		$self->{to_return}{data}{checks}{$name}{output} = system($check);
		my $exit_code = $?;
		chomp( $self->{to_return}{data}{checks}{$name}{output} );

		# handle the exit code
		if ( $? == -1 ) {
			$self->{to_return}{data}{checks}{$name}{error} = 'failed to execute';
		}
		elsif ( $? & 127 ) {
			$self->{to_return}{data}{checks}{$name}{error} = sprintf( "child died with signal %d, %s coredump\n",
				( $? & 127 ), ( $? & 128 ) ? 'with' : 'without' );
		}
		else {
			$exit_code = $? >> 8;
		}
		$self->{to_return}{data}{checks}{$name}{exit} = $exit_code;

		# anything other than 0, 1, 2, or 3 is a error
		if ( $self->{to_return}{data}{checks}{$name}{exit} == 0 ) {
			$self->{to_return}{data}{ok}++;
		}
		elsif ( $self->{to_return}{data}{checks}{$name}{exit} == 1 ) {
			$self->{to_return}{data}{warning}++;
			$self->{to_return}{data}{alert} = 1;
		}
		elsif ( $self->{to_return}{data}{checks}{$name}{exit} == 2 ) {
			$self->{to_return}{data}{critical}++;
			$self->{to_return}{data}{alert} = 1;
		}
		elsif ( $self->{to_return}{data}{checks}{$name}{exit} == 3 ) {
			$self->{to_return}{data}{unknown}++;
			$self->{to_return}{data}{alert} = 1;
		}
		else {
			$self->{to_return}{data}{errored}++;
			$self->{to_return}{data}{alert} = 1;
		}

		# add it to the alert string if it is a warning
		if ( $exit_code == 1 || $exit_code == 2 || $exit_code == 3 ) {
			$self->{to_return}{data}{alertString}
				= $self->{to_return}{data}{alertString} . $self->{to_return}{data}{checks}{$name}{output} . "\n";
		}
	}

	$self->{to_return}{data}{vars}=$self->{vars};

	return $self->{to_return};
}

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
    
    - $hash{data}[checks}{$name} :: A hash with info on the checks ran.
    
    - $hash{data}[checks}{$name}{check} :: The command pre-variable substitution.
    
    - $hash{data}[checks}{$name}{ran} :: The command ran.
    
    - $hash{data}[checks}{$name}{output} :: The output of the check.
    
    - $hash{data}[checks}{$name}{exit} :: The exit code.
    
    - $hash{data}[checks}{$name}{error} :: Only present it died on a
      signal or could not be executed. Provides a brief description.

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

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Monitoring-Sneck>

=item * Search CPAN

L<https://metacpan.org/release/Monitoring-Sneck>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Monitoring::Sneck
