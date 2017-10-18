package Mojolicious::Command::report;
use Mojo::Base 'Mojolicious::Command';

has description => "Generate report of users in specified basedn\n";
has usage => sub { shift->extract_usage };

use Getopt::Long;

sub run {
  my $self = shift;
  @ARGV = @_;
  my $basedn = '';
  GetOptions(
          'basedn|b=s' => \$basedn,
  );
  die "Usage: $0 report -b basedn -u loginacct -p password\n" unless $basedn;

  my $search = $self->app->ldap->search(
    base=>$basedn,
    filter => "objectClass=posixAccount",
  );
  $search->code and die $search->code;
  #$search->entry(0) or die $search->entry(0);
  for ( 0..$search->count ) {
    my $entry = $search->entry($_) or next;
    format REPORT = 
@<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<
$entry->get_value('givenName'), $entry->get_value('sn'), $entry->get_value('uid'), $entry->get_value('userPassword')
.
    $~ = 'REPORT';
    write;
  }

}

1;
