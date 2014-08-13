package Mojolicious::Command::bulkcopy;
use Mojo::Base 'Mojolicious::Command';

has description => 'Show versions of installed modules.';
has usage => sub { shift->extract_usage };

use Getopt::Long;

sub run {
  my $self = shift;
  @ARGV = @_;
  my $header = 0;
  my $sep = "\t";
  my $columns;
  my $username;
  my $password;
  my $template;
  my $execute = 0;
  GetOptions(
          'header|H' => \$header,
          'sep|s=s' => \$sep,
          'columns|c=s' => \$columns,
          'username|u=s' => \$username,
          'password|p=s' => \$password,
          'template|t=s' => \$template,
          'execute|E' => \$execute,
  );
  die "Usage: $0 bulkcopy [-H] [-s _] [-E] -c c,o,l,u,m,n,s -t template_user -u loginacct -p password\n" unless $columns && $template && $username && $password;

  my $ua = $self->app->ua;
  my $tx;
  $tx = $ua->post("/login?username=$username&password=$password");
  my $from = $ua->post("/details?details=$template" => {'X-Requested-With' => 'XMLHttpRequest'})->res->json;
  $_ = <STDIN> if $header;
  while ( <STDIN> ) {
    chomp;
    @_ = split /$sep/, $_;
    my %input = ();
    foreach ( split /,/, $columns ) {
      $input{$_||'undef'} = shift @_;
    }
    my $to = $from;
    $to->{uid} = $input{uid} || lc($input{sn}.substr($input{givenName},0,1));
    $to->{homeDirectory} =~ s/[^\/]+$/$to->{uid}/;
    $to->{gecos} = join ' ', $input{givenName}, $input{sn};
    $to->{sn} = $input{sn};
    $to->{givenName} = $input{givenName};
    $to->{localPersonID} = $input{localPersonID} if $input{localPersonID};
    $to->{localStudentGradYr} = $input{localStudentGradYr} if $input{localStudentGradYr};
    $to->{mail} =~ s/^[^\@]+/$to->{uid}/; $to->{mail} = $input{mail} if $input{mail};
    $to->{userPassword} = $input{userPassword};
    my $copy = join '&', map { "$_=$to->{$_}" } keys %$to;
    warn "Adding $to->{uid}\n";
    warn "/home/admin/copy?$copy\n" unless $execute;
    say Data::Dumper::Dumper($ua->post("/home/admin/copy?$copy" => {'X-Requested-With' => 'XMLHttpRequest'})->res->json) if $execute;
  }
}

1;
