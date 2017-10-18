package Mojolicious::Command::bulkcopy;
use Mojo::Base 'Mojolicious::Command';

has description => "Use a template user as a basis for creating multiple accounts\n";
has usage => sub { shift->extract_usage };

use Getopt::Long;
use String::MkPasswd 'mkpasswd';

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
    my %from = %$from;
    $to->{localPersonID} = $input{localPersonID} if $input{localPersonID};
    $to->{localStudentGradYr} = $input{localStudentGradYr} if $input{localStudentGradYr};
    $to->{location} =~ s/$from{localStudentGradYr}/$to->{localStudentGradYr}/ if $to->{localStudentGradYr};
    $to->{uid} = $input{uid};
    unless ( $to->{uid} ) {
      $to->{uid} = lc($input{sn}.substr($input{givenName},0,1));
      $to->{uid} =~ s/\W//g;
    }
    $to->{homeDirectory} =~ s/$from{uid}/$to->{uid}/;
    $to->{homeDirectory} =~ s/$from{localStudentGradYr}/$to->{localStudentGradYr}/ if $to->{localStudentGradYr};
    $to->{gecos} = join ' ', $input{givenName}, $input{sn};
    $to->{sn} = $input{sn};
    $to->{givenName} = $input{givenName};
    $to->{mail} = ''; #~ s/$from->{uid}/$to->{uid}/; $to->{mail} = $input{mail} if $input{mail};
    $to->{userPassword} = $input{userPassword} || mkpasswd(-length => 4, -minnum => 4, -minlower => 0, -minupper => 0, -minspecial => 0, -distribute => 1, -noambiguous => 1);
    my $copy = join '&', map { "$_=$to->{$_}" } keys %$to;
    warn "Adding $to->{uid}\n";
    warn "/home/admin/copy?$copy\n" unless $execute;
    say Data::Dumper::Dumper($ua->post("/home/admin/copy?$copy" => {'X-Requested-With' => 'XMLHttpRequest'})->res->json) if $execute;
  }
}

1;
