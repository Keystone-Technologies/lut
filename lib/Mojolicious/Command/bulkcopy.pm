package Mojolicious::Command::bulkcopy;
use Mojo::Base 'Mojolicious::Command';

has description => 'Show versions of installed modules.';
has usage => sub { shift->extract_usage };

sub run {
  my ($self, $header, $sep, $columns, $username, $password, $template) = @_;

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
    $to->{mail} =~ s/^[^\@]+/$to->{uid}/; $to->{mail} = $input{mail} if $input{mail};
    $to->{userPassword} = $input{userPassword};
    my $copy = join '&', map { "$_=$to->{$_}" } keys %$to;
    #warn "/home/admin/copy?$copy\n";
    warn "Adding $to->{uid}\n";
    say Data::Dumper::Dumper($ua->post("/home/admin/copy?$copy" => {'X-Requested-With' => 'XMLHttpRequest'})->res->json);
  }
}

1;

__END__
Student_Number,First_Name,Last_Name,Grade_Level,Username,Password,email,,,School,User Type
180010,Dylan,Altheimer,8,altheimerd,7EUK8M7Y,altheimerd@students.duchesne-hs.org,,,Duchesne,Student

{"uid":"kchoinka",
"location":"ou=staff,ou=people,o=local",
"homeDirectory":"\/data\/users\/staff\/kchoinka",
"description":"Staff",
"gecos":"Kim Choinka",
"sn":"Choinka",
"mail":"kchoinka@duchesne-hs.org",
"accountStatus":"active",
"userPassword":"imissc00kie",
"givenName":"Kim",
"loginShell":"\/bin\/bash",
"dn":"uid=kchoinka,ou=staff,ou=people,o=local"}
