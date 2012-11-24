use Mojolicious::Lite;  
use Mojo::JSON;
use FindBin qw($Bin);
use lib "$Bin/lib";
use File::Basename;
use Switch;
use Net::LDAP;
use Crypt::SmbHash qw(lmhash nthash);

use Data::Dumper;

my $basename = basename $0, '.pl';
plugin Config => {
	default => {
		ldapbase => $ENV{LDAPBASE} || 'o=Local',
		ldaphost => $ENV{LDAPHOST} || 'localhost',
		ldapport => $ENV{LDAPPORT} || 389,
		ldapversion => $ENV{LDAPVERSION} || 3,
		ldapbinddn => $ENV{LDAPBINDDN} || 'cn=Manager,o=Local',
		ldapbindpw => $ENV{LDAPBINDPW} || 'secret',
	}
};
warn "Connecting to LDAP ", app->config->{ldaphost}, " port ", app->config->{ldapport}, " version ", app->config->{ldapversion}, "\n";
my $ldap = Net::LDAP->new(app->config->{ldaphost}, port=>app->config->{ldapport}, version=>app->config->{ldapversion}); # Need a timeout here.
warn "Connected.\n";
defined $ldap or die "Cannot start $0: $!\n";
$ldap->bind(app->config->{ldapbinddn}, password=>app->config->{ldapbindpw});
my $search = $ldap->search(
	base => app->config->{ldapbase},
	scope => 'base',
	attrs => ['dn'],
	filter => 'o=*',
);
$search->code && die "Cannot find base ".app->config->{ldapbase}.": ".$search->error."\n";
#my $entry = $search->entry(0);
#warn $entry->dn, "\n";

app->config(hypnotoad => {pid_file=>"$Bin/../.$basename", listen=>[split ',', $ENV{MOJO_LISTEN}], proxy=>$ENV{MOJO_REVERSE_PROXY}});
plugin 'IsXHR';
plugin 'authentication' => {
	'autoload_user' => 1,
	'session_key' => '272djn32lk32jhsuieghi383hwskl',
	'load_user' => sub {
		my ($self, $uid) = @_;
		my $search = $self->ldap->search(
			base=>$self->config->{ldapbase},
			filter => "(&(objectClass=person)(accountStatus=active)(uid=$uid))",
		);
		$search->code or return $search->entry(0);
		warn $search->error;
		return undef;
	},
	'validate_user' => sub {
		my ($self, $username, $password, $extradata) = @_;
		return undef unless defined $username;
		my $search = $self->ldap->search(
			base=>$self->config->{ldapbase},
			filter => "(&(objectClass=person)(accountStatus=active)(uid=$username))",
		);
		$search->code and do { warn $search->error; return undef; };
		if ( my $entry = $search->entry(0) ) {
			return $entry->get_value('uid');
		}
		return undef;
	},
	#'current_user_fn' => 'user', # compatibility with old code
};
plugin 'authorization', {
	has_priv => sub {
		my ($self, $priv, $extradata) = @_;
		my $uid = $self->current_user->get_value('uid');
		my $search = $self->ldap->search(
			base=>$self->config->{ldapbase},
			filter => "(&(cn=$priv)(objectClass=posixGroup)(memberuid=$uid))",
		);
		$search->code and do { warn $search->error; return 0; };
		return $search->entries;
	},
	is_role => sub {
		my ($self, $role, $extradata) = @_;
		my $uid = $self->current_user->get_value('uid');
		my $search = $self->ldap->search(
			base=>$self->config->{ldapbase},
			filter => "(&(cn=$role)(objectClass=posixGroup))",
		);
		$search->code and do { warn $search->error; return 0; };
		return $search->entries;
	},
	user_privs => sub {
		my ($self, $extradata) = @_;
		my $uid = $self->current_user->get_value('uid');
		my $search = $self->ldap->search(
			base=>$self->config->{ldapbase},
			filter => "(&(objectClass=posixGroup)(memberuid=$uid))",
		);
		$search->code and do { warn $search->error; return 0; };
		return map { $search->entry($_)->get_value('cn') } 0..$search->entries;
	},
	user_role => sub {
		my ($self, $extradata) = @_;
		return $self->has_priv("Domain Admins") ? 'admin' : 'user';
	},
};

helper ldap => sub { return $ldap };
helper replace => sub {
	my $self = shift;
	my $dn = shift;
	%_ = (@_);
	%_ = (map { $_ => $_{$_} } grep { /Password$/ } keys %_) unless $self->has_priv('Domain Admins');
	$_{sambaLMPassword} = lmhash($_{userPassword}) if $_{userPassword};
	$_{sambaNTPassword} = nthash($_{userPassword}) if $_{userPassword};
warn Dumper({%_});
return 0?('err','Error!'):('ok','All good!');
#	my $modify = $self->ldap->modify($dn, replace => {%_});
#	return $modify->is_error?'err':'ok', $modify->error;
};
helper find => sub {
	my $self = shift;
	return undef unless $_[0];
        my $search = $self->ldap->search(
                base=>$self->config->{ldapbase},
                filter => "(&(uid=$_[0])(objectClass=posixAccount))",
        );
        $search->code and do { warn $search->error; return undef; };
	return $search->entry(0);
};

get '/' => sub {
	my $self = shift;

	unless ( $self->is_user_authenticated ) {
		$self->session->{'requested_page'} = $self->current_route;
		return $self->redirect_to('login');
	}
	return $self->redirect_to('home');
};

any '/login' => sub {
	my $self = shift;
	if ( $self->param('username') && $self->param('password') ) {
		return $self->redirect_to($self->session->{'requested_page'}||'/') if $self->authenticate($self->param('username'), $self->param('password'));
		$self->stash(denied => 1);
	}
} => 'login';
get '/logout' => (authenticated => 1) => 'logout';

post '/details' => (is_xhr=>1) => sub {
	my $self = shift;
	my $details = $self->role eq 'admin' ? $self->find($self->param('details')) || $self->current_user : $self->current_user;
	my $sup = $details->dn;
	$sup =~ s/^[^,]+,//;
	$self->render_json({
		superior => $sup,
		gecos => $details->get_value('gecos'),
		givenName => $details->get_value('givenName'),
		sn => $details->get_value('sn'),
		uid => $details->get_value('uid'),
		userPassword => $details->get_value('userPassword'),
		homeDirectory => $details->get_value('homeDirectory'),
		accountStatus => $details->get_value('accountStatus'),
		mail => $details->get_value('mail'),
		loginShell => $details->get_value('loginShell'),
		description => $details->get_value('description'),
	});
};

under '/home' => (authenticated => 1);
get '/' => {template=>'home', role=>'user'};
post '/' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($res, $msg) = $self->replace(map { s/^o_//; $_ => $self->param($_) } grep { /^o_/ } $self->param);
	$self->render_json({response=>$res,message=>$msg});
};

under '/home/admin' => (authenticated => 1, has_priv => 'Domain Admins');
get '/' => {template=>'home',role=>'admin'};
post '/' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($res, $msg) = $self->replace(map { s/^o_//; $_ => $self->param($_) } grep { /^o_/ } $self->param);
	$self->render_json({response=>$res,message=>$msg});
};
get '/search' => (is_xhr=>1) => sub {
	my $self = shift;
	my $q = $self->param('term');
	my $search = $self->ldap->search(
		base=>$self->config->{ldapbase},
		filter => "(&(objectClass=person)(|(uid=$q*)(sn=$q*)(givenName=$q*)))",
	);
	return (success=>'err',message=>$search->error) if $search->is_error;
	return $self->render_json([]) unless $search->entries;
	my @ac = map { {label=>$search->entry($_)->get_value('gecos').' ('.$search->entry($_)->get_value('uid').')',value=>$search->entry($_)->get_value('uid')} } 0..$search->entries-1;
	return $self->render_json([@ac]);
};

app->start;

__DATA__
@@ logout.html.ep
% $self->logout;
Not logged in.<br />
%= link_to Login => 'login'

@@ login.html.ep
% if ( stash 'denied' ) {
    Access Denied<br />
% }
%= form_for '/login' => (method=>'POST') => begin
Username: <%= text_field 'username' %><br />
Password: <%= password_field 'password' %><br />
%= submit_button 'login', name=>'Login'
% end

@@ home.html.ep
<!doctype html>
<html>
<head>
<title>LDAP Object Tool</title>
<link   href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8/themes/base/jquery-ui.css" type="text/css" rel="stylesheet" media="all" />
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.8/jquery.min.js" type="text/javascript"></script>
<script src="http://ajax.googleapis.com/ajax/libs/jqueryui/1.9.1/jquery-ui.min.js" type="text/javascript"></script>
<script src="http://jtemplates.tpython.com/jTemplates/jquery-jtemplates.js" type="text/javascript"></script>
<script type="text/javascript">
$(document).ready(function(){
    $("#form").submit(function(event){
        event.preventDefault();
        var u1 = $("#form").find('input[name=o_userPassword]').val();
        var u2 = $("#form").find('input[name=userPassword2]').val();
        if ( u1 != u2 ) {
            $("#msg").addClass('err').removeClass('ok').html("Passwords do not match!");
            return false;
        }
        $.post("<%= url_for %>", $("#form").serialize(), function(data){
            console.log(data);
            if ( data.response == "ok" ) {
                $("#msg").addClass('ok').removeClass('err').html(data.message);
            } else {
                $("#msg").addClass('err').removeClass('ok').html(data.message);
            }
        });
        return false;
    });
    $("#details").setTemplateElement("t_details", null, {runnable_functions: true});
    $("#details").processTemplateURL("/details", null, {
            type: 'POST',
            headers: { 
                    Accept : "application/json; charset=utf-8"
            },
            on_success: function(){
                $("#search").autocomplete({
                    source: "<%= url_for 'search' %>",
                    minLength: 2,
                    select: function(event, ui) {
                        $("#details").processTemplateURL("/details", null, {
                                type: 'POST',
                                data: {details: ui.item.value},
                                headers: { 
                                        Accept : "application/json; charset=utf-8"
                                }
                        });
                    }
                });
            }
    });
});
</script>
</head>
<body>
%= link_to Logout => 'logout'
<div id="details" class="jTemplatesTest"></div>
<textarea id="t_details" style="display:none">
%= include $role
</textarea>
</body>
</html>

@@ admin.html.ep
    %= link_to User => '/home'
    <hr />
    Search: <%= text_field 'search', id=>'search' %>
    <hr />
    <form id="form">
    <input type="hidden" name="superior" value="{$T.superior}">
    <table>
    <tr><td>DN</td><td><input type="text" name="newsup" value="{$T.superior}"></td></tr>
    <tr><td>Name</td><td><input type="text" name="name" value="{$T.gecos}"></td></tr>
    <tr><td>First Name</td><td><input type="text" name="o_givenName" value="{$T.givenName}"></td></tr>
    <tr><td>Last Name</td><td><input type="text" name="o_sn" value="{$T.sn}"></td></tr>
    <tr><td>Username</td><td><input type="text" name="o_uid" value="{$T.uid}"></td></tr>
    <tr><td>Password</td><td><input type="text" name="o_userPassword" value="{$T.userPassword}"></td></tr>
    <tr><td>Home Directory</td><td><input type="text" name="o_homeDirectory" value="{$T.homeDirectory}"></td></tr>
    <tr><td>Account Status</td><td><input type="text" name="o_accountStatus" value="{$T.accountStatus}"></td></tr>
    <tr><td>E-mail Address</td><td><input type="text" name="o_mail" value="{$T.mail}"></td></tr>
    <tr><td>Login Shell</td><td><input type="text" name="o_loginShell" value="{$T.loginShell}"></td></tr>
    <tr><td>Description</td><td><input type="text" name="o_description" value="{$T.description}"></td></tr>
    <tr><td colspan=2><%= submit_button 'Update' %></td></tr>
    <tr><td colspan=2><div id="msg"></div></td></tr>
    </table>
    </form>

@@ user.html.ep
    %= link_to Admin => '/home/admin'
    <form id="form">
    <table>
    <tr><td>Name</td><td>{$T.gecos}</td></tr>
    <tr><td>First Name</td><td>{$T.givenName}</td></tr>
    <tr><td>Last Name</td><td>{$T.sn}</td></tr>
    <tr><td>Username</td><td>{$T.uid}</td></tr>
    <tr><td>Password</td><td><%= password_field 'o_userPassword' %> -> <%= password_field 'userPassword2' %></td></tr>
    <tr><td>Home Directory</td><td>{$T.homeDirectory}</td></tr>
    <tr><td>Account Status</td><td>{$T.accountStatus}</td></tr>
    <tr><td>E-mail Address</td><td>{$T.mail}</td></tr>
    <tr><td>Login Shell</td><td>{$T.loginShell}</td></tr>
    <tr><td>Description</td><td>{$T.description}</td></tr>
    <tr><td colspan=2><%= submit_button 'Update' %></td></tr>
    <tr><td colspan=2><div id="msg"></div></td></tr>
    </table>
    </form>
