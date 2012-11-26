use Mojolicious::Lite;  
use Mojo::JSON;
use FindBin qw($Bin);
use lib "$Bin/lib";
use File::Basename;
use Switch;
use Net::LDAP;
use Net::LDAP::Util 'ldap_explode_dn';
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
		return $search->count;
	},
	is_role => sub {
		my ($self, $role, $extradata) = @_;
		my $uid = $self->current_user->get_value('uid');
		my $search = $self->ldap->search(
			base=>$self->config->{ldapbase},
			filter => "(&(cn=$role)(objectClass=posixGroup))",
		);
		$search->code and do { warn $search->error; return 0; };
		return $search->count;
	},
	user_privs => sub {
		my ($self, $extradata) = @_;
		my $uid = $self->current_user->get_value('uid');
		my $search = $self->ldap->search(
			base=>$self->config->{ldapbase},
			filter => "(&(objectClass=posixGroup)(memberuid=$uid))",
		);
		$search->code and do { warn $search->error; return 0; };
		return map { $_->get_value('cn') } $search->entries;
	},
	user_role => sub {
		my ($self, $extradata) = @_;
		return $self->has_priv("Domain Admins") ? 'admin' : 'user';
	},
};

helper ldap => sub { return $ldap };
helper find => sub {
	my $self = shift;
	my $uid = shift;
	return undef unless $uid;
        $_ = $self->ldap->search(
                base=>$self->config->{ldapbase},
                filter => "(&(uid=$uid)(objectClass=posixAccount))",
        );
        $_->code and return undef;
	return $_->entry(0);
};
helper search => sub {
	my $self = shift;
	my $q = shift;
	return () unless $q;
        $_ = $self->ldap->search(
                base=>$self->config->{ldapbase},
                filter => "(&(objectClass=person)(|(uid=$q*)(sn=$q*)(givenName=$q*)))",
        );
        return () if $_->is_error;
        return () unless $_->entries;
        return map { {label=>($_->get_value('gecos')||join(' ', $_->get_value('givenName')||'',$_->get_value('sn')||'')).' ('.$_->get_value('uid').')',value=>$_->get_value('uid')} } grep { $_->get_value('uid') } $_->entries;
};
helper ous => sub {
	my $self = shift;
        my $search = $self->ldap->search(
                base=>$self->config->{ldapbase},
                filter => "objectClass=organizationalUnit",
		attr => ['description'],
        );
        $search->code and do { warn $search->error; return undef; };
	my @ous = ();
	foreach ( $search->entries ) {
		next unless $_->dn && $_->get_value('description');
		push @ous, [$_->get_value('description') => lc($_->dn)];
	}
	return sort { $a->[0] cmp $b->[0] } @ous;
};
helper replace => sub {
	my $self = shift;
	my $dn = shift;
	return ('err','Error!') unless $dn;
	%_ = (@_);
	($_{sambaLMPassword}, $_{sambaNTPassword}) = (lmhash($_{userPassword}), nthash($_{userPassword})) if $_{userPassword};
warn Dumper($dn, {%_});
return 0?('err','Error!'):('ok','All good!');
#	$_ = $self->ldap->modify($dn, replace => {%_});
#	return $_->is_error?'err':'ok', $_->error;
};
helper delete => sub {
	my $self = shift;
	my $dn = shift;
	return ('err','Error!') unless $dn;
warn Dumper($dn);
return 0?('err','Error!'):('ok','All good!');
#	$_ = $self->ldap->delete($dn);
#	return $_->is_error?'err':'ok', $_->error;
};
helper add => sub {
	my $self = shift;
	my $dn = shift;
	my $attrs = shift;
	return ('err','Error!') unless $dn && ref $attrs eq 'ARRAY';
warn Dumper($dn, $attrs);
return 0?('err','Error!'):('ok','All good!');
#	$_ = $self->ldap->add($dn, attrs=>$attrs);
#	return $_->is_error?'err':'ok', $_->error;
};
helper rename => sub {
	my $self = shift;
	my $dn = shift;
	my $newrdn = shift;
	return ('err','Error!') unless $dn && $newrdn;
warn Dumper($dn, $newrdn);
return 0?('err','Error!'):('ok','All good!');
#	$_ = $self->ldap->moddn($dn, deleteoldrdn=>1, newrdn=>$newrdn);
#	return $_->is_error?'err':'ok', $_->error;
};
helper move => sub {
	my $self = shift;
	my $dn = shift;
	my $newlocation = shift;
	return ('err','Error!') unless $dn && $newlocation;
warn Dumper($dn, $newlocation);
return 0?('err','Error!'):('ok','All good!');
#	$_ = $self->ldap->moddn($dn, newsuperior=>$newlocation);
#	return $_->is_error?'err':'ok', $_->error;
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
	my $location = $details->dn;
	$location =~ s/^[^,]+,//;
	$self->render_json({
		dn => lc($details->dn)||'',
		location => lc($location)||'',
		gecos => $details->get_value('gecos')||'',
		givenName => $details->get_value('givenName')||'',
		sn => $details->get_value('sn')||'',
		uid => $details->get_value('uid')||'',
		userPassword => $details->get_value('userPassword')||'',
		homeDirectory => $details->get_value('homeDirectory')||'',
		accountStatus => $details->get_value('accountStatus')||'',
		mail => $details->get_value('mail')||'',
		loginShell => $details->get_value('loginShell')||'',
		description => $details->get_value('description')||'',
	});
};

under '/home' => (authenticated => 1);
get '/' => {template=>'home', view=>'user'};
post '/changepassword' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($res, $msg) = $self->replace($self->param('dn'),
		userPassword => $self->param('userPassword'),
	);
	$self->render_json({response=>$res,message=>$msg});
};

under '/home/admin' => (authenticated => 1, has_priv => 'Domain Admins');
get '/' => {template=>'home',view=>'admin'};
get '/search' => (is_xhr=>1) => sub {
	my $self = shift;
	$self->render_json([$self->search($self->param('term'))]);
};
post '/addou' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($location, $ou, $description) = ($self->param('location'), $self->param('ou'), $self->param('description'));
	return $self->render_json({response=>'err',message=>'Error!'}) unless $location && $ou && $description;
	my ($res, $msg) = $self->add("ou=$ou,$location", [objectClass => ['top', 'organizationalUnit'], ou => $ou, description => $description]);
	$self->render_json({response=>$res,message=>$msg});
};
post '/resetdir' => (is_xhr=>1) => sub {
	my $self = shift;
	my $uid = shift;
	return $self->render_json({response=>'err',message=>'Error!'}) unless $uid;
	warn "Resetting User $uid\n";
	my ($res, $msg) = 0?('err','Error!'):('ok','All good!');
	$self->render_json({response=>$res,message=>$msg});
};
post '/update' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($res, $msg);
	if ( $self->param('newuid') ne $self->param('uid') ) {
            ($res, $msg) = $self->rename($self->param('dn'), "uid=".$self->param('newuid'));
	} elsif ( $self->param('newlocation') ne $self->param('location') ) {
            ($res, $msg) = $self->move($self->param('dn'), $self->param('newlocation'));
	} else {
            ($res, $msg) = $self->replace($self->param('dn'),
                    gecos => $self->param('gecos'),
                    givenName => $self->param('givenName'),
                    sn => $self->param('sn'),
                    uid => $self->param('uid'),
                    userPassword => $self->param('userPassword'),
                    homeDirectory => $self->param('homeDirectory'),
                    accountStatus => $self->param('accountStatus'),
                    mail => $self->param('mail'),
                    loginShell => $self->param('loginShell'),
                    description => $self->param('description'),
            );
	}
	$self->render_json({response=>$res,message=>$msg});
};
post '/remove' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($res, $msg) = $self->delete($self->param('dn'));
	$self->render_json({response=>$res,message=>$msg});
};
post '/copy' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($res, $msg) = $self->add($self->param('dn'),
		gecos => $self->param('gecos'),
		givenName => $self->param('givenName'),
		sn => $self->param('sn'),
		uid => $self->param('uid'),
		userPassword => $self->param('userPassword'),
		homeDirectory => $self->param('homeDirectory'),
		accountStatus => $self->param('accountStatus'),
		mail => $self->param('mail'),
		loginShell => $self->param('loginShell'),
		description => $self->param('description'),
	);
	$self->render_json({response=>$res,message=>$msg});
};
get '/gads' => (is_xhr=>1) => sub {
	my $self = shift;
	warn "Executing GADS\n";
	my ($res, $msg) = 0?('err','Error!'):('ok','All good!');
	$self->render_json({response=>$res,message=>$msg});
};
get '/backup' => (is_xhr=>1) => sub {
	my $self = shift;
	warn "Making backup\n";
	my ($res, $msg) = 0?('err','Error!'):('ok','All good!');
	$self->render_json({response=>$res,message=>$msg});
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
<style>
    * {font-family:verdana; font-size:12px;}
    .link {font-size:10px;text-decoration:underline;color:blue;cursor:pointer;}
    div.modal,div.msg {display:none;}
    .err {color:red;}
    .ok {color:green;}
</style>
<link   href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8/themes/base/jquery-ui.css" type="text/css" rel="stylesheet" media="all" />
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.8/jquery.min.js" type="text/javascript"></script>
<script src="http://ajax.googleapis.com/ajax/libs/jqueryui/1.9.1/jquery-ui.min.js" type="text/javascript"></script>
<script src="http://jtemplates.tpython.com/jTemplates/jquery-jtemplates.js" type="text/javascript"></script>
<script type="text/javascript">
$(document).ready(function(){
    $("#gads").click(function(){
        $.get("<%= url_for 'gads' %>", null, function(data){
            console.log(data);
            if ( data.response == "ok" ) {
                $("#admin-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
            } else {
                $("#admin-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
            }
        });
    });
    $("#backup").click(function(){
        $.get("<%= url_for 'backup' %>", null, function(data){
            console.log(data);
            if ( data.response == "ok" ) {
                $("#admin-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
            } else {
                $("#admin-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
            }
        });
    });

    function bind_buttons () {
        $("#newlocation").val($("#location").val()); // Select OU in form
        $("#addou-location").val("ou=people,o=local"); // Select Location in Add OU form
        $("#search").val("");
        $("#changepassword").click(function(){
            var u1 = $("#form").find('input[name=userPassword]').val();
            var u2 = $("#form").find('input[name=userPassword2]').val();
            if ( u1 != u2 ) {
                $("#user-msg").addClass('err').removeClass('ok').html("Passwords do not match!");
                return false;
            }
            $.post("<%= url_for 'changepassword' %>", $("#form").serialize(), function(data){
                console.log(data);
                if ( data.response == "ok" ) {
                    $("#user-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                } else {
                    $("#user-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                }
            });
            return false;
        });
        $("#resetdir").click(function(){
            $.post("<%= url_for 'resetdir' %>", {uid: $("#form input[name=uid]").val()}, function(data){
                console.log(data);
                if ( data.response == "ok" ) {
                    $("#user-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                } else {
                    $("#user-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                }
            });
        });
        $("#update").click(function(){
            $.post("<%= url_for 'update' %>", $("#form").serialize(), function(data){
                console.log(data);
                if ( data.response == "ok" ) {
                    $("#user-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                } else {
                    $("#user-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                }
            });
            return false;
        });
        $("#remove").click(function(){
            $.post("<%= url_for 'remove' %>", $("#form").serialize(), function(data){
                console.log(data);
                if ( data.response == "ok" ) {
                    $("#user-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                } else {
                    $("#user-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                }
            });
            return false;
        });
        $("#copy").attr('disabled', 'disabled').click(function(){
            $("#dialog-copy").dialog({
                autoOpen: false,
                height: 320,
                width: 380,
                modal: true,
                buttons: {
                    "Create New User": function() {
                        var copy = $(this);
                        if ( $("#copy-givenName").val() == "" ) {
                            $("#copy-msg").addClass('err').removeClass('ok').html("Missing First Name").show().delay(2500).fadeOut();
                        } else if ( $("#copy-sn").val() == "" ) {
                            $("#copy-msg").addClass('err').removeClass('ok').html("Missing Last Name").show().delay(2500).fadeOut();
                        } else if ( $("#copy-uid").val() == "" ) {
                            $("#copy-msg").addClass('err').removeClass('ok').html("Missing Username").show().delay(2500).fadeOut();
                        } else if ( $("#copy-userPassword").val() == "" ) {
                            $("#copy-msg").addClass('err').removeClass('ok').html("Missing Password").show().delay(2500).fadeOut();
                        } else {
                            $("#dn").val($("#dn").val().replace($("#uid").val(), $("#copy-uid").val()));
                            $("#homeDirectory").val($("#homeDirectory").val().replace($("#uid").val(), $("#copy-uid").val()));
                            $("#mail").val($("#mail").val().replace($("#uid").val(), $("#copy-uid").val()));
                            $("#newuid").val($("#copy-uid").val());
                            $("#uid").val($("#copy-uid").val());
                            copy.dialog("close");
                            $.post("<%= url_for 'update' %>", $("#form").serialize(), function(data){
                                console.log(data);
                                if ( data.response == "ok" ) {
                                    $("#user-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                                } else {
                                    $("#user-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                                }
                            });
                        }
                    },
                    Cancel: function() {
                        $(this).dialog("close");
                    }
                },
            });
            $("#dialog-copy").dialog("open");
        });
        $("#addou").click(function(){
            $("#dialog-addou").dialog({
                autoOpen: false,
                height: 320,
                width: 380,
                modal: true,
                buttons: {
                    "Add OU": function() {
                        var addou = $(this);
                        if ( $("#addou-location").val() == "" ) {
                            $("#addou-msg").addClass('err').removeClass('ok').html("Missing Location").show().delay(2500).fadeOut();
                        } else if ( $("#addou-ou").val() == "" ) {
                            $("#addou-msg").addClass('err').removeClass('ok').html("Missing OU").show().delay(2500).fadeOut();
                        } else if ( $("#addou-description").val() == "" ) {
                            $("#addou-msg").addClass('err').removeClass('ok').html("Missing Description").show().delay(2500).fadeOut();
                        } else {
                            $.post("<%= url_for 'addou' %>", {location: $("#addou-location").val(), ou: $("#addou-ou").val(), description: $("#addou-description").val()}, function(data){
                                console.log(data);
                                if ( data.response == "ok" ) {
                                    $("#addou-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                                    addou.dialog("close");
                                } else {
                                    $("#addou-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                                }
                            });
                        }
                    },
                    Cancel: function() {
                        $(this).dialog("close");
                    }
                },
            });
            $("#dialog-addou").dialog("open");
        });
    }

    $("#details").setTemplateElement("t_details", null, {runnable_functions: true});
    $("#search").autocomplete({
        source: "<%= url_for 'search' %>",
        minLength: 2,
        select: function(event, ui) {
            $("#details").processTemplateURL("/details", null, {
                    type: 'POST',
                    data: {details: ui.item.value},
                    headers: { 
                            Accept : "application/json; charset=utf-8"
                    },
                    on_success: bind_buttons
            });
        }
    });
    $("#details").processTemplateURL("/details", null, {
            type: 'POST',
            headers: { 
                    Accept : "application/json; charset=utf-8"
            },
            on_success: bind_buttons
    });
});
</script>
</head>
<body>
%= link_to Logout => 'logout'
<br />
% if ( $view eq 'admin' ) {
    %= link_to User => '/home'
    <hr />
    Search: <%= text_field 'search', id=>'search' %>
    <hr />
% } else {
    %= link_to Admin => '/home/admin'
% }
<div id="details" class="jTemplatesTest"></div>
% if ( $view eq 'admin' ) {
    <hr />
    <button id="gads">Google Sync</button> <button id="backup">Download Backup</button>
    <div id="admin-msg" class="msg">
% }
<textarea id="t_details" style="display:none">
%= include $view
</textarea>
<div id="dialog-addou" title="New OU" class="modal">
        <form id="addou-form">
        <table>
        <tr><td>Location</td><td><%= select_field location => [$self->ous], id => 'addou-location' %></td></tr>
        <tr><td>OU</td><td><input id="addou-ou" type='text' name='dn' maxlength='60'></td></tr>
        <tr><td>Description</td><td><input id="addou-description" type='text' name='description' maxlength='60'></td></tr>
        <tr><td colspan="2"><div id="addou-msg" class="msg"></div></td></tr>
        </table>
        </form>
</div>  
<div id="dialog-copy" title="Copy User" class="modal">
        <form id="copy-form">
        <table>
        <tr><td>First Name</td><td><input id="copy-givenName" type='text' name='givenName' maxlength='60'></td></tr>
        <tr><td>Last Name</td><td><input id="copy-sn" type='text' name='sn' maxlength='60'></td></tr>
        <tr><td>Username</td><td><input id="copy-uid" type='text' name='uid' maxlength='60'></td></tr>
        <tr><td>Password</td><td><input id="copy-userPassword" type='text' name='userPassword' maxlength='60'></td></tr>
        <tr><td colspan="2"><div id="copy-msg" class="msg"></div></td></tr>
        </table>
        </form>
</div>  

</body>
</html>

@@ admin.html.ep
    <form id="form">
    <input type="hidden" name="dn" value="{$T.dn}" id="dn">
    <input type="hidden" name="location" value="{$T.location}" id="location">
    <input type="hidden" name="uid" value="{$T.uid}" id="uid">
    <table>
    <tr><td>OU</td><td><%= select_field newlocation => [$self->ous], id => 'newlocation' %> <img src="/plus.png" id="addou" class="link"></td></tr>
    <tr><td>Name</td><td><input type="text" name="gecos" value="{$T.gecos}" id="gecos"></td></tr>
    <tr><td>First Name</td><td><input type="text" name="givenName" value="{$T.givenName}" id="givenName"></td></tr>
    <tr><td>Last Name</td><td><input type="text" name="sn" value="{$T.sn}" id="sn"></td></tr>
    <tr><td>Username</td><td><input type="text" name="newuid" value="{$T.uid}" id="newuid"></td></tr>
    <tr><td>Password</td><td><input type="text" name="userPassword" value="{$T.userPassword}" id="userPassword"></td></tr>
    <tr><td>Home Directory</td><td><input type="text" name="homeDirectory" value="{$T.homeDirectory}" id="homeDirectory"> <img src="/reset.png" id="resetdir" class="link" height=16 width=20></td></tr>
    <tr><td>Account Status</td><td><input type="text" name="accountStatus" value="{$T.accountStatus}"></td></tr>
    <tr><td>E-mail Address</td><td><input type="text" name="mail" value="{$T.mail}" id="mail"></td></tr>
    <tr><td>Login Shell</td><td><input type="text" name="loginShell" value="{$T.loginShell}"></td></tr>
    <tr><td>Description</td><td><input type="text" name="description" value="{$T.description}"></td></tr>
    <tr><td colspan=2><button id="update">Update</button> <button id="remove">Remove</button> <button id="copy">Copy</button></td></tr>
    <tr><td colspan=2><div id="user-msg" class="msg"></div></td></tr>
    </table>
    </form>

@@ user.html.ep
    <form id="form">
    <table>
    <tr><td>Name</td><td>{$T.gecos}</td></tr>
    <tr><td>E-mail Address</td><td>{$T.mail}</td></tr>
    <tr><td>Account Status</td><td>{$T.accountStatus}</td></tr>
    <tr><td style="vertical-align:top">Password</td><td><%= password_field 'userPassword' %><br /><%= password_field 'userPassword2' %></td></tr>
    <tr><td colspan=2><button id="changepassword">Change Password</button></td></tr>
    <tr><td colspan=2><div id="user-msg" class="msg"></div></td></tr>
    </table>
    </form>

@@ plus.png (base64)
/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAkGBwgHBgkIBwgKCgkLDRYPDQwM
DRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5Ojf/
2wBDAQoKCg0MDRoPDxo3JR8lNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3
Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzf/wAARCAAQABADASIAAhEBAxEB/8QA
FgABAQEAAAAAAAAAAAAAAAAAAwQH/8QAIxAAAQMEAQQDAAAAAAAAAAAAAQID
BAUREiEABhMiMRQjQv/EABUBAQEAAAAAAAAAAAAAAAAAAAIF/8QAHBEAAgIC
AwAAAAAAAAAAAAAAAREAAgQUMWGx/9oADAMBAAIRAxEAPwDVK1WI6ozsaK89
8jupQS22sWssBfmBYay3fg0isMRG5DU5+Rp27anEOOAIxT+7HV8vZ1wuoKQ3
Divz2pL4+5K1NqwwAW4M943A8lH3rktBpTVYjSHXpT3aDnbCWigpUnBJO8Sf
ZUNHkq18naAAHHaT9hZc/9k=

@@ copy.png (base64)
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAAK/I
NwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAABg
UExURcji/lllnGV1qP7//7jK/+Xy/7fa/5HG/22T0YnC/1xhkW2Kwmh/tHSa
1rG7y9nt/1pdjKex//Hx8qjC/8HDyPj7/nGSzeDv/8XY/5+9/+32/19omXyn
32Ftn3Od6v///5dPi28AAAAgdFJOU///////////////////////////////
//////////8AXFwb7QAAAONJREFUeNpikJfhAAFGPnkIAAggBnleZlEhISFG
GagIQAABBUSZmZmlGBkZIQIAAcQgLyYF5LMyyEEFAAKIQZ6blZWVlwNikIi8
PEAAAQX42dnFQNpEpRg5ROQBAohBnoeBgYFbCsQXBxkEEEAM8kwM7OzcrCA+
v4QgozxAAAEF2NjYePghACgAEEAM8rJs7Ow8QFUgABQACCAGeWkWFhaQOSAA
FAAIIAZ5LiBgYgMr4AQKAAQQA9g1smwQABQACCCIgDRQBScQAAUAAggiwMUC
AsLCkozyAAEEFRCAAkZ5gAADAKOYD7TsXpWTAAAAAElFTkSuQmCC

@@ reset.png (base64)
iVBORw0KGgoAAAANSUhEUgAAAB0AAAATCAIAAADj+5EoAAAACXBIWXMAABTq
AAAU6gFxlYZXAAAAHnRFWHRTb2Z0d2FyZQBBRlBMIEdob3N0c2NyaXB0IDgu
MTQi0fnWAAADNklEQVR4nLXV3U9TdxgH8Oc557SlUE4tgjOU1kp5EYWZxZmK
XZiwZOIkzphGSTRu0QujMSxLpokXLlxs/8BmpokXXnijJDpfQoBkmzdDjdNI
EbvIm7Qc2p5jD9AWaHvenl0Q9cIlPTf8bp/n98k3z8XzIBHBGjxmLdD/cVVJ
UgRhJhQK8/xoRcXounVhR/lMKKQIgipJ5l0kIioUAACtVlLV6UOHlp4/r/F6
na2t5HZDOouzs+nICyE269ixo/b2bbRazbpjtbVos9UPDETPnKlaWLAHg5zb
zUajJIqUXUJZ1gt5DTFvtb5xOuv6+5FlTblhh8N38qT4+PEGjuM7Oph0GtJp
kKQ/IpEHkmTRdR1xC8seRcxomtTe7r93r2hqbnUCZTU1NS5Xyc6dzOIiJJMw
P98/MqIcPvzNsWMAgIjJ4eGfzp8HgNJI5HuOK5r3bQdRaWUlxOMUi2E+fz8S
Mbq7Pzt3rsrnW61XNzXxLS2p6em+np5f9u37bmjIlEsAQESTk5jL3Z2Z4U6c
aO3pqfR43vWVuVzbOztB0UuIuX72tKm8CGDhOMhkMJeDeNyfSr0aG5uPxSo9
nkfCo8GJIQQGEYkIGUavLwjf+k25anrpVl+fNjVFigKZjAVgeHCQ7+xsCAZH
EuG/xYGOxk9UwwAARFzhVp7V5025f3Z5N/tbse1zAgJEDTEAUBcIAEDAHVgG
qcy12ODjC5SSZUaaz4uxOVPulXbrz18FuxtCH5Z5m9NCdmFpwtDm4ol/k0km
my0AFmWBA4BmW/3F3y+oX+aryquCnmC5zbFae5UavzNxk3gh0OT7J/5MTHJW
jmVRRxMwEpGYFbf1bmvZ5dM05VTzD5t4P5EBpfhQ+IuxJxob1j9JPJWSkqLo
KXnZydtv3nipXzaK50XA3XW7NjXq9rLC4NTV3GQJEatvXP5i68fe8ooniacp
UVJVPRlTlhMVuWrR0IuvVlzdv5qhdf3aVbeH+XS93ftRox1dqibMwcJLORV9
PZtb0RZlrTq3u/dA78HfviaAFz+OmnIBQDf0rkv7x+fG9x4p2cxZorIhA7As
JmLK67DS1tx27fi199+wyIhxje7Ff8vRgpPyuOVSAAAAAElFTkSuQmCC
