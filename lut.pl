use Mojolicious::Lite;  
use Mojo::JSON;
use FindBin qw($Bin);
use lib "$Bin/lib";
use File::Path;
use File::Find;
use File::Basename;
use Switch;
use Net::LDAP;
use Net::LDAP::Entry;
use Net::LDAP::LDIF;
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
app->types->type(ldif => 'application/ldif');

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
	warn 'find', Dumper($_->entry(0)->dn);
	return $_->entry(0);
};
helper finddn => sub {
	my $self = shift;
	my $dn = shift;
	return undef unless $dn;
        $_ = $self->ldap->search(
                base=>$dn,
                filter => "objectClass=posixAccount",
        );
        $_->code and return undef;
	warn 'finddn', Dumper($_->entry(0)->dn);
	return $_->entry(0);
};
helper search => sub {
	my $self = shift;
	my $q = shift;
	return () unless $q;
        $_ = $self->ldap->search(
                base=>$self->config->{ldapbase},
                filter => "(&(objectClass=posixAccount)(|(uid=$q*)(sn=$q*)(givenName=$q*)))",
        );
        return () if $_->is_error;
        return () unless $_->entries;
	warn 'search', Dumper({entries => scalar $search->entries});
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
	warn 'replace', Dumper($dn, {%_});
	$_ = $self->ldap->modify($dn, replace => {%_});
	$self->lut_error($_);
};
helper delete => sub {
	my $self = shift;
	my $dn = shift;
	return ('err','Error!') unless $dn;
	warn 'delete', Dumper($dn);
	$_ = $self->ldap->delete($dn);
	$self->lut_error($_);
};
helper add => sub {
	my $self = shift;
	my $dn = shift;
	my %attrs = @_;
	return ('err','Error!') unless $dn;
	warn 'add', Dumper($dn, {%attrs});
	$_ = $self->ldap->add($dn, attrs=>[%attrs]);
	$self->lut_error($_);
};
helper rename => sub {
	my $self = shift;
	my $dn = shift;
	my $newrdn = shift;
	return ('err','Error!') unless $dn && $newrdn;
	#warn 'rename', Dumper($dn, {deleteoldrdn=>1, newrdn=>$newrdn});
	$_ = $self->ldap->moddn($dn, deleteoldrdn=>1, newrdn=>$newrdn);
	$self->param('dn', $_->dn);
	$self->lut_error($_);
};
helper move => sub {
	my $self = shift;
	my $dn = shift;
	my $newlocation = shift;
	return ('err','Error!') unless $dn && $newlocation;
	#warn 'move', Dumper($dn, {newsuperior=>$newlocation});
	$_ = $self->ldap->moddn($dn, newsuperior=>$newlocation);
	$self->param('dn', $_->dn);
	$self->lut_error($_);
};


helper resetdir => sub {
	my $self = shift;
	my $user = shift;
	return 'Requested user doesn\'t exist' unless defined $user;
	warn "Resetting User ", $user->dn, "\n";
	$self->system("sudo", "mkdir", "-p", $user->get_value('homeDirectory'));
	$self->system("sudo", "chmod", "0700", $user->get_value('homeDirectory')) if -e $user->get_value('homeDirectory');
	$self->system("sudo", "chown", "-RLP", $user->get_value('uid').'.'.$user->get_value('gidNumber'), $user->get_value('homeDirectory')) if -e $user->get_value('homeDirectory');
};
helper system => sub {
	my $self = shift;
	my @system = @_;
	warn join(' ', @system), "\n";
	system @system;
	if ( $? == -1 ) {
		$self->lut_error("Failed to execute @system");
	} else {
		$self->lut_error($? >> 8 ? $! : undef);
	}
};
helper lut_error => sub {
	my $self = shift;
	my $msg = shift;
	if ( defined $msg ) {
		if ( ref $msg ) {
			push @{$self->{__LUT_ERROR}}, $msg->error if $msg->is_error;
		} else {
			push @{$self->{__LUT_ERROR}}, $msg;
		}
	}
	$msg = join ',', grep { defined $_ } @{$self->{__LUT_ERROR}};
	return $self->render_json(@{$self->{__LUT_ERROR}} ? {response=>'err',message=>$msg} : {response=>'ok',message=>'All is good!'});
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
	my $dn = $self->param('dn');
	my ($u1, $u2) = ($self->param('userPassword'), $self->param('userPassword2'));
	return $self->render_json({response=>'err',message=>'Error!  No user or passwords don\'t match'}) unless $dn && $u1 eq $u2;
	$self->replace($dn, userPassword => $u1);
	$self->lut_error;
};

under '/home/admin' => (authenticated => 1, has_priv => 'Domain Admins');
get '/' => {template=>'home',view=>'admin'};
get '/search' => (is_xhr=>1) => sub {
	my $self = shift;
	my $term = $self->param('term');
	return $self->render_json({response=>'err',message=>'Error!'}) unless $term;
	$self->render_json([$self->search($term)]);
};
post '/addou' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($location, $ou, $description) = ($self->param('location'), $self->param('ou'), $self->param('description'));
	return $self->render_json({response=>'err',message=>'Error!'}) unless $location && $ou && $description;
	$self->add("ou=$ou,$location", [objectClass => ['top', 'organizationalUnit'], ou => $ou, description => $description]);
	$self->lut_error;
};
post '/resetdir' => (is_xhr=>1) => sub {
	my $self = shift;
	my $dn = $self->param('dn');
	return $self->render_json({response=>'err',message=>'Error!'}) unless $dn;
	$self->resetdir($self->finddn($dn));
	$self->lut_error;
};
post '/update' => (is_xhr=>1) => sub {
	my $self = shift;
	my $dn = $self->param('dn');
	return $self->render_json({response=>'err',message=>'Error!'}) unless $dn;
	my $user = $self->finddn($dn);
        $self->replace($user->dn,
                gecos => $self->param('gecos'),
                givenName => $self->param('givenName'),
                sn => $self->param('sn'),
                userPassword => $self->param('userPassword'),
                homeDirectory => $self->param('homeDirectory'),
                accountStatus => $self->param('accountStatus'),
                mail => $self->param('mail'),
                loginShell => $self->param('loginShell'),
                description => $self->param('description'),
        );
	if ( $self->param('homeDirectory') ne $user->get_value('homeDirectory') ) {
	    $self->system("sudo", "mv", $user->get_value('homeDirectory'), $self->param('homeDirectory')) if -e $user->get_value('homeDirectory') && ! -e $self->param('homeDirectory');
	    $self->resetdir($user);
	}
	if ( lc($self->param('uid')) ne lc($user->get_value('uid')) ) {
            if ( $user = $self->rename($user->dn, "uid=".$self->param('uid')) ) {
		$user = $self->finddn($user->dn);
	    } else {
		$self->lut_error('Error renaming');
	    }
	}
	if ( lc($user->dn) ne lc('uid='.$self->param('uid').','.$self->param('location')) ) {
            if ( $user = $self->move($user->dn, $self->param('location')) ) {
	        $user = $self->finddn($user->dn);
	    } else {
		$self->lut_error('error moving');
	    }
	}
	$self->lut_error;
};
post '/remove' => (is_xhr=>1) => sub {
	my $self = shift;
	my $dn = $self->param('dn');
	return $self->render_json({response=>'err',message=>'Error!'}) unless $dn;
	my $user = $self->finddn($dn);
        $_ = $self->ldap->search(
                base=>$dn,
                filter=>'objectClass=*',
        );
#        open(my $fh, ">/tmp/backup.ldif");
#        my $ldif = Net::LDAP::LDIF->new($fh, "w", change=>0, onerror=>'undef');
#        $ldif->write_entry($_->entries);
#	return $self->render_json({response=>'err',message=>'Could not make backup of user\'s object'}) unless -e '/tmp/backup.ldif';
#	if ( $user->get_value('homeDirectory') && -e $user->get_value('homeDirectory') ) {
#	    $self->system("sudo", "mv", '/tmp/backup.ldif', $user->get_value('homeDirectory'));
#	    $self->system("sudo", "mkdir", "-p", '/data/deleted_users');
#	    $self->system("sudo", "mv", $user->get_value('homeDirectory'), '/data/deleted_users');
#	}
	$self->delete($dn);
	$self->lut_error;
};
post '/copy' => (is_xhr=>1) => sub {
	my $self = shift;
	return $self->render_json({response=>'err',message=>'Error!'}) unless $self->param('dn');
	my $from = $self->finddn($self->param('dn'));
	my @uids = ();
	while ( my (undef,undef,$uid) = getpwent ) {
		push @uids, $uid unless $uid >= 65000 
	}
	my $nextuid = 1000;
	foreach my $uid ( sort { $a <=> $b } @uids ) {
		last if $uid != ++$nextuid;
	}
	return $self->render_json({response=>'err',message=>'Cannot add any more users, out of UIDs!'}) if $nextuid >= 65000;
	endpwent;
	my $sambaSID = $from->get_value('sambaSID');
	$sambaSID =~ s/\d+$//;
	$self->add('uid='.$self->param('uid').','.$self->param('location'),
		objectClass => [$from->get_value('objectClass')],
		(map { $_ => $from->get_value($_) } grep { /^samba/ } $from->attributes),
		cn => [$self->param('givenName'), $self->param('gecos')],
		gidNumber => $from->get_value('gidNumber'),
		gecos => $self->param('gecos'),
		displayName => $self->param('gecos'),
		givenName => $self->param('givenName'),
		sn => $self->param('sn'),
		uid => $self->param('uid'),
		uidNumber => $nextuid,
		sambaSID => $sambaSID.($nextuid*2+1000),
		shadowLastChange => 13790,
		userPassword => $self->param('userPassword'),
		sambaLMPassword => lmhash($self->param('userPassword')),
		sambaNTPassword => nthash($self->param('userPassword')),
		homeDirectory => $self->param('homeDirectory'),
		accountStatus => $self->param('accountStatus'),
		mail => $self->param('mail'),
		loginShell => $self->param('loginShell'),
		description => $self->param('description'),
	);
	$self->resetdir($self->find($self->param('uid')));
	$self->lut_error;
};

get '/gads' => (is_xhr=>1) => sub {
	my $self = shift;
	my ($res, $msg);
	warn "Executing GADS\n";
	$self->system("sudo", "/usr/local/GoogleAppsDirSync/sync-cmd", "-c", "/etc/gads/Duchesne.xml", "-a");
	$self->lut_error;
};
get '/backup' => sub {
	my $self = shift;
	my ($res, $msg);
	warn "Making Backup\n";
	$_ = $self->ldap->search(
		base=>$self->config->{ldapbase},
		filter=>'objectClass=*',
	);
	open(my $fh, ">", \my $buffer);
	my $ldif = Net::LDAP::LDIF->new($fh, "w", change=>0, onerror=>'undef');
	$ldif->write_entry($_->entries);
	$self->cookie(fileDownload=>'true');
	$self->cookie(path=>'/');
	$self->render(text=>$buffer, format=>'ldif');
};

app->start;

__DATA__
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
<script src="/jquery-fileDownload.js" type="text/javascript"></script>
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

    $("a.button").button();
    $(document).on("click", "a.fileDownloadSimpleRichExperience", function () {
        $.fileDownload($(this).attr('href'), {
            preparingMessageHtml: "We are preparing your report, please wait...",
            failMessageHtml: "There was a problem generating your report, please try again."
        });
        return false; //this is critical to stop the click event which will trigger a normal file download!
    });

    function bind_buttons () {
        $("#location").val($("#Tlocation").val()); // Select OU in form
        $("#addou-location").val("ou=people,o=local"); // Select Location in Add OU form
        $("#search").val("");
        $("a.button").button();
        $("#changepassword").click(function(){
            var u1 = $("#form").find('input[name=userPassword]').val();
            var u2 = $("#form").find('input[name=userPassword2]').val();
            if ( u1 != u2 ) {
                $("#user-msg").addClass('err').removeClass('ok').html("Passwords do not match!");
                return false;
            }
            $.post("<%= url_for 'changepassword' %>", {dn: $("#form input[name=dn]").val(), userPassword: u1, userPassword2: u2}, function(data){
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
            $.post("<%= url_for 'resetdir' %>", {dn: $("#form input[name=dn]").val()}, function(data){
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
            $.post("<%= url_for 'remove' %>", {dn: $("#form input[name=dn]").val()}, function(data){
                console.log(data);
                if ( data.response == "ok" ) {
                    $("#user-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                    location.reload();
                } else {
                    $("#user-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                }
            });
            return false;
        });
        $("#copy").click(function(){
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
			    var origuid=$("#uid").val();
                            $("#homeDirectory").val($("#homeDirectory").val().replace($("#uid").val(), $("#copy-uid").val()));
                            $("#mail").val($("#mail").val().replace($("#uid").val(), $("#copy-uid").val()));
                            $("#uid").val($("#copy-uid").val());
                            $("#givenName").val($("#copy-givenName").val());
                            $("#sn").val($("#copy-sn").val());
                            $("#gecos").val($("#copy-givenName").val()+' '+$("#copy-sn").val());
                            $("#userPassword").val($("#copy-userPassword").val());
                            copy.dialog("close");
                            $.post("<%= url_for 'copy' %>", $("#form").serialize(), function(data){
                                console.log(data);
                                if ( data.response == "ok" ) {
                                    $("#user-msg").addClass('ok').removeClass('err').html(data.message).show().delay(2500).fadeOut();
                                } else {
                                    $("#user-msg").addClass('err').removeClass('ok').html(data.message).show().delay(2500).fadeOut();
                                }
                            });
                            $("#dn").val($("#dn").val().replace(origuid, $("#copy-uid").val()));
			    $("#copy-givenName").val('');
			    $("#copy-sn").val('');
			    $("#copy-uid").val('');
			    $("#copy-userPassword").val('');
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
			    location.reload();
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
  % if ( $self->has_priv("Domain Admins") ) {
      %= link_to Admin => '/home/admin'
      <br />
  % }
% }
<div id="details" class="jTemplatesTest"></div>
% if ( $view eq 'admin' ) {
    <hr />
    <a class="button" id="gads">Google Sync</a> <a class="button fileDownloadSimpleRichExperience" href="<%= url_for 'backup' %>" id="backup">Download Backup</a>
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
    <input type="hidden" name="Tlocation" value="{$T.location}" id="Tlocation"> <!-- This exists just so jquery can set the selected location -->
    <table>
    <tr><td>OU</td><td><%= select_field location => [$self->ous], id => 'location' %> <img src="/plus.png" id="addou" class="link" height=12 width=12></td></tr>
    <tr><td>Name</td><td><input type="text" name="gecos" value="{$T.gecos}" id="gecos"></td></tr>
    <tr><td>First Name</td><td><input type="text" name="givenName" value="{$T.givenName}" id="givenName"></td></tr>
    <tr><td>Last Name</td><td><input type="text" name="sn" value="{$T.sn}" id="sn"></td></tr>
    <tr><td>Username</td><td><input type="text" name="uid" value="{$T.uid}" id="uid"></td></tr>
    <tr><td>Password</td><td><input type="text" name="userPassword" value="{$T.userPassword}" id="userPassword"></td></tr>
    <tr><td>Home Directory</td><td><input type="text" name="homeDirectory" value="{$T.homeDirectory}" id="homeDirectory"> <img src="/reset.png" id="resetdir" class="link" height=12 width=16></td></tr>
    <tr><td>Account Status</td><td><input type="text" name="accountStatus" value="{$T.accountStatus}"></td></tr>
    <tr><td>E-mail Address</td><td><input type="text" name="mail" value="{$T.mail}" id="mail"></td></tr>
    <tr><td>Login Shell</td><td><input type="text" name="loginShell" value="{$T.loginShell}"></td></tr>
    <tr><td>Description</td><td><input type="text" name="description" value="{$T.description}"></td></tr>
    <tr><td colspan=2><a class="button" id="update">Update</a> <a class="button" id="remove">Remove</a> <a class="button" id="copy">Copy</a></td></tr>
    <tr><td colspan=2><div id="user-msg" class="msg"></div></td></tr>
    </table>
    </form>

@@ user.html.ep
    <form id="form">
    <input type="hidden" name="dn" value="{$T.dn}" id="dn">
    <table>
    <tr><td>Name</td><td>{$T.gecos}</td></tr>
    <tr><td>E-mail Address</td><td>{$T.mail}</td></tr>
    <tr><td>Account Status</td><td>{$T.accountStatus}</td></tr>
    <tr><td style="vertical-align:top">Password</td><td><%= password_field 'userPassword' %><br /><%= password_field 'userPassword2' %></td></tr>
    <tr><td colspan=2><a class="button" id="changepassword">Change Password</a></td></tr>
    <tr><td colspan=2><div id="user-msg" class="msg"></div></td></tr>
    </table>
    </form>

@@ not_found.html.ep
The page you are looking for cannot be found.  Perhaps you need to login?
<hr />
%= include 'login'

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

@@ jquery-fileDownload.js (base64)
77u/LyoKKiBqUXVlcnkgRmlsZSBEb3dubG9hZCBQbHVnaW4gdjEuMy4zCioK
KiBodHRwOi8vd3d3LmpvaG5jdWx2aW5lci5jb20KKgoqIENvcHlyaWdodCAo
YykgMjAxMiAtIEpvaG4gQ3VsdmluZXIKKgoqIExpY2Vuc2VkIHVuZGVyIHRo
ZSBNSVQgbGljZW5zZToKKiAgIGh0dHA6Ly93d3cub3BlbnNvdXJjZS5vcmcv
bGljZW5zZXMvbWl0LWxpY2Vuc2UucGhwCiovCgp2YXIgJCA9IGpRdWVyeS5u
b0NvbmZsaWN0KCk7CgokLmV4dGVuZCh7CiAgICAvLwogICAgLy8kLmZpbGVE
b3dubG9hZCgnL3BhdGgvdG8vdXJsLycsIG9wdGlvbnMpCiAgICAvLyAgc2Vl
IGRpcmVjdGx5IGJlbG93IGZvciBwb3NzaWJsZSAnb3B0aW9ucycKICAgIGZp
bGVEb3dubG9hZDogZnVuY3Rpb24gKGZpbGVVcmwsIG9wdGlvbnMpIHsKCiAg
ICAgICAgdmFyIGRlZmF1bHRGYWlsQ2FsbGJhY2sgPSBmdW5jdGlvbiAocmVz
cG9uc2VIdG1sLCB1cmwpIHsKICAgICAgICAgICAgYWxlcnQoIkEgZmlsZSBk
b3dubG9hZCBlcnJvciBoYXMgb2NjdXJyZWQsIHBsZWFzZSB0cnkgYWdhaW4u
Iik7CiAgICAgICAgfTsKCiAgICAgICAgLy9wcm92aWRlIHNvbWUgcmVhc29u
YWJsZSBkZWZhdWx0cyB0byBhbnkgdW5zcGVjaWZpZWQgb3B0aW9ucyBiZWxv
dwogICAgICAgIHZhciBzZXR0aW5ncyA9ICQuZXh0ZW5kKHsKCiAgICAgICAg
ICAgIC8vCiAgICAgICAgICAgIC8vUmVxdWlyZXMgalF1ZXJ5IFVJOiBwcm92
aWRlIGEgbWVzc2FnZSB0byBkaXNwbGF5IHRvIHRoZSB1c2VyIHdoZW4gdGhl
IGZpbGUgZG93bmxvYWQgaXMgYmVpbmcgcHJlcGFyZWQgYmVmb3JlIHRoZSBi
cm93c2VyJ3MgZGlhbG9nIGFwcGVhcnMKICAgICAgICAgICAgLy8KICAgICAg
ICAgICAgcHJlcGFyaW5nTWVzc2FnZUh0bWw6IG51bGwsCgogICAgICAgICAg
ICAvLwogICAgICAgICAgICAvL1JlcXVpcmVzIGpRdWVyeSBVSTogcHJvdmlk
ZSBhIG1lc3NhZ2UgdG8gZGlzcGxheSB0byB0aGUgdXNlciB3aGVuIGEgZmls
ZSBkb3dubG9hZCBmYWlscwogICAgICAgICAgICAvLwogICAgICAgICAgICBm
YWlsTWVzc2FnZUh0bWw6IG51bGwsCgogICAgICAgICAgICAvLwogICAgICAg
ICAgICAvL3RoZSBzdG9jayBhbmRyb2lkIGJyb3dzZXIgc3RyYWlnaHQgdXAg
ZG9lc24ndCBzdXBwb3J0IGZpbGUgZG93bmxvYWRzIGluaXRpYXRlZCBieSBh
IG5vbiBHRVQ6IGh0dHA6Ly9jb2RlLmdvb2dsZS5jb20vcC9hbmRyb2lkL2lz
c3Vlcy9kZXRhaWw/aWQ9MTc4MAogICAgICAgICAgICAvL3NwZWNpZnkgYSBt
ZXNzYWdlIGhlcmUgdG8gZGlzcGxheSBpZiBhIHVzZXIgdHJpZXMgd2l0aCBh
biBhbmRyb2lkIGJyb3dzZXIKICAgICAgICAgICAgLy9pZiBqUXVlcnkgVUkg
aXMgaW5zdGFsbGVkIHRoaXMgd2lsbCBiZSBhIGRpYWxvZywgb3RoZXJ3aXNl
IGl0IHdpbGwgYmUgYW4gYWxlcnQKICAgICAgICAgICAgLy8KICAgICAgICAg
ICAgYW5kcm9pZFBvc3RVbnN1cHBvcnRlZE1lc3NhZ2VIdG1sOiAiVW5mb3J0
dW5hdGVseSB5b3VyIEFuZHJvaWQgYnJvd3NlciBkb2Vzbid0IHN1cHBvcnQg
dGhpcyB0eXBlIG9mIGZpbGUgZG93bmxvYWQuIFBsZWFzZSB0cnkgYWdhaW4g
d2l0aCBhIGRpZmZlcmVudCBicm93c2VyLiIsCgogICAgICAgICAgICAvLwog
ICAgICAgICAgICAvL1JlcXVpcmVzIGpRdWVyeSBVSTogb3B0aW9ucyB0byBw
YXNzIGludG8galF1ZXJ5IFVJIERpYWxvZwogICAgICAgICAgICAvLwogICAg
ICAgICAgICBkaWFsb2dPcHRpb25zOiB7IG1vZGFsOiB0cnVlIH0sCgogICAg
ICAgICAgICAvLwogICAgICAgICAgICAvL2EgZnVuY3Rpb24gdG8gY2FsbCBh
ZnRlciBhIGZpbGUgZG93bmxvYWQgZGlhbG9nL3JpYmJvbiBoYXMgYXBwZWFy
ZWQKICAgICAgICAgICAgLy9BcmdzOgogICAgICAgICAgICAvLyAgdXJsIC0g
dGhlIG9yaWdpbmFsIHVybCBhdHRlbXB0ZWQKICAgICAgICAgICAgLy8KICAg
ICAgICAgICAgc3VjY2Vzc0NhbGxiYWNrOiBmdW5jdGlvbiAodXJsKSB7IH0s
CgogICAgICAgICAgICAvLwogICAgICAgICAgICAvL2EgZnVuY3Rpb24gdG8g
Y2FsbCBhZnRlciBhIGZpbGUgZG93bmxvYWQgZGlhbG9nL3JpYmJvbiBoYXMg
YXBwZWFyZWQKICAgICAgICAgICAgLy9BcmdzOgogICAgICAgICAgICAvLyAg
cmVzcG9uc2VIdG1sICAgIC0gdGhlIGh0bWwgdGhhdCBjYW1lIGJhY2sgaW4g
cmVzcG9uc2UgdG8gdGhlIGZpbGUgZG93bmxvYWQuIHRoaXMgd29uJ3QgbmVj
ZXNzYXJpbHkgY29tZSBiYWNrIGRlcGVuZGluZyBvbiB0aGUgYnJvd3Nlci4K
ICAgICAgICAgICAgLy8gICAgICAgICAgICAgICAgICAgICAgaW4gbGVzcyB0
aGFuIElFOSBhIGNyb3NzIGRvbWFpbiBlcnJvciBvY2N1cnMgYmVjYXVzZSA1
MDArIGVycm9ycyBjYXVzZSBhIGNyb3NzIGRvbWFpbiBpc3N1ZSBkdWUgdG8g
SUUgc3ViYmluZyBvdXQgdGhlCiAgICAgICAgICAgIC8vICAgICAgICAgICAg
ICAgICAgICAgIHNlcnZlcidzIGVycm9yIG1lc3NhZ2Ugd2l0aCBhICJoZWxw
ZnVsIiBJRSBidWlsdCBpbiBtZXNzYWdlCiAgICAgICAgICAgIC8vICB1cmwg
ICAgICAgICAgICAgLSB0aGUgb3JpZ2luYWwgdXJsIGF0dGVtcHRlZAogICAg
ICAgICAgICAvLwogICAgICAgICAgICBmYWlsQ2FsbGJhY2s6IGRlZmF1bHRG
YWlsQ2FsbGJhY2ssCgogICAgICAgICAgICAvLwogICAgICAgICAgICAvLyB0
aGUgSFRUUCBtZXRob2QgdG8gdXNlLiBEZWZhdWx0cyB0byAiR0VUIi4KICAg
ICAgICAgICAgLy8KICAgICAgICAgICAgaHR0cE1ldGhvZDogIkdFVCIsCgog
ICAgICAgICAgICAvLwogICAgICAgICAgICAvLyBpZiBzcGVjaWZpZWQgd2ls
bCBwZXJmb3JtIGEgImh0dHBNZXRob2QiIHJlcXVlc3QgdG8gdGhlIHNwZWNp
ZmllZCAnZmlsZVVybCcgdXNpbmcgdGhlIHNwZWNpZmllZCBkYXRhLgogICAg
ICAgICAgICAvLyBkYXRhIG11c3QgYmUgYW4gb2JqZWN0ICh3aGljaCB3aWxs
IGJlICQucGFyYW0gc2VyaWFsaXplZCkgb3IgYWxyZWFkeSBhIGtleT12YWx1
ZSBwYXJhbSBzdHJpbmcKICAgICAgICAgICAgLy8KICAgICAgICAgICAgZGF0
YTogbnVsbCwKCiAgICAgICAgICAgIC8vCiAgICAgICAgICAgIC8vYSBwZXJp
b2QgaW4gbWlsbGlzZWNvbmRzIHRvIHBvbGwgdG8gZGV0ZXJtaW5lIGlmIGEg
c3VjY2Vzc2Z1bCBmaWxlIGRvd25sb2FkIGhhcyBvY2N1cmVkIG9yIG5vdAog
ICAgICAgICAgICAvLwogICAgICAgICAgICBjaGVja0ludGVydmFsOiAxMDAs
CgogICAgICAgICAgICAvLwogICAgICAgICAgICAvL3RoZSBjb29raWUgbmFt
ZSB0byBpbmRpY2F0ZSBpZiBhIGZpbGUgZG93bmxvYWQgaGFzIG9jY3VyZWQK
ICAgICAgICAgICAgLy8KICAgICAgICAgICAgY29va2llTmFtZTogImZpbGVE
b3dubG9hZCIsCgogICAgICAgICAgICAvLwogICAgICAgICAgICAvL3RoZSBj
b29raWUgdmFsdWUgZm9yIHRoZSBhYm92ZSBuYW1lIHRvIGluZGljYXRlIHRo
YXQgYSBmaWxlIGRvd25sb2FkIGhhcyBvY2N1cmVkCiAgICAgICAgICAgIC8v
CiAgICAgICAgICAgIGNvb2tpZVZhbHVlOiAidHJ1ZSIsCgogICAgICAgICAg
ICAvLwogICAgICAgICAgICAvL3RoZSBjb29raWUgcGF0aCBmb3IgYWJvdmUg
bmFtZSB2YWx1ZSBwYWlyCiAgICAgICAgICAgIC8vCiAgICAgICAgICAgIGNv
b2tpZVBhdGg6ICIvIiwKCiAgICAgICAgICAgIC8vCiAgICAgICAgICAgIC8v
dGhlIHRpdGxlIGZvciB0aGUgcG9wdXAgc2Vjb25kIHdpbmRvdyBhcyBhIGRv
d25sb2FkIGlzIHByb2Nlc3NpbmcgaW4gdGhlIGNhc2Ugb2YgYSBtb2JpbGUg
YnJvd3NlcgogICAgICAgICAgICAvLwogICAgICAgICAgICBwb3B1cFdpbmRv
d1RpdGxlOiAiSW5pdGlhdGluZyBmaWxlIGRvd25sb2FkLi4uIiwKCiAgICAg
ICAgICAgIC8vCiAgICAgICAgICAgIC8vRnVuY3Rpb25hbGl0eSB0byBlbmNv
ZGUgSFRNTCBlbnRpdGllcyBmb3IgYSBQT1NULCBuZWVkIHRoaXMgaWYgZGF0
YSBpcyBhbiBvYmplY3Qgd2l0aCBwcm9wZXJ0aWVzIHdob3NlIHZhbHVlcyBj
b250YWlucyBzdHJpbmdzIHdpdGggcXVvdGF0aW9uIG1hcmtzLgogICAgICAg
ICAgICAvL0hUTUwgZW50aXR5IGVuY29kaW5nIGlzIGRvbmUgYnkgcmVwbGFj
aW5nIGFsbCAmLDwsPiwnLCIsXHIsXG4gY2hhcmFjdGVycy4KICAgICAgICAg
ICAgLy9Ob3RlIHRoYXQgc29tZSBicm93c2VycyB3aWxsIFBPU1QgdGhlIHN0
cmluZyBodG1sZW50aXR5LWVuY29kZWQgd2hpbHN0IG90aGVycyB3aWxsIGRl
Y29kZSBpdCBiZWZvcmUgUE9TVGluZy4KICAgICAgICAgICAgLy9JdCBpcyBy
ZWNvbW1lbmRlZCB0aGF0IG9uIHRoZSBzZXJ2ZXIsIGh0bWxlbnRpdHkgZGVj
b2RpbmcgaXMgZG9uZSBpcnJlc3BlY3RpdmUuCiAgICAgICAgICAgIC8vCiAg
ICAgICAgICAgIGVuY29kZUhUTUxFbnRpdGllczogdHJ1ZQogICAgICAgIH0s
IG9wdGlvbnMpOwoKCiAgICAgICAgLy9TZXR1cCBtb2JpbGUgYnJvd3NlciBk
ZXRlY3Rpb246IFBhcnRpYWwgY3JlZGl0OiBodHRwOi8vZGV0ZWN0bW9iaWxl
YnJvd3Nlci5jb20vCiAgICAgICAgdmFyIHVzZXJBZ2VudCA9IChuYXZpZ2F0
b3IudXNlckFnZW50IHx8IG5hdmlnYXRvci52ZW5kb3IgfHwgd2luZG93Lm9w
ZXJhKS50b0xvd2VyQ2FzZSgpOwoKICAgICAgICB2YXIgaXNJb3MgPSBmYWxz
ZTsgICAgICAgICAgICAgICAgICAvL2hhcyBmdWxsIHN1cHBvcnQgb2YgZmVh
dHVyZXMgaW4gaU9TIDQuMCssIHVzZXMgYSBuZXcgd2luZG93IHRvIGFjY29t
cGxpc2ggdGhpcy4KICAgICAgICB2YXIgaXNBbmRyb2lkID0gZmFsc2U7ICAg
ICAgICAgICAgICAvL2hhcyBmdWxsIHN1cHBvcnQgb2YgR0VUIGZlYXR1cmVz
IGluIDQuMCsgYnkgdXNpbmcgYSBuZXcgd2luZG93LiBQT1NUIHdpbGwgcmVz
b3J0IHRvIGEgUE9TVCBvbiB0aGUgY3VycmVudCB3aW5kb3cuCiAgICAgICAg
dmFyIGlzT3RoZXJNb2JpbGVCcm93c2VyID0gZmFsc2U7ICAgLy90aGVyZSBp
cyBubyB3YXkgdG8gcmVsaWFibHkgZ3Vlc3MgaGVyZSBzbyBhbGwgb3RoZXIg
bW9iaWxlIGRldmljZXMgd2lsbCBHRVQgYW5kIFBPU1QgdG8gdGhlIGN1cnJl
bnQgd2luZG93LgoKICAgICAgICBpZiAoL2lwKGFkfGhvbmV8b2QpLy50ZXN0
KHVzZXJBZ2VudCkpIHsKCiAgICAgICAgICAgIGlzSW9zID0gdHJ1ZTsKCiAg
ICAgICAgfSBlbHNlIGlmICh1c2VyQWdlbnQuaW5kZXhPZignYW5kcm9pZCcp
ICE9IC0xKSB7CgogICAgICAgICAgICBpc0FuZHJvaWQgPSB0cnVlOwoKICAg
ICAgICB9IGVsc2UgewoKICAgICAgICAgICAgaXNPdGhlck1vYmlsZUJyb3dz
ZXIgPSAvYXZhbnRnb3xiYWRhXC98YmxhY2tiZXJyeXxibGF6ZXJ8Y29tcGFs
fGVsYWluZXxmZW5uZWN8aGlwdG9wfHBsYXlib29rfHNpbGt8aWVtb2JpbGV8
aXJpc3xraW5kbGV8bGdlIHxtYWVtb3xtaWRwfG1tcHxuZXRmcm9udHxvcGVy
YSBtKG9ifGluKWl8cGFsbSggb3MpP3xwaG9uZXxwKGl4aXxyZSlcL3xwbHVj
a2VyfHBvY2tldHxwc3B8c3ltYmlhbnx0cmVvfHVwXC4oYnJvd3NlcnxsaW5r
KXx2b2RhZm9uZXx3YXB8d2luZG93cyAoY2V8cGhvbmUpfHhkYXx4aWluby9p
LnRlc3QodXNlckFnZW50KSB8fCAvMTIwN3w2MzEwfDY1OTB8M2dzb3w0dGhw
fDUwWzEtNl1pfDc3MHN8ODAyc3xhIHdhfGFiYWN8YWMoZXJ8b298c1wtKXxh
aShrb3xybil8YWwoYXZ8Y2F8Y28pfGFtb2l8YW4oZXh8bnl8eXcpfGFwdHV8
YXIoY2h8Z28pfGFzKHRlfHVzKXxhdHR3fGF1KGRpfFwtbXxyIHxzICl8YXZh
bnxiZShja3xsbHxucSl8YmkobGJ8cmQpfGJsKGFjfGF6KXxicihlfHYpd3xi
dW1ifGJ3XC0obnx1KXxjNTVcL3xjYXBpfGNjd2F8Y2RtXC18Y2VsbHxjaHRt
fGNsZGN8Y21kXC18Y28obXB8bmQpfGNyYXd8ZGEoaXR8bGx8bmcpfGRidGV8
ZGNcLXN8ZGV2aXxkaWNhfGRtb2J8ZG8oY3xwKW98ZHMoMTJ8XC1kKXxlbCg0
OXxhaSl8ZW0obDJ8dWwpfGVyKGljfGswKXxlc2w4fGV6KFs0LTddMHxvc3x3
YXx6ZSl8ZmV0Y3xmbHkoXC18Xyl8ZzEgdXxnNTYwfGdlbmV8Z2ZcLTV8Z1wt
bW98Z28oXC53fG9kKXxncihhZHx1bil8aGFpZXxoY2l0fGhkXC0obXxwfHQp
fGhlaVwtfGhpKHB0fHRhKXxocCggaXxpcCl8aHNcLWN8aHQoYyhcLXwgfF98
YXxnfHB8c3x0KXx0cCl8aHUoYXd8dGMpfGlcLSgyMHxnb3xtYSl8aTIzMHxp
YWMoIHxcLXxcLyl8aWJyb3xpZGVhfGlnMDF8aWtvbXxpbTFrfGlubm98aXBh
cXxpcmlzfGphKHR8dilhfGpicm98amVtdXxqaWdzfGtkZGl8a2VqaXxrZ3Qo
IHxcLyl8a2xvbnxrcHQgfGt3Y1wtfGt5byhjfGspfGxlKG5vfHhpKXxsZygg
Z3xcLyhrfGx8dSl8NTB8NTR8ZVwtfGVcL3xcLVthLXddKXxsaWJ3fGx5bnh8
bTFcLXd8bTNnYXxtNTBcL3xtYSh0ZXx1aXx4byl8bWMoMDF8MjF8Y2EpfG1c
LWNyfG1lKGRpfHJjfHJpKXxtaShvOHxvYXx0cyl8bW1lZnxtbygwMXwwMnxi
aXxkZXxkb3x0KFwtfCB8b3x2KXx6eil8bXQoNTB8cDF8diApfG13YnB8bXl3
YXxuMTBbMC0yXXxuMjBbMi0zXXxuMzAoMHwyKXxuNTAoMHwyfDUpfG43KDAo
MHwxKXwxMCl8bmUoKGN8bSlcLXxvbnx0Znx3Znx3Z3x3dCl8bm9rKDZ8aSl8
bnpwaHxvMmltfG9wKHRpfHd2KXxvcmFufG93ZzF8cDgwMHxwYW4oYXxkfHQp
fHBkeGd8cGcoMTN8XC0oWzEtOF18YykpfHBoaWx8cGlyZXxwbChheXx1Yyl8
cG5cLTJ8cG8oY2t8cnR8c2UpfHByb3h8cHNpb3xwdFwtZ3xxYVwtYXxxYygw
N3wxMnwyMXwzMnw2MHxcLVsyLTddfGlcLSl8cXRla3xyMzgwfHI2MDB8cmFr
c3xyaW05fHJvKHZlfHpvKXxzNTVcL3xzYShnZXxtYXxtbXxtc3xueXx2YSl8
c2MoMDF8aFwtfG9vfHBcLSl8c2RrXC98c2UoYyhcLXwwfDEpfDQ3fG1jfG5k
fHJpKXxzZ2hcLXxzaGFyfHNpZShcLXxtKXxza1wtMHxzbCg0NXxpZCl8c20o
YWx8YXJ8YjN8aXR8dDUpfHNvKGZ0fG55KXxzcCgwMXxoXC18dlwtfHYgKXxz
eSgwMXxtYil8dDIoMTh8NTApfHQ2KDAwfDEwfDE4KXx0YShndHxsayl8dGNs
XC18dGRnXC18dGVsKGl8bSl8dGltXC18dFwtbW98dG8ocGx8c2gpfHRzKDcw
fG1cLXxtM3xtNSl8dHhcLTl8dXAoXC5ifGcxfHNpKXx1dHN0fHY0MDB8djc1
MHx2ZXJpfHZpKHJnfHRlKXx2ayg0MHw1WzAtM118XC12KXx2bTQwfHZvZGF8
dnVsY3x2eCg1Mnw1M3w2MHw2MXw3MHw4MHw4MXw4M3w4NXw5OCl8dzNjKFwt
fCApfHdlYmN8d2hpdHx3aShnIHxuY3xudyl8d21sYnx3b251fHg3MDB8eGRh
KFwtfDJ8Zyl8eWFzXC18eW91cnx6ZXRvfHp0ZVwtL2kudGVzdCh1c2VyQWdl
bnQuc3Vic3RyKDAsIDQpKTsKCiAgICAgICAgfQoKICAgICAgICB2YXIgaHR0
cE1ldGhvZFVwcGVyID0gc2V0dGluZ3MuaHR0cE1ldGhvZC50b1VwcGVyQ2Fz
ZSgpOwoKICAgICAgICBpZiAoaXNBbmRyb2lkICYmIGh0dHBNZXRob2RVcHBl
ciAhPSAiR0VUIikgewogICAgICAgICAgICAvL3RoZSBzdG9jayBhbmRyb2lk
IGJyb3dzZXIgc3RyYWlnaHQgdXAgZG9lc24ndCBzdXBwb3J0IGZpbGUgZG93
bmxvYWRzIGluaXRpYXRlZCBieSBub24gR0VUIHJlcXVlc3RzOiBodHRwOi8v
Y29kZS5nb29nbGUuY29tL3AvYW5kcm9pZC9pc3N1ZXMvZGV0YWlsP2lkPTE3
ODAKCiAgICAgICAgICAgIGlmICgkKCkuZGlhbG9nKSB7CiAgICAgICAgICAg
ICAgICAkKCI8ZGl2PiIpLmh0bWwoc2V0dGluZ3MuYW5kcm9pZFBvc3RVbnN1
cHBvcnRlZE1lc3NhZ2VIdG1sKS5kaWFsb2coc2V0dGluZ3MuZGlhbG9nT3B0
aW9ucyk7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICBh
bGVydChzZXR0aW5ncy5hbmRyb2lkUG9zdFVuc3VwcG9ydGVkTWVzc2FnZUh0
bWwpOwogICAgICAgICAgICB9CgogICAgICAgICAgICByZXR1cm47CiAgICAg
ICAgfQoKICAgICAgICAvL3dpcmUgdXAgYSBqcXVlcnkgZGlhbG9nIHRvIGRp
c3BsYXkgdGhlIHByZXBhcmluZyBtZXNzYWdlIGlmIHNwZWNpZmllZAogICAg
ICAgIHZhciAkcHJlcGFyaW5nRGlhbG9nID0gbnVsbDsKICAgICAgICBpZiAo
c2V0dGluZ3MucHJlcGFyaW5nTWVzc2FnZUh0bWwpIHsKCiAgICAgICAgICAg
ICRwcmVwYXJpbmdEaWFsb2cgPSAkKCI8ZGl2PiIpLmh0bWwoc2V0dGluZ3Mu
cHJlcGFyaW5nTWVzc2FnZUh0bWwpLmRpYWxvZyhzZXR0aW5ncy5kaWFsb2dP
cHRpb25zKTsKCiAgICAgICAgfQoKICAgICAgICB2YXIgaW50ZXJuYWxDYWxs
YmFja3MgPSB7CgogICAgICAgICAgICBvblN1Y2Nlc3M6IGZ1bmN0aW9uICh1
cmwpIHsKCiAgICAgICAgICAgICAgICAvL3JlbW92ZSB0aGUgcGVycGFyaW5n
IG1lc3NhZ2UgaWYgaXQgd2FzIHNwZWNpZmllZAogICAgICAgICAgICAgICAg
aWYgKCRwcmVwYXJpbmdEaWFsb2cpIHsKICAgICAgICAgICAgICAgICAgICAk
cHJlcGFyaW5nRGlhbG9nLmRpYWxvZygnY2xvc2UnKTsKICAgICAgICAgICAg
ICAgIH07CgogICAgICAgICAgICAgICAgc2V0dGluZ3Muc3VjY2Vzc0NhbGxi
YWNrKHVybCk7CgogICAgICAgICAgICB9LAoKICAgICAgICAgICAgb25GYWls
OiBmdW5jdGlvbiAocmVzcG9uc2VIdG1sLCB1cmwpIHsKCiAgICAgICAgICAg
ICAgICAvL3JlbW92ZSB0aGUgcGVycGFyaW5nIG1lc3NhZ2UgaWYgaXQgd2Fz
IHNwZWNpZmllZAogICAgICAgICAgICAgICAgaWYgKCRwcmVwYXJpbmdEaWFs
b2cpIHsKICAgICAgICAgICAgICAgICAgICAkcHJlcGFyaW5nRGlhbG9nLmRp
YWxvZygnY2xvc2UnKTsKICAgICAgICAgICAgICAgIH07CgogICAgICAgICAg
ICAgICAgLy93aXJlIHVwIGEganF1ZXJ5IGRpYWxvZyB0byBkaXNwbGF5IHRo
ZSBmYWlsIG1lc3NhZ2UgaWYgc3BlY2lmaWVkCiAgICAgICAgICAgICAgICBp
ZiAoc2V0dGluZ3MuZmFpbE1lc3NhZ2VIdG1sKSB7CgogICAgICAgICAgICAg
ICAgICAgICQoIjxkaXY+IikuaHRtbChzZXR0aW5ncy5mYWlsTWVzc2FnZUh0
bWwpLmRpYWxvZyhzZXR0aW5ncy5kaWFsb2dPcHRpb25zKTsKCiAgICAgICAg
ICAgICAgICAgICAgLy9vbmx5IHJ1biB0aGUgZmFsbGNhbGxiYWNrIGlmIHRo
ZSBkZXZlbG9wZXIgc3BlY2lmaWVkIHNvbWV0aGluZyBkaWZmZXJlbnQgdGhh
biBkZWZhdWx0CiAgICAgICAgICAgICAgICAgICAgLy9vdGhlcndpc2Ugd2Ug
d291bGQgc2VlIHR3byBtZXNzYWdlcyBhYm91dCBob3cgdGhlIGZpbGUgZG93
bmxvYWQgZmFpbGVkCiAgICAgICAgICAgICAgICAgICAgaWYgKHNldHRpbmdz
LmZhaWxDYWxsYmFjayAhPSBkZWZhdWx0RmFpbENhbGxiYWNrKSB7CiAgICAg
ICAgICAgICAgICAgICAgICAgIHNldHRpbmdzLmZhaWxDYWxsYmFjayhyZXNw
b25zZUh0bWwsIHVybCk7CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAg
ICAgICAgICAgIH0gZWxzZSB7CgogICAgICAgICAgICAgICAgICAgIHNldHRp
bmdzLmZhaWxDYWxsYmFjayhyZXNwb25zZUh0bWwsIHVybCk7CiAgICAgICAg
ICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9OwoKCiAgICAgICAg
Ly9tYWtlIHNldHRpbmdzLmRhdGEgYSBwYXJhbSBzdHJpbmcgaWYgaXQgZXhp
c3RzIGFuZCBpc24ndCBhbHJlYWR5CiAgICAgICAgaWYgKHNldHRpbmdzLmRh
dGEgIT09IG51bGwgJiYgdHlwZW9mIHNldHRpbmdzLmRhdGEgIT09ICJzdHJp
bmciKSB7CiAgICAgICAgICAgIHNldHRpbmdzLmRhdGEgPSAkLnBhcmFtKHNl
dHRpbmdzLmRhdGEpOwogICAgICAgIH0KCgogICAgICAgIHZhciAkaWZyYW1l
LAogICAgICAgICAgICBkb3dubG9hZFdpbmRvdywKICAgICAgICAgICAgZm9y
bURvYywKICAgICAgICAgICAgJGZvcm07CgogICAgICAgIGlmIChodHRwTWV0
aG9kVXBwZXIgPT09ICJHRVQiKSB7CgogICAgICAgICAgICBpZiAoc2V0dGlu
Z3MuZGF0YSAhPT0gbnVsbCkgewogICAgICAgICAgICAgICAgLy9uZWVkIHRv
IG1lcmdlIGFueSBmaWxlVXJsIHBhcmFtcyB3aXRoIHRoZSBkYXRhIG9iamVj
dAoKICAgICAgICAgICAgICAgIHZhciBxc1N0YXJ0ID0gZmlsZVVybC5pbmRl
eE9mKCc/Jyk7CgogICAgICAgICAgICAgICAgaWYgKHFzU3RhcnQgIT0gLTEp
IHsKICAgICAgICAgICAgICAgICAgICAvL3dlIGhhdmUgYSBxdWVyeXN0cmlu
ZyBpbiB0aGUgdXJsCgogICAgICAgICAgICAgICAgICAgIGlmIChmaWxlVXJs
LnN1YnN0cmluZyhmaWxlVXJsLmxlbmd0aCAtIDEpICE9PSAiJiIpIHsKICAg
ICAgICAgICAgICAgICAgICAgICAgZmlsZVVybCA9IGZpbGVVcmwgKyAiJiI7
CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfSBlbHNl
IHsKCiAgICAgICAgICAgICAgICAgICAgZmlsZVVybCA9IGZpbGVVcmwgKyAi
PyI7CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgZmlsZVVy
bCA9IGZpbGVVcmwgKyBzZXR0aW5ncy5kYXRhOwogICAgICAgICAgICB9Cgog
ICAgICAgICAgICBpZiAoaXNJb3MgfHwgaXNBbmRyb2lkKSB7CgogICAgICAg
ICAgICAgICAgZG93bmxvYWRXaW5kb3cgPSB3aW5kb3cub3BlbihmaWxlVXJs
KTsKICAgICAgICAgICAgICAgIGRvd25sb2FkV2luZG93LmRvY3VtZW50LnRp
dGxlID0gc2V0dGluZ3MucG9wdXBXaW5kb3dUaXRsZTsKICAgICAgICAgICAg
ICAgIHdpbmRvdy5mb2N1cygpOwoKICAgICAgICAgICAgfSBlbHNlIGlmIChp
c090aGVyTW9iaWxlQnJvd3NlcikgewoKICAgICAgICAgICAgICAgIHdpbmRv
dy5sb2NhdGlvbihmaWxlVXJsKTsKCiAgICAgICAgICAgIH0gZWxzZSB7Cgog
ICAgICAgICAgICAgICAgLy9jcmVhdGUgYSB0ZW1wb3JhcnkgaWZyYW1lIHRo
YXQgaXMgdXNlZCB0byByZXF1ZXN0IHRoZSBmaWxlVXJsIGFzIGEgR0VUIHJl
cXVlc3QKICAgICAgICAgICAgICAgICRpZnJhbWUgPSAkKCI8aWZyYW1lPiIp
CiAgICAgICAgICAgICAgICAgICAgLmhpZGUoKQogICAgICAgICAgICAgICAg
ICAgIC5hdHRyKCJzcmMiLCBmaWxlVXJsKQogICAgICAgICAgICAgICAgICAg
IC5hcHBlbmRUbygiYm9keSIpOwogICAgICAgICAgICB9CgogICAgICAgIH0g
ZWxzZSB7CgogICAgICAgICAgICB2YXIgZm9ybUlubmVySHRtbCA9ICIiOwoK
ICAgICAgICAgICAgaWYgKHNldHRpbmdzLmRhdGEgIT09IG51bGwpIHsKCiAg
ICAgICAgICAgICAgICAkLmVhY2goc2V0dGluZ3MuZGF0YS5yZXBsYWNlKC9c
Ky9nLCAnICcpLnNwbGl0KCImIiksIGZ1bmN0aW9uICgpIHsKCiAgICAgICAg
ICAgICAgICAgICAgdmFyIGt2cCA9IHRoaXMuc3BsaXQoIj0iKTsKCiAgICAg
ICAgICAgICAgICAgICAgdmFyIGtleSA9IHNldHRpbmdzLmVuY29kZUhUTUxF
bnRpdGllcyA/IGh0bWxTcGVjaWFsQ2hhcnNFbnRpdHlFbmNvZGUoZGVjb2Rl
VVJJQ29tcG9uZW50KGt2cFswXSkpIDogZGVjb2RlVVJJQ29tcG9uZW50KGt2
cFswXSk7CiAgICAgICAgICAgICAgICAgICAgaWYgKCFrZXkpIHJldHVybjsK
ICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWUgPSBrdnBbMV0gfHwgJyc7
CiAgICAgICAgICAgICAgICAgICAgdmFsdWUgPSBzZXR0aW5ncy5lbmNvZGVI
VE1MRW50aXRpZXMgPyBodG1sU3BlY2lhbENoYXJzRW50aXR5RW5jb2RlKGRl
Y29kZVVSSUNvbXBvbmVudChrdnBbMV0pKSA6IGRlY29kZVVSSUNvbXBvbmVu
dChrdnBbMV0pOwoKICAgICAgICAgICAgICAgICAgICBmb3JtSW5uZXJIdG1s
ICs9ICc8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSInICsga2V5ICsgJyIg
dmFsdWU9IicgKyB2YWx1ZSArICciIC8+JzsKICAgICAgICAgICAgICAgIH0p
OwogICAgICAgICAgICB9CgogICAgICAgICAgICBpZiAoaXNPdGhlck1vYmls
ZUJyb3dzZXIpIHsKCiAgICAgICAgICAgICAgICAkZm9ybSA9ICQoIjxmb3Jt
PiIpLmFwcGVuZFRvKCJib2R5Iik7CiAgICAgICAgICAgICAgICAkZm9ybS5o
aWRlKCkKICAgICAgICAgICAgICAgICAgICAuYXR0cignbWV0aG9kJywgc2V0
dGluZ3MuaHR0cE1ldGhvZCkKICAgICAgICAgICAgICAgICAgICAuYXR0cign
YWN0aW9uJywgZmlsZVVybCkKICAgICAgICAgICAgICAgICAgICAuaHRtbChm
b3JtSW5uZXJIdG1sKTsKCiAgICAgICAgICAgIH0gZWxzZSB7CgogICAgICAg
ICAgICAgICAgaWYgKGlzSW9zKSB7CgogICAgICAgICAgICAgICAgICAgIGRv
d25sb2FkV2luZG93ID0gd2luZG93Lm9wZW4oImFib3V0OmJsYW5rIik7CiAg
ICAgICAgICAgICAgICAgICAgZG93bmxvYWRXaW5kb3cuZG9jdW1lbnQudGl0
bGUgPSBzZXR0aW5ncy5wb3B1cFdpbmRvd1RpdGxlOwogICAgICAgICAgICAg
ICAgICAgIGZvcm1Eb2MgPSBkb3dubG9hZFdpbmRvdy5kb2N1bWVudDsKICAg
ICAgICAgICAgICAgICAgICB3aW5kb3cuZm9jdXMoKTsKCiAgICAgICAgICAg
ICAgICB9IGVsc2UgewoKICAgICAgICAgICAgICAgICAgICAkaWZyYW1lID0g
JCgiPGlmcmFtZSBzdHlsZT0nZGlzcGxheTogbm9uZScgc3JjPSdhYm91dDpi
bGFuayc+PC9pZnJhbWU+IikuYXBwZW5kVG8oImJvZHkiKTsKICAgICAgICAg
ICAgICAgICAgICBmb3JtRG9jID0gZ2V0aWZyYW1lRG9jdW1lbnQoJGlmcmFt
ZSk7CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgZm9ybURv
Yy53cml0ZSgiPGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5Pjxmb3JtIG1ldGhv
ZD0nIiArIHNldHRpbmdzLmh0dHBNZXRob2QgKyAiJyBhY3Rpb249JyIgKyBm
aWxlVXJsICsgIic+IiArIGZvcm1Jbm5lckh0bWwgKyAiPC9mb3JtPiIgKyBz
ZXR0aW5ncy5wb3B1cFdpbmRvd1RpdGxlICsgIjwvYm9keT48L2h0bWw+Iik7
CiAgICAgICAgICAgICAgICAkZm9ybSA9ICQoZm9ybURvYykuZmluZCgnZm9y
bScpOwogICAgICAgICAgICB9CgogICAgICAgICAgICAkZm9ybS5zdWJtaXQo
KTsKICAgICAgICB9CgoKICAgICAgICAvL2NoZWNrIGlmIHRoZSBmaWxlIGRv
d25sb2FkIGhhcyBjb21wbGV0ZWQgZXZlcnkgY2hlY2tJbnRlcnZhbCBtcwog
ICAgICAgIHNldFRpbWVvdXQoY2hlY2tGaWxlRG93bmxvYWRDb21wbGV0ZSwg
c2V0dGluZ3MuY2hlY2tJbnRlcnZhbCk7CgoKICAgICAgICBmdW5jdGlvbiBj
aGVja0ZpbGVEb3dubG9hZENvbXBsZXRlKCkgewoKICAgICAgICAgICAgLy9o
YXMgdGhlIGNvb2tpZSBiZWVuIHdyaXR0ZW4gZHVlIHRvIGEgZmlsZSBkb3du
bG9hZCBvY2N1cmluZz8KICAgICAgICAgICAgaWYgKGRvY3VtZW50LmNvb2tp
ZS5pbmRleE9mKHNldHRpbmdzLmNvb2tpZU5hbWUgKyAiPSIgKyBzZXR0aW5n
cy5jb29raWVWYWx1ZSkgIT0gLTEpIHsKCiAgICAgICAgICAgICAgICAvL2V4
ZWN1dGUgc3BlY2lmaWVkIGNhbGxiYWNrCiAgICAgICAgICAgICAgICBpbnRl
cm5hbENhbGxiYWNrcy5vblN1Y2Nlc3MoZmlsZVVybCk7CgogICAgICAgICAg
ICAgICAgLy9yZW1vdmUgdGhlIGNvb2tpZSBhbmQgaWZyYW1lCiAgICAgICAg
ICAgICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKDEwMDApOwogICAgICAgICAg
ICAgICAgZG9jdW1lbnQuY29va2llID0gc2V0dGluZ3MuY29va2llTmFtZSAr
ICI9OyBleHBpcmVzPSIgKyBkYXRlLnRvVVRDU3RyaW5nKCkgKyAiOyBwYXRo
PSIgKyBzZXR0aW5ncy5jb29raWVQYXRoOwoKICAgICAgICAgICAgICAgIGNs
ZWFuVXAoZmFsc2UpOwoKICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAg
ICAgICAgfQoKICAgICAgICAgICAgLy9oYXMgYW4gZXJyb3Igb2NjdXJlZD8K
ICAgICAgICAgICAgLy9pZiBuZWl0aGVyIGNvbnRhaW5lcnMgZXhpc3QgYmVs
b3cgdGhlbiB0aGUgZmlsZSBkb3dubG9hZCBpcyBvY2N1cmluZyBvbiB0aGUg
Y3VycmVudCB3aW5kb3cKICAgICAgICAgICAgaWYgKGRvd25sb2FkV2luZG93
IHx8ICRpZnJhbWUpIHsKCiAgICAgICAgICAgICAgICAvL2hhcyBhbiBlcnJv
ciBvY2N1cmVkPwogICAgICAgICAgICAgICAgdHJ5IHsKCiAgICAgICAgICAg
ICAgICAgICAgdmFyIGZvcm1Eb2M7CiAgICAgICAgICAgICAgICAgICAgaWYg
KGRvd25sb2FkV2luZG93KSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGZv
cm1Eb2MgPSBkb3dubG9hZFdpbmRvdy5kb2N1bWVudDsKICAgICAgICAgICAg
ICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgICAgICBmb3Jt
RG9jID0gZ2V0aWZyYW1lRG9jdW1lbnQoJGlmcmFtZSk7CiAgICAgICAgICAg
ICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICBpZiAoZm9ybURvYyAm
JiBmb3JtRG9jLmJvZHkgIT0gbnVsbCAmJiBmb3JtRG9jLmJvZHkuaW5uZXJI
VE1MLmxlbmd0aCA+IDApIHsKCiAgICAgICAgICAgICAgICAgICAgICAgIHZh
ciBpc0ZhaWx1cmUgPSB0cnVlOwoKICAgICAgICAgICAgICAgICAgICAgICAg
aWYgKCRmb3JtICYmICRmb3JtLmxlbmd0aCA+IDApIHsKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIHZhciAkY29udGVudHMgPSAkKGZvcm1Eb2MuYm9k
eSkuY29udGVudHMoKS5maXJzdCgpOwoKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgIGlmICgkY29udGVudHMubGVuZ3RoID4gMCAmJiAkY29udGVudHNb
MF0gPT09ICRmb3JtWzBdKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgaXNGYWlsdXJlID0gZmFsc2U7CiAgICAgICAgICAgICAgICAgICAg
ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAg
ICAgICAgICAgICAgICAgIGlmIChpc0ZhaWx1cmUpIHsKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIGludGVybmFsQ2FsbGJhY2tzLm9uRmFpbChmb3Jt
RG9jLmJvZHkuaW5uZXJIVE1MLCBmaWxlVXJsKTsKCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICBjbGVhblVwKHRydWUpOwoKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgICAgICAgICAg
fQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAg
ICAgICAgICAgICAgIGNhdGNoIChlcnIpIHsKCiAgICAgICAgICAgICAgICAg
ICAgLy81MDAgZXJyb3IgbGVzcyB0aGFuIElFOQogICAgICAgICAgICAgICAg
ICAgIGludGVybmFsQ2FsbGJhY2tzLm9uRmFpbCgnJywgZmlsZVVybCk7Cgog
ICAgICAgICAgICAgICAgICAgIGNsZWFuVXAodHJ1ZSk7CgogICAgICAgICAg
ICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAg
ICAgfQoKCiAgICAgICAgICAgIC8va2VlcCBjaGVja2luZy4uLgogICAgICAg
ICAgICBzZXRUaW1lb3V0KGNoZWNrRmlsZURvd25sb2FkQ29tcGxldGUsIHNl
dHRpbmdzLmNoZWNrSW50ZXJ2YWwpOwogICAgICAgIH0KCiAgICAgICAgLy9n
ZXRzIGFuIGlmcmFtZXMgZG9jdW1lbnQgaW4gYSBjcm9zcyBicm93c2VyIGNv
bXBhdGlibGUgbWFubmVyCiAgICAgICAgZnVuY3Rpb24gZ2V0aWZyYW1lRG9j
dW1lbnQoJGlmcmFtZSkgewogICAgICAgICAgICB2YXIgaWZyYW1lRG9jID0g
JGlmcmFtZVswXS5jb250ZW50V2luZG93IHx8ICRpZnJhbWVbMF0uY29udGVu
dERvY3VtZW50OwogICAgICAgICAgICBpZiAoaWZyYW1lRG9jLmRvY3VtZW50
KSB7CiAgICAgICAgICAgICAgICBpZnJhbWVEb2MgPSBpZnJhbWVEb2MuZG9j
dW1lbnQ7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIGlmcmFt
ZURvYzsKICAgICAgICB9CgogICAgICAgIGZ1bmN0aW9uIGNsZWFuVXAoaXNG
YWlsdXJlKSB7CgogICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkg
ewoKICAgICAgICAgICAgICAgIGlmIChkb3dubG9hZFdpbmRvdykgewoKICAg
ICAgICAgICAgICAgICAgICBpZiAoaXNBbmRyb2lkKSB7CiAgICAgICAgICAg
ICAgICAgICAgICAgIGRvd25sb2FkV2luZG93LmNsb3NlKCk7CiAgICAgICAg
ICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICBpZiAoaXNJb3Mp
IHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGlzRmFpbHVyZSkgewog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgZG93bmxvYWRXaW5kb3cuZm9j
dXMoKTsgLy9pb3Mgc2FmYXJpIGJ1ZyBkb2Vzbid0IGFsbG93IGEgd2luZG93
IHRvIGJlIGNsb3NlZCB1bmxlc3MgaXQgaXMgZm9jdXNlZAogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgZG93bmxvYWRXaW5kb3cuY2xvc2UoKTsKICAg
ICAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgIGRvd25sb2FkV2luZG93LmZvY3VzKCk7CiAgICAgICAg
ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAg
ICAgICAgICAgICB9CgogICAgICAgICAgICB9LCAwKTsKICAgICAgICB9Cgog
ICAgICAgIGZ1bmN0aW9uIGh0bWxTcGVjaWFsQ2hhcnNFbnRpdHlFbmNvZGUo
c3RyKSB7CiAgICAgICAgICAgIHJldHVybiBzdHIucmVwbGFjZSgvJi9nbSwg
JyZhbXA7JykKICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9cbi9nbSwgIiYj
MTA7IikKICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9cci9nbSwgIiYjMTM7
IikKICAgICAgICAgICAgICAgIC5yZXBsYWNlKC88L2dtLCAnJmx0OycpCiAg
ICAgICAgICAgICAgICAucmVwbGFjZSgvPi9nbSwgJyZndDsnKQogICAgICAg
ICAgICAgICAgLnJlcGxhY2UoLyIvZ20sICcmcXVvdDsnKQogICAgICAgICAg
ICAgICAgLnJlcGxhY2UoLycvZ20sICcmYXBvczsnKTsgLy9zaW5nbGUgcXVv
dGVzIGp1c3QgdG8gYmUgc2FmZQogICAgICAgIH0KICAgIH0KfSk7Cgo=
====
