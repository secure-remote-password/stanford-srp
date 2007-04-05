#
# Spec file for EPS based PAM modules
# Contributed to SRP Authentication Project by
# Michal Jaegermann <michal@harddata.com, michal@ellpspace.math.ualberta.ca> 
#
Summary:      PAM modules for Exponential Password Suite authentication
Name:         pam-eps
%define       srpver 1.5.0
Version:      %{srpver}
Release:      1
Source:       ftp://srp.stanford.edu/pub/srp/srp-%{srpver}.tar.gz
Copyright:    Stanford University
# Packager:     
# Distribution: 
Group:        Utilities/System
Patch0:       pam-eps.patch
Patch1:       pam-eps.README.patch
Buildroot:    /var/tmp/pam-eps
Prereq:       /usr/bin/perl

%description

This package includes two PAM modules which allow Exponential Password
Suite passwords and a configuaration program.  Such passwords are
required if you plan to use SRP authentication software
(http://srp.stanford.edu/srp/)

%prep
%setup -n srp-%{srpver}
%patch0 -p1 -b .pam
%patch1 -p1

%build
rm -rf cryptolib* docs freelip ftp gmp-2.0.2
rm -rf java  libmp rsaref telnet
( cd base ; rm -rf etc libmisc )
./configure  --prefix=$RPM_BUILD_ROOT/usr
( cd libsrp ; make )
cp -p base/pam_eps/README README.old
cp -p base/pam_eps/README.pam 00README

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/doc
( cd base/src ; make install-data )
( cd base/pam_eps ; make "FAKEROOT=$RPM_BUILD_ROOT/lib/security" install )

# This script will update PAM configuration files if you have
# pamconfig >= 0.51. Otherwise you will have to do yourself
%post
(
  pamd=/etc/pam.d
  [ -d $pamd ] || exit 0
  if [ "" = "`type -path perl`" ] ; then
    echo "I do not see perl around; please reconfigure PAM by hand"
    exit 0
  fi
  cd $pamd
  for file in * ; do
    if [ -f $file ] ; then
      if grep -v '^#' $file | grep -q  _eps_ ; then
	echo $pamd/$file apparently already updated
      else
	echo "modifying $pamd/$file"
	perl -i.bak -e '{
	  while (<>) {
	    if (m{pam_pwdb}) {
	      if (m{^auth\s}) {
                ($line = $_ ) =~ s{pam_pwdb\.so\s.*$}{pam_eps_auth.so};
                ($nolog = $line) =~ s{pam_eps_auth}{pam_nologin};
                $line =~ s{required}{sufficient};
		print $nolog, $line;
		s/nullok/nullok use_first_pass/;
	      }
	      elsif (m{^password\s}) {
		# if you want update both /etc/passwd and /etc/tpasswd
		# when changing passwords then use 'required' in both cases
		print (($ARGV[0] =~ m{passwd}) ?
		  "password   sufficient" :  "password   required");
		print "     /lib/security/pam_eps_passwd.so\n";
	      }
	    }
	    print;
	  }
	}' $file
        cmp -s $file.bak $file && mv $file.bak $file
      fi
    fi
  done
)
echo "Please review modified files in your /etc/pam.d directory"
echo "and delete backup files if everything is correct"

# This script attempts to revert changes to your PAM configuration
# if you are deinstalling these modules but tries to leave comments
# intact.  Extra "pam_nologin" lines should not matter.
%preun
(
  pamd=/etc/pam.d
  [ -d $pamd ] || exit 0
  if [ "" = "`type -path perl`" ] ; then
    echo "I do not see perl around; please reconfigure PAM by hand"
    exit 0
  fi
  cd $pamd
  for file in * ; do
    if [ -f $file ] ; then
      if grep -v '^#' $file | grep -q  _eps_ ; then
	echo "modifying $pamd/$file"
	perl -i.bak -e '{
	  while (<>) {
            if (m/^#/) {
              print; next;
            }
	    next if (m{_eps_});
	    if (m{^auth\s}) {
	      s/nullok use_first_pass/nullok/;
	    }
  	    print;
	  }
	}' $file
      fi
    fi
  done
)
echo "Please review modified files in your /etc/pam.d directory"
echo "and delete backup files if everything is correct"

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(-,root,root) %doc 00README README.old 
%attr(755,root,root) /lib/security/pam_eps_auth.so
%attr(755,root,root) /lib/security/pam_eps_passwd.so
%attr(755,root,root) /usr/sbin/tconf

