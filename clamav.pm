## A spamassassin plugin for calling clamav
# Version 2.0 was downloaded from https://wiki.apache.org/spamassassin/ClamAVPlugin
#
# # version 2.0, 2010-01-07
#   - use SA public interface set_tag() and add_header, instead of
#     pushing a header field directly into $conf->{headers_spam}
#
# # version 2.1, 2017-09-09 (pmeulen):
#   - Allow ClamAV::Client, which is provided by debian package libclamav-client-perl, to be used
#     in addition to File::Scan::ClamAV

## ABOUT
#
# This plugin submits the entire email to a locally running Clam AntiVirus daemon for virus detection. If a virus is
# found, it returns a positive return code to indicate spam and sets the header "X-Spam-Virus: Yes ($virusname)".

## REQUIREMENTS
#
# - clamd
# - spamassassin, spamd
# - one of the perl modules: ClamAV::Client, File::Scan::ClamAV

## INSTALL
#
# - Store this file as /etc/mail/spamassassin/clamav.pm
#
# - Add a file /etc/mail/spamassassin/clamav.cf with:
# loadplugin ClamAV clamav.pm
# full CLAMAV eval:check_clamav()
# describe CLAMAV Clam AntiVirus detected a virus
# score CLAMAV 10
# add_header all Virus _CLAMAVRESULT_
#
# - Set "$CLAMD_SOCK" in this file to the location of the clamd socket

## TESTING
#
# Testing this clamav.pm plugin after installation in spamassassin (Debian 9)
#
# Check the spammassassing configuration to see wether the plugin is present in spamassassin and check for warnings
# and errors. To see the active spamassassin configuration run:
#   sudo -u debian-spamd spamassassin -D --lint
#
# Test wether spamasassin still works. To test a message using spamassassin:
#   sudo -u debian-spamd spamassassin -t -D < /usr/share/doc/spamassassin/examples/sample-spam.txt
#   sudo -u debian-spamd spamassassin -t -D < /usr/share/doc/spamassassin/examples/sample-nospam.txt
#
# Test wether the CLAMAV rule in spamasassin currectly marks message as a virus:
#   sudo -u debian-spamd spamassassin -t -D ClamAV < eicar.txt
#
# eicar.txt:
# X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

package ClamAV;
use strict;
use warnings;

# our $CLAMD_SOCK = 3310;               # for TCP-based usage
# our $CLAMD_SOCK = "/var/run/clamd.basic/clamd.sock";   # change me

# Note: ClamAV::Client can use a TCP socket, but this is not suppored by this script yet, only unix socket is supported
our $CLAMD_SOCK = "/var/clamd";

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

# Import either File::Scan::ClamAV or ClamAV::Client and set $HAVE_FILE_SCAN_CLAMAV or $HAVE_CLAMAV_CLIENT
# accordingly
my $HAVE_FILE_SCAN_CLAMAV = eval
{
  require File::Scan::ClamAV;
  File::Scan::ClamAV->import();
  dbg("ClamAV: Found File::Scan::ClamAV");
  1;
};
my $HAVE_CLAMAV_CLIENT = 0;
if (!$HAVE_FILE_SCAN_CLAMAV) {
  $HAVE_CLAMAV_CLIENT = eval
  {
    require ClamAV::Client;
    ClamAV::Client->import();
    dbg("ClamAV: Found ClamAV::Client");
    1;
  };
}

if (!$HAVE_CLAMAV_CLIENT && !$HAVE_FILE_SCAN_CLAMAV) {
  die "required perl library not found: one of ClamAV::Client, File::Scan::ClamAV is required."
}

our @ISA = qw(Mail::SpamAssassin::Plugin);


sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless($self, $class);
  $self->register_eval_rule("check_clamav");
  return $self;
}

sub check_clamav {
  # $pms : Mail::SpamAssassin::PerMsgStatus
  #
  my($self, $pms, $fulltext) = @_;

  my $isspam = 0;
  my $header = "Error (Unknown error)";

  if ($HAVE_FILE_SCAN_CLAMAV) {
    dbg("ClamAV: invoking File::Scan::ClamAV, port/socket: %s", $CLAMD_SOCK);
    my $clamav = new File::Scan::ClamAV(port => $CLAMD_SOCK);
    my($code, $virus) = $clamav->streamscan(${$fulltext});
    if (!$code) {
      my $errstr = $clamav->errstr();
      $header = "Error ($errstr)";
    } elsif ($code eq 'OK') {
      $header = "No";
    } elsif ($code eq 'FOUND') {
      $header = "Yes ($virus)";
      $isspam = 1;
      # include the virus name in SpamAssassin's report
      $pms->test_log($virus);
    } else {
      $header = "Error (Unknown return code from ClamAV: $code)";
    }
  } else {
    # So $HAVE_CLAMAV_CLIENT is true
    dbg("ClamAV: invoking ClamAV::Client, port/socket: %s", $CLAMD_SOCK);
    my $scanner = ClamAV::Client->new(
      socket_name => $CLAMD_SOCK
    );
    if (not defined($scanner) or not $scanner->ping()) {
      dbg("ClamAV: ClamAV daemon not alive");
      $header = "Error (ClamAV daemon not alive)";
    } else {
      my $result = eval { $scanner->scan_scalar(\${$fulltext}) };
      # returns the name of the matching malware signature, undef otherwise.
      # THROWS ClamAV::Client::Error
      if ($@) {
        dbg("ClamAV: error: $@");
        $header = "Error (ClamAV error: $@)";
      } elsif ( defined($result) ) {
        dbg("Spam ($result)");
        $header = "Yes ($result)";
        $isspam = 1;
      } else {
        dbg("No spam");
        $header = "No";
      }
    }
  }

  # Set header and return spam status
  dbg("ClamAV: result - $header");
  $pms->set_tag('CLAMAVRESULT', $header);
  # add a metadatum so that rules can match against the result too
  $pms->{msg}->put_metadata('X-Spam-Virus',$header);
  return $isspam;
}

1;
