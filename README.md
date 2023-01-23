# clamav-spamd
A spamassassin plugin that calls clamav
This plugin submits the entire email to a locally running Clam AntiVirus server for virus detection. If a virus is found, it returns a positive return code to indicate spam and sets the header "X-Spam-Virus: Yes ($virusname)".



How To Use It
First of all, you need to install ClamAV and ensure that scanning a mail with clamscan works.

Second, you need to install the File::Scan::ClamAV perl module.

Finally, save the two files above into the /etc/mail/spamassassin/ directory. You can adjust the default score of 10 in clamav.cf if you like. You should edit the clamav.pm file and change the setting for '$CLAMD_SOCK' to match where your ClamAV installation has put its named pipe.

Restart the spamd daemon if you're using that, and you should be all set.

If you'd like to sort virus emails to a separate folder, create a rule looking for the "X-Spam-Virus: Yes" header.
