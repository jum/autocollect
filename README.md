# autocollect

A simple command line utility in go to collect all Autocrypt headers
from a mailbox and output a openpgp public key block, ready to import
with gpg.

If you use Maildir format mailboxes:

    autocollect -maildir ~/Maildir/.DeltaChat | gpg --import

or for normal mbox format:

    autocollect -mbox ~/Mail/DeltaChat | gpg --import
