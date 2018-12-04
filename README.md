# Setting Watchdog

Run this on a local VM that's already protected by the host system. Unaware of
the VM context, computer management may enforce certain draconian restrictions.
This watches for when those restrictions get enabled, and disables them.

* Remove the login message that appears prior to signing in. Reading it once is
  generally sufficient.
* Allows the last username to appear on the signin screen. On a local VM, it's
  no secret who's logging in to it.
* Allow user to be logged in automatically after a restart. On a VM, you're
  already logged in to the host.
* Disables screen-saver restrictions. On a VM, the screen-saver restrictions of
  the host should be sufficient for protecting the VM, too.
