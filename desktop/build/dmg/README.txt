netflow — the window
====================

Installing
----------

Drag netflow to the Applications folder beside it.


The first time you open it
--------------------------

This build is signed by nobody. macOS does not trust an application that
arrived from the internet without a developer certificate, and it will refuse
to open it with a message about it being damaged or from an unidentified
developer. It is neither; it is unsigned.

To open it anyway:

  1. Open Applications and double-click netflow. Let it be refused.
  2. Open System Settings, then Privacy & Security.
  3. Scroll to Security. There is a line saying netflow was blocked,
     with an "Open Anyway" button. Press it.
  4. Double-click netflow again and confirm.

That is once, not every time.

If you would rather do it in one command, this says the same thing to macOS:

  xattr -dr com.apple.quarantine /Applications/netflow.app


What it needs
-------------

The agent. The window reads it and shows what it is doing; it does not create
the tunnel and it holds no key. If this machine has not joined a mesh yet, the
window will say the agent is not running, and joining is a command with a setup
key in it — the panel's help has it.


Removing it
-----------

Double-click "Uninstall netflow.command". It lists what it will remove, asks,
and then asks separately about the agent.
