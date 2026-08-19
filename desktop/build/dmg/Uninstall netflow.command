#!/bin/sh
# Removes the netflow window from this Mac.
#
# A shell script and not an application, so that everything it is about to do
# is readable before it does it. Uninstallers that are themselves opaque
# programs are how a machine ends up with things nobody can account for.
#
# The agent is a separate question and is asked separately: somebody replacing
# the window still wants their machine on the mesh, and taking the mesh away
# because they threw away a window would be a surprise.

set -eu

APP="/Applications/netflow.app"
SUPPORT="$HOME/Library/Application Support/netflow"
WEBKIT="$HOME/Library/WebKit/cc.netflow.desktop"
CACHES="$HOME/Library/Caches/cc.netflow.desktop"
PREFS="$HOME/Library/Preferences/cc.netflow.desktop.plist"
SAVED="$HOME/Library/Saved Application State/cc.netflow.desktop.savedState"

echo
echo "This removes the netflow window from this Mac:"
echo
for path in "$APP" "$SUPPORT" "$WEBKIT" "$CACHES" "$PREFS" "$SAVED"; do
	if [ -e "$path" ]; then
		echo "  $path"
	fi
done
echo
echo "It does not touch this machine's membership of the mesh, its address,"
echo "its keys, or the agent that keeps the tunnels up."
echo
printf "Remove them? [y/N] "
read -r answer
case "$answer" in
	y | Y | yes | YES) ;;
	*)
		echo "Nothing was removed."
		exit 0
		;;
esac

# Asked to quit rather than killed: the window has nothing to save, but a
# process that is still running will put its files back as it exits.
osascript -e 'tell application "netflow" to quit' >/dev/null 2>&1 || true
sleep 1
pkill -f "netflow.app/Contents/MacOS/netflow" >/dev/null 2>&1 || true

for path in "$APP" "$SUPPORT" "$WEBKIT" "$CACHES" "$PREFS" "$SAVED"; do
	rm -rf "$path"
done
echo "The window is gone."

# The agent, only if it is here and only if it is asked for.
if [ -x /usr/local/bin/nfagent ]; then
	echo
	echo "The agent is still installed. Removing it takes this machine off the"
	echo "mesh: no tunnels, and nothing on the mesh can reach it. Its identity"
	echo "is kept, so reinstalling comes back as the same machine — and it will"
	echo "still be listed in the panel until somebody removes it there."
	echo
	printf "Remove the agent too? [y/N] "
	read -r answer
	case "$answer" in
		y | Y | yes | YES)
			echo "This needs an administrator password."
			sudo /usr/local/bin/nfagent uninstall
			sudo rm -f /usr/local/bin/nfagent
			echo "The agent is gone."
			;;
		*) echo "The agent was left alone." ;;
	esac
fi

echo
echo "Done. This window can be closed."
