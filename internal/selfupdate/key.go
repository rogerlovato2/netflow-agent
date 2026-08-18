package selfupdate

// PublicKey is the ed25519 key every update must be signed with, in base64.
//
// It is a constant in the source rather than something read at runtime or
// injected at build time, and that is the point: it is auditable in the
// repository, it travels inside the binary, and there is no configuration file
// or environment variable an attacker could point somewhere else. Changing who
// may sign an update means changing this line, in a commit, in public.
//
// Empty means updates are refused outright. That is the correct default for a
// build made before anybody generated a key: a machine that would install
// anything is worse than one that installs nothing. Generate the pair with
// `nfsign keygen`, paste the public half here, and keep the private half as the
// NFSIGN_KEY secret of the repository — it must never be on the panel, on the
// server, or on any machine in the mesh.
const PublicKey = "28CUsS0+1/x/oucs0nCLWdeEBDIlzdMBU8noinDsJHE="

// repo is where releases come from, and it is not configurable either.
//
// If the management server could name the source, whoever held the management
// server could run code as root on every machine in the mesh. It cannot: the
// most it can do is ask for an upgrade, and the upgrade still has to be
// something signed by the key above.
const repo = "rogerlovato2/netflow-agent"
