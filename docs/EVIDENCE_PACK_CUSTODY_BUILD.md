# Evidence pack custody build notes

The deterministic archive includes `bin/evidence-pack-custody` as a separately
launched private Store transport producer. It carries no tenant key, roster or
socket group. A signed installer plan must place the daemon on the Shell host,
provide the exact public-roster digest, durable root outside the grain tree,
private socket path and grain-mapped `--socket-gid`, then mount only that socket
into the opted-in DueProcess grain. Merely extracting this binary does not
start the service or authorize a pack read.

An isolated velocity worker may pass `--source-ref refs/velocity/<job>/store`
to either builder. The builder then verifies that `origin` names exactly its
clean detached HEAD at that hidden ref. This produces a local candidate for
review; the option grants no installation, signing or publication authority.
