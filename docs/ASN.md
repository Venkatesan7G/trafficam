# Network owner and country table (ASN data)

trafficam labels every destination with the **network that owns the address**
(its autonomous system number, ASN, and owner name, such as
`AS13335 CLOUDFLARENET - Cloudflare, Inc.`) and that network's **country**.
The model uses ASN and country as features, and alerts can say "a new
connection to a server in a network you've never used before".

Everything is looked up in a local file. Nothing is ever sent anywhere.

## Where the data comes from

[IPtoASN](https://iptoasn.com), which publishes the internet's routing table
(which network announces which addresses) as a free download, updated hourly.

**Licence: public domain** ([Open Data Commons PDDL
1.0](https://opendatacommons.org/licenses/pddl/1.0/)). That means no conditions
at all, so it can ship with trafficam (GPL-3.0) and be redistributed in
knowledge packs without attribution rules. We still credit it in the file
header.

Other sources we looked at and why we didn't pick them:

| Source | Licence | Why not |
|---|---|---|
| DB-IP Lite (ASN, country) | CC BY 4.0 | Fine to use, but needs an attribution notice wherever it is shown, and updates only monthly. A good second source if IPtoASN ever stops. |
| MaxMind GeoLite2 | Own EULA, needs an account | Licence terms don't allow free redistribution in packs. |
| Raw RIR delegation files | Free, per-registry terms | Give the country an address block was *registered* to, but not the network owner (ASN). |

**The "country" is the owner's registered country**, not where the server
physically sits. A CDN registered in the US with servers in Germany shows
`US`. For spotting "this program suddenly talks to a network it never used",
the owner is what matters; exact geolocation would need a paid or
attribution-bound source.

## File format (`asn.csv.gz`)

Plain or gzip-compressed CSV, `#` starts a comment:

```text
cidr,asn,country[,owner name]
1.0.0.0/24,13335,US,"CLOUDFLARENET - Cloudflare, Inc."
1.1.1.0/24,13335,US
```

- The owner name only needs to appear once per ASN (the builder writes it on
  the first network of each ASN, which keeps the file small).
- Nested networks are allowed; the most specific one wins.
- Old 3-column files (`cidr,asn,country`) still load.

The full table is about 700,000 networks, about 5 MB compressed. trafficam
loads it in about 0.6 s at start-up and keeps about 22 MB in memory. A
lookup is a binary search, about 15 ns.

## Building it

This runs on the machine that prepares a knowledge pack, not on users' PCs.
`asnbuild` never downloads anything; you fetch the input yourself:

```sh
curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
go run ./cmd/asnbuild -in ip2asn-combined.tsv.gz -out asn.csv.gz
# asnbuild: 500337 ranges in, 705208 networks out, 86901 owners, ...

# Optional: check the result
TRAFFICAM_ASN_TABLE=asn.csv.gz go test -v -run RealTable ./internal/enrich
```

The same input always gives a byte-identical `asn.csv.gz`, so anyone can
rebuild a pack and check its SHA-256.

## How it reaches users

The knowledge pack carries `asn.csv.gz` next to the blocklist and Head C
weights, checked against the pack's signed manifest. Installed into
trafficam's data folder, it is picked up automatically on the next start
(no `-asn` flag needed). You can also point at any table with `-asn FILE`.

The table is deliberately **not committed to git**: it changes every day and
would bloat the repository. Refreshing it is a new pack, not a new release.
