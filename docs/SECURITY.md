# Security

- Only walks `payload.drives`. No implicit whole-disk scan.
- `followlinks=False`. Symlinks are skipped.
- Jail: `keys/`, licenses, catalog, topta paths refused.
- Archives: members with `..` or absolute names dropped. Encrypted zip entries skipped. No extract-to-disk.
- Report file mode `0600` under `$KRAKEN_HOME/.kraken/data/twin/`.
- Hash is streaming (1 MiB chunks). Unique sizes are not hashed.
