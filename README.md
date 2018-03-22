# segvan

## Segwit vanity address and bulk address generator for Bitcoin

By nullius <[nullius@nym.zone](nullius@nym.zone)> ([PGP ECC](https://sks-keyservers.net/pks/lookup?op=get&search=0xC2E91CD74A4C57A105F6C21B5A00591B2F307E0C)) ([PGP RSA](https://sks-keyservers.net/pks/lookup?op=get&search=0xA232750664CC39D61CE5D61536EBB4AB699A10EE)) ([Bitcoin Forum](https://bitcointalk.org/index.php?action=profile;u=976210))

This is an early release of something I more or less whipped up off-the-cuff in December.  It will be improved and documented.  Yes, it will have a manpage (currently half-written).

## Docker

To build the container locally run:

```
docker build -t segvan .
```

After the container is built you may run:

```
docker run -ti segvan segvan -R Test
```

Development may be encouraged by tips sent to these sample products of this program:

- [bc1q**nullnym**efa273hgss63kvtvr0q7377kjza0607](bitcoin:bc1qnullnymefa273hgss63kvtvr0q7377kjza0607)
- [35**segwit**gLKnDi2kn7unNdETrZzHD2c5xh](bitcoin:35segwitgLKnDi2kn7unNdETrZzHD2c5xh)
