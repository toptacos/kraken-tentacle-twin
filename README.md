# twin

TopTaco Kraken tentacle. **One binary. Many tentacles.**

Exact-duplicate finder over a list of drives you declare. Size groups first, then SHA-256. Zip/tar members are hashed in place. Nothing is unpacked onto disk. `..` members are ignored.

```json
{"v":1,"action":"scan","payload":{"drives":["/data/disk1","/data/disk2"],"archives":true}}
```
