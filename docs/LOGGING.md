# Node and core logs

Management logs (panel requests, core startup status and failures):

```sh
docker compose logs -f -t remnanode
```

Core stdout/stderr, for both Go Xray and Rust rcore:

```sh
docker exec remnanode xlogs
```

`xerrors` is an alias for the same combined core log, matching the original node. Both commands show the current file from its beginning and follow it across rotation. Use `docker exec remnanode xlogs -n 100` for only the last 100 lines and subsequent output.

The image stores core output in `/var/log/xray/current`, rotating at 10 MiB and retaining one `previous` file (up to 20 MiB total). It appends across panel restarts. Set `XRAY_LOG_DIR` to change the directory. Outside the image, the default is `$STATE_DIR/xray-logs`. Logs are private to the node's OS user. To keep logs when recreating the container, mount a volume at `/var/log/xray`.

Explicit `log.access` and `log.error` paths in your Xray profile still write to those configured destinations. `xlogs` reads the process output, as in the original node. Profiles with `loglevel: none` suppress diagnostic output; use `info` when debugging traffic.
