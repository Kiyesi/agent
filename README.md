# Kiyesi: the agent and the browser snippet

This is the code that runs on your machines when you use [Kiyesi](https://kiyesi.dev),
published so you can read what it does before you install it.

- `agent/`: the `kiyesi` program. It scans a Linux server with 22 read-only checks,
  runs as the agent that sends results, and is the command line you use from a laptop.
  It only reads, opens no port, and masks passwords and tokens before anything leaves
  the server. [What it reads and sends](https://docs.kiyesi.dev/reference/agent-reads-and-sends/).
- `snippet/`: the browser snippet that reports errors from your website's visitors.

Version 0.27.0, from commit 4b29ab6 of Kiyesi's own repository. Each release is
copied here whole, as one commit with its tag.

## Install

```sh
curl -fsSL https://get.kiyesi.dev | sh
```

The installer checks that the download is signed with Kiyesi's release key
(`agent/internal/update/release.pub`) before it installs anything.

## Build it yourself

```sh
cd agent && go build -o kiyesi ./cmd/kiyesi && ./kiyesi scan
```

## Security

Please report a flaw to security@kiyesi.dev, not in a public issue:
[how to report a flaw](https://docs.kiyesi.dev/security/report-a-flaw/).

This code is published to be read. It carries no licence, so it is not offered for reuse.
