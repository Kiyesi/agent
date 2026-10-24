# Kiyesi: the agent and the browser snippet

This is the code that runs on your machines when you use [Kiyesi](https://kiyesi.dev),
published so you can read what it does before you install it.

- `agent/`: the `kiyesi` program. It scans a Linux server with 23 read-only checks,
  runs as the agent that sends results, and is the command line you use from a laptop.
  It only reads, opens no port, and masks passwords and tokens before anything leaves
  the server. [What it reads and sends](https://docs.kiyesi.dev/reference/agent-reads-and-sends/).
- `snippet/`: the browser snippet that reports errors from your website's visitors.

Version 0.39.2, from commit af6d2f3 of Kiyesi's own repository. Each release is
copied here whole, as one commit with its tag.

## Install

```sh
curl -fsSL https://get.kiyesi.dev/install.sh | sudo sh
```

The installer checks that the download is signed with Kiyesi's release key
(`agent/internal/update/release.pub`) before it installs anything. The key's
fingerprint is:

```
SHA256:0VzDAz1EgK2U4EOHsynWHyab3xZWo7cqzgyrhANVyzE
```

## Check a download by hand

For Linux on x86_64; for ARM use `kiyesi-linux-arm64`, on a Mac `kiyesi-darwin-arm64`
or `kiyesi-darwin-amd64`.

1. Download the program, the signed list of checksums and its signature:
   ```sh
   curl -fsSLO https://get.kiyesi.dev/kiyesi-linux-amd64
   curl -fsSLO https://get.kiyesi.dev/SHA256SUMS
   curl -fsSLO https://get.kiyesi.dev/SHA256SUMS.sig
   ```
2. Check the signature with the release key. It must say `Good "kiyesi-release" signature`,
   and `ssh-keygen -lf agent/internal/update/release.pub` must show the fingerprint above:
   ```sh
   echo 'releases@kiyesi.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOcyIth+Acex97zKO5+nK58MFxDLEqVI2U8hendjz9uc' > allowed_signers
   ssh-keygen -Y verify -f allowed_signers -I releases@kiyesi.dev -n kiyesi-release -s SHA256SUMS.sig < SHA256SUMS
   ```
3. Check the program against its signed checksum. It must say `OK`. (The first line of
   SHA256SUMS is the release's version.)
   ```sh
   grep ' kiyesi-linux-amd64$' SHA256SUMS | sha256sum -c -
   ```

If either check fails, install nothing and tell security@kiyesi.dev.

## Build it yourself

```sh
cd agent && go build -o kiyesi ./cmd/kiyesi && ./kiyesi scan
```

## Security

Please report a flaw to security@kiyesi.dev, not in a public issue:
[how to report a flaw](https://docs.kiyesi.dev/security/report-a-flaw/).

This code is published to be read. It carries no licence, so it is not offered for reuse.
