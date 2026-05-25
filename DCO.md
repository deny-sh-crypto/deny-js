# Developer Certificate of Origin

This project uses the Linux Foundation [Developer Certificate of Origin (DCO)](https://developercertificate.org/) version 1.1. Every commit in a pull request must carry a `Signed-off-by:` trailer to be accepted.

The DCO text is:

> Developer Certificate of Origin
> Version 1.1
>
> Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
>
> Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.
>
>
> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is covered under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including all
>     personal information I submit with it, including my sign-off) is
>     maintained indefinitely and may be redistributed consistent with
>     this project or the open source license(s) involved.

## How to sign off your commits

Add the `-s` flag to your commit:

```bash
git commit -s -m "your commit message"
```

This appends a trailer to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match the values configured in your `git config user.name` and `git config user.email`.

To sign off a series of existing commits:

```bash
git rebase --signoff <commit-before-the-series>
```

## What we accept and what we don't

We use DCO (sign-off), not a Contributor License Agreement (CLA). The DCO is a per-commit, lightweight affirmation. No paperwork, no scanned PDFs, no contributor database. It does the same job for our purposes: making the provenance of every line of contributed code legally clear.

By signing off, you affirm that you have the right to contribute the code under the project's licence (see `LICENSE`) and that we may redistribute it as part of this project.

## Enforcement

Every pull request runs an automated DCO check (`.github/workflows/dco.yml`). PRs whose commits are missing the `Signed-off-by:` trailer are blocked until the contributor amends and force-pushes the corrected commits.

If you have questions, open an issue or email hello@deny.sh.
