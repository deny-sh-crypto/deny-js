# Commercial License - deny.sh

## What is open source under what licence

deny.sh ships in two layers, each under a different licence.

- **The cryptographic primitive (SDK)**: TypeScript, Rust, Go, and Python implementations are under the **Apache License 2.0**. Free for commercial use, free for proprietary integration, free for embedding in closed-source products. No copyleft obligation, no commercial licence required.

- **The application layer**: the deny.sh vault, dead-man's switch, inheritance service, MCP server orchestration, browser-tool source code, hosted API server, and website are under the **AGPL-3.0 license**. If you self-host these components and offer them as part of a network service (SaaS, API, hosted product), AGPL requires that you open-source your entire codebase under AGPL-3.0.

This page concerns the application-layer commercial licence. If you are integrating the SDK into your product under Apache 2.0, you do not need a commercial licence.

## Why a commercial application-layer licence

If you want to run the deny.sh application layer (vault, dead-man's switch, MCP server orchestration, hosted API) as part of a proprietary product, the AGPL copyleft obligation may not work for your business. A commercial licence removes the copyleft obligation for those specific components.

## What you get

- Use the deny.sh application-layer code in proprietary software without open-sourcing your code
- Self-host the vault, dead-man's switch, MCP server orchestration, or hosted API as part of a commercial SaaS without AGPL obligations
- Priority support and custom integration assistance
- A negotiated SLA on top of the standard 99.9% commitment in [deny.sh/sla](https://deny.sh/sla)

## Who needs this

- Companies self-hosting the deny.sh vault or dead-man's switch as part of a proprietary product
- SaaS providers offering deny.sh-equivalent functionality as a hosted feature
- Enterprises with legal policies that prohibit AGPL dependencies in their application-layer stack

## Who doesn't need this

- **Anyone using only the SDK** (Apache 2.0, fully permissive)
- **Hosted API customers** (you are using our hosted service under the Terms of Service, no licence concern)
- Open-source projects building on top of the AGPL application layer (AGPL is fine)
- Internal tools that aren't offered as a service
- Personal use, research, education

## Pricing

See [deny.sh/licensing](https://deny.sh/licensing) for the tier structure, or email hello@deny.sh for a quote.

## FAQ

**Can I try it under AGPL first?**
Yes. Start with AGPL, switch to commercial when you need to.

**Is the code different?**
No. Same code, different licence terms.

**Can I get a trial commercial licence?**
Yes. Email us.

**Why did the licence change in May 2026?**
The SDK previously shipped under AGPL-3.0. From the 1.1.0 release onward (May 2026), the SDK ships under Apache 2.0 because the developer-led launch positioning required a licence that passes enterprise procurement allow-lists without a custom legal review. The application layer remains AGPL-3.0 because that is where the operational moat sits.

**Does this affect my existing AGPL-licensed copy of the SDK?**
No. Versions of the SDK released under AGPL-3.0 remain available under AGPL-3.0. The relicence applies forward from version 1.1.0.
