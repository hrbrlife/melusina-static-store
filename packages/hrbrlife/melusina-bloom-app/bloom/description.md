BLOOM Identity is a self-hosted KYC (Know Your Customer) identity verification platform for Sandstorm. It lets you run compliant identity checks entirely on your own server — no third-party data processors, no cloud dependencies.

## How It Works

An administrator creates a **Station** grain, configures the verification workflow, and shares a link. Recipients open the link and complete the verification steps in their own **Identity** grain. Results flow back to the Station for review.

### For Administrators

- Create verification workflows with configurable steps
- Share invite links to respondents — no account needed on their end
- Review submitted cases from the Station dashboard
- AI-assisted document and identity analysis (optional, via local Ollama or configured endpoint)
- Case notes, status tracking, and audit logs

### For Respondents

The verification flow guides users through each step:

1. **Terms & Conditions** — Accept the verification terms
2. **Contact Verification** — Email and phone OTP confirmation
3. **Document Upload** — Government ID, passport, or other identity documents
4. **Facial Verification** — Live selfie capture with liveness detection
5. **Personal Details** — Identity form with occupation, source of funds, etc.
6. **Review & Submit** — Confirm all information before submission

Each step is completed in-browser with no app installation required.

## Key Features

- **Privacy-First** — All data stays on your Sandstorm server. Documents, photos, and personal data never leave your infrastructure.
- **Two-Grain Architecture** — Station (admin) and Identity (respondent) grains communicate via Sandstorm's capability system, enforcing strict access control.
- **AI-Powered Analysis** — Optional integration with local LLMs for document OCR, face matching, and risk scoring.
- **Workflow Engine** — YAML-defined verification workflows with conditional steps, configurable per use case.
- **Multi-Language** — Internationalized interface supporting multiple languages.
- **Audit Trail** — Complete journal of all actions for compliance reporting.
- **Responsive Design** — Works on desktop and mobile browsers.

## Screenshots

![Admin Dashboard](screenshots/01-admin-dashboard.png)
*Station admin dashboard showing active verification cases*

![Share Link](screenshots/02-share-link.png)
*Creating a shareable verification link for respondents*

![KYC Start](screenshots/03-kyc-start.png)
*Respondent begins the identity verification process*

![Terms Acceptance](screenshots/04-terms-accepted.png)
*Terms and conditions step*

![Document Upload](screenshots/05-document-upload.png)
*Document upload with supported ID types*

![Face Capture](screenshots/06-face-capture.png)
*Live facial verification capture*

![Verification Complete](screenshots/07-verification-complete.png)
*Respondent completes all verification steps*

![Admin Review](screenshots/08-admin-final-review.png)
*Administrator reviews completed verification case*
