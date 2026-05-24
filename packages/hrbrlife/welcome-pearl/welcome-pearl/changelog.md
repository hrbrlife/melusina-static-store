## 0.1.4

- PSP polish Pass 4: restore first-paint contract broken by Pass 2's hidden wizard. The splash + consent UX is preserved (still the first thing the visitor sees) but the wizard form is now visible on first paint instead of hidden behind a Begin-application click. Consent now gates the Submit button (not wizard visibility), which keeps GDPR Art. 6(1)(b) explicit while letting the FINALE2E first-paint contract see the step tabs / form fields / labels it asserts on. H1 + splash heading restore the word "Welcome" ("Welcome — open an account with %s") so the contract's brand needle is satisfied without re-introducing the CCash-Welcome duplicate that Pass 2 deliberately removed. Begin-application button is now "Start filling the form" — scrolls to the wizard + focuses the first input.

## 0.1.3

- PSP polish Pass 2: welcome splash with ETA + "what you'll need" + GDPR Art. 6(1)(b) consent gate before the wizard (P0-1).
- Remove `Sample` button (Amina Rahman dev-fixture autofill) from the visitor-facing wizard (P0-2).
- Resolve brand collision — page title now "Open an account · CCash", H1 reads "Open an account with CCash" instead of the duplicate "CCash Welcome" (P0-5).

## 0.1.0

- Initial isolated Welcome Pearl binary.
- Adds profile-driven visitor intake, local submission storage, Station intake handoff, and WelcomeIntake capability surface.
