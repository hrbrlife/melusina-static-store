# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: static_store.spec.ts >> Static store — public surface >> Detail modal opens for first app
- Location: tests/static_store.spec.ts:74:3

# Error details

```
Error: Detail page didn't render. URL=https://hrbrlife.github.io/melusina-static-store/
Errors during click:
TypeError: Cannot read properties of undefined (reading 'description')
    at Dd (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:1698:5700)
    at hs (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:38:16952)
    at fd (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:40:43834)
    at cd (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:40:39616)
    at eh (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:40:39544)
    at _o (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:40:39398)
    at Ti (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:40:35790)
    at Bl (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:40:36592)
    at At (https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:38:3259)
    at https://hrbrlife.github.io/melusina-static-store/assets/index-DpVR_-Zo.js:40:34126
Cannot read properties of undefined (reading 'description')
```