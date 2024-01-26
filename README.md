# Passkeys demo

This is a toy implementation of a basic sign up and sign in flow using passkeys, which I wrote to help check my understanding of the flows. **It is not safe for production use.** Data is not encrypted in transit, and no doubt there are other security issues too. It's a quick-and-dirty implementation without any effort spent on things like code quality.

The repository consists of a Node.js server and associated frontend HTML, CSS and JavaScript. I wanted to implement everything using only standard libraries as much as possible: the only third-party dependency is a Node.js library used to handle decoding CBOR.

All data is only held in memory, and there is no error handling, so if something goes wrong the server will probably crash and forget any registered users. There's currently no UI that acknowledges successful login. Attestation is not supported, and client extensions are ignored. Conditional mediation is commented out because it doesn't work properly on Windows 10 with Windows Hello.

Tested on Windows 10 22H2 with Windows Hello, Firefox v122 and Node.js v20.11.0. It's also been tested with Deno v1.40.2, and with Bun v1.0.25.

Unfortunately, because the user IDs are randomly generated, every time you sign up you create a new passkey in Windows Hello, and Windows 10 does not provide a practical UI for managing passkeys. The best way to clear out credentials on Windows 10 is therefore to turn Windows Hello off and on again. It's also not possible to restrict Windows Hello to just managing passkeys, so enabling Windows Hello means it becomes an option for logging into your Windows account.

To get set up with Node.js installed, run:

```
npm install
npm start
```

For use with Deno, instead run:

```
deno run --allow-net --allow-read=. index.js
```

For use with Bun, instead run:

```
bun run index.js
```

Then navigate to `http://localhost:8080` in your web browser.
