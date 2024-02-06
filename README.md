# Passkeys Relying Party

This is a toy implementation of a basic sign up and sign in flow using passkeys, which I wrote to help check my understanding of the flows. **It is not safe for production use.** Data is not encrypted in transit, there are no guards against stored data getting overwritten improperly, and no doubt there are other security issues too. It's a relatively quick-and-dirty implementation without much effort spent on things like code quality, error handling or writing tests.

The project can be run as a local server, in which case all data is only held in memory (so if something goes wrong the server will probably crash and forget everything), or deployed to AWS. Third-party dependencies are minimal, with libraries only added for decoding CBOR and interacting with DynamoDB, and tooling limited to TypeScript and esbuild.

Attestation is not supported, and client extensions are ignored. Conditional mediation is commented out because it doesn't work properly on Windows 10 with Windows Hello.

The local server has been tested with Node.js v20.11.0, Deno v1.40.2 and Bun v1.0.25. The AWS deployment has been tested with the following clients:

- Firefox v122 on Windows 10 22H2 with Windows Hello
- Firefox v122 on Windows 10 22H2 with Dashlane
- Edge v121 on Windows 10 22H2 with Windows Hello
- Chrome v121 on Android 14 with Google Credential Manager
- Chrome v121 on macOS 14.2.1 using Chrome's profile
- Chrome v121 on macOS 14.2.1 using 1Password
- Chrome v121 on macOS 14.2.1 using iCloud Keychain
- Safari v17.2.1 on macOS 14.2.1 using iCloud Keychain

Unfortunately, Windows Hello on Windows 10 does not provide a practical UI for managing passkeys. The best way to clear out credentials is therefore to turn Windows Hello off and on again. It's also not possible to restrict Windows Hello to just managing passkeys, so enabling Windows Hello means it becomes an option for logging into your Windows account.

Limitations:

- Only supports ES256 and RS256 signing algorithms
- Does not support attestation or client extensions
- Conditional mediation is commented out because it doesn't work properly on Windows 10 with Windows Hello (and is untested on other platforms).
- There's no UI that acknowledges successful sign in, sign up or logout

Things that caught me by surprise:

- localhost counts as a secure context (last time it was relevant to me I think browsers were still inconsistent about what was allowed on localhost).
- Conditional mediation not working on Windows 10 with Windows Hello - I think that's because the APIs that support it were only added to Windows 11.
- There's no JavaScript standard library function for turning an ArrayBuffer into base64 or base64url, or for parsing them into an ArrayBuffer.
- Although [AuthenticatorAttestationResponse.getPublicKey()](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-getpublickey) is implemented in Firefox, its return value is invalid according to SubtleCrypto.importKey(). The same function's return value is fine in Edge. `getPublicKey()` not working as expected meant that I needed to parse the attestationObject and pull in the CBOR library dependency to help with that.
- ES256 signatures are encoded using DER and need to be decoded before verification


## Running locally

To get set up with Node.js installed, run:

```
cd backend
npm install
npm run build
npm start
```

For use with Deno, instead run:

```
cd backend
deno run --allow-net --allow-read=.. --unstable-sloppy-imports src/index.ts
```

Sloppy imports are required so that the `*.js` imports that Node.js needs will also work for Deno without renaming them to `*.ts`.

For use with Bun, instead run:

```
cd backend
bun run src/index.ts
```

Then navigate to `http://localhost:8080` in your web browser.

## Deploying to AWS

The AWS stack is deployed using SAM and involves the use of API Gateway, Lambda, DynamoDB, S3, Certificate Manager and CloudFront. A custom domain is also used.

The SAM template has a single parameter `SiteDomainName`, which is the custom domain name to use. Certificate Manager is configured to use DNS validation for that domain name, and that requires adding a CNAME DNS record for the domain. The deployment will be blocked until that record is seen by Certificate Manager, and the name and value of the record can only be obtained from Certificate Manager after the certificate has been created. However, the record's name and value aren't unique to that certificate, so you can manually create a certificate in Certificate Manager for the same domain name to get the details and so create the necessary DNS record before deployment.

To use CloudFront with Certificate Manager, the certificate needs to be requested for the us-east-1 region.

To deploy the stack to AWS, first install the AWS CLI and SAM CLI and configure authentication in the AWS CLI so that it authenticates as a user with permission to perform the deployment. Then run:

```
sam build
sam deploy

cd frontend
./deploy.ps1
```

Once deployment is complete, one of the template's outputs will be the CloudFront distribution's domain name: this should be added as another CNAME record for the custom domain.
