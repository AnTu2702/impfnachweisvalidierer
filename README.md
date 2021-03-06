Inspired by the following links:

- https://github.com/ehn-digital-green-development/hcert-spec
- https://github.com/ehn-digital-green-development/ehn-sign-verify-python-trivial
- https://github.com/eu-digital-green-certificates/dgc-lib
- https://github.com/eu-digital-green-certificates/dgc-testdata
- https://github.com/Digitaler-Impfnachweis/certification-apis
- https://github.pathcheck.org/debug.html
- https://dgc.a-sit.at/ehn/

Technological base mechanism:

<img src="https://github.com/ehn-digital-green-development/hcert-spec/blob/main/overview.png"/>

Use as follows to validate:

    python3 hc1_verify.py --cert demo-dsc.crt --token "$(< demo-token.b45)"

    Decoding and validating your token with given certificate...
    --------------------------------------------------------------------------------------------------
    {
        "1": {
            "dob": "1964-08-12",
            "nam": {
                "fn": "Mustermann",
                "fnt": "MUSTERMANN",
                "gn": "Erika",
                "gnt": "ERIKA"
            },
            "t": [
                {
                    "ci": "URN:UVCI:01DE/IZ12345A/5CWLU12RNOB9RXSEOP6FG8#W",
                    "co": "DE",
                    "dr": "2021-05-30T10:30:15Z",
                    "is": "Robert Koch-Institut",
                    "sc": "2021-05-30T10:12:22Z",
                    "tc": "Testzentrum Köln Hbf",
                    "tg": "840539006",
                    "tr": "260415000",
                    "tt": "LP217198-3"
                }
            ],
            "ver": "1.0.0"
        }
    }
    --------------------------------------------------------------------------------------------------
    Issuer: DE
    Issued At: 29.05.2021, 19:21:13
    Expiration time: 28.01.2022, 07:47:53
    Is valid: True - Validation Key: 0c4b15512be91401
    --------------------------------------------------------------------------------------------------
    
Since I don't know about any PKD for testing, I will use a direct trust establishement mechanism here using corresponding [demo-dsc.crt](./demo-dsc.crt)
<img src="./images/trust-framework_interoperability_certificates.png" width="1000"/>
    
Data from sample QR-Code: ( see [demo-token.b45](./demo-token.b45) )
<table>
  <tbody>
    <tr>
      <td><img src="./images/AF54E9D9-255E-4C5A-85E2-A923D0491D5A.png" width="280"/></td>
      <td><img src="./images/8DF9B1FB-9C12-4CCD-9562-858B2D0FB84B.png" width="280"/></td>
    </tr>
  </tbody>
</table>
