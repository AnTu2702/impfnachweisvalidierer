import sys, json, zlib, click, cbor2, base45, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from cose.algorithms import Es256
from cose.curves import P256
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, KpKty
from cose.keys.keytype import KtyEC2
from cose.messages import CoseMessage

class HC1Verify:

    def load(self, cert):

        with open(cert, "rb") as file:
            pem = file.read()

            cert = x509.load_pem_x509_certificate(pem)
            pub = cert.public_key().public_numbers()
            self.key_x = pub.x.to_bytes(32, byteorder="big")
            self.key_y = pub.y.to_bytes(32, byteorder="big")

            fingerprint = cert.fingerprint(hashes.SHA256())
            self.keyid = fingerprint[0:8].hex()

    def verify(self, token):

        compressed = base45.b45decode(token)
        decompressed = zlib.decompress(compressed)
        cose = CoseMessage.decode(decompressed)
        cose.key = CoseKey.from_dict({KpKty: KtyEC2, EC2KpCurve: P256, KpAlg: Es256, EC2KpX: self.key_x, EC2KpY: self.key_y})
        jsondoc = cbor2.loads(cose.payload)
        
        claims = { "Issuer" : 1, "Issued At" : 6, "Experation time" : 4, "Health claims" : -260 }

        self.health = jsondoc[claims["Health claims"]]
        self.issuer = jsondoc[claims["Issuer"]]
        self.issued = jsondoc[claims["Issued At"]]
        self.expires = jsondoc[claims["Experation time"]]

        return cose.verify_signature()

    def print(self, result):

        print(f"\r\nDecoding and validating your token with given certificate...")
        print(f"--------------------------------------------------------------------------------------------------------")
        print(json.dumps(self.health, indent=4, sort_keys=True, ensure_ascii=False))
        print(f"--------------------------------------------------------------------------------------------------------")
        print(f"Issuer: {self.issuer}")
        print(f"Issued At: {datetime.datetime.utcfromtimestamp(self.issued).strftime('%d.%m.%Y, %H:%M:%S')}")
        print(f"Experation time: {datetime.datetime.utcfromtimestamp(self.expires).strftime('%d.%m.%Y, %H:%M:%S')}")
        print(f"Is valid: {result} - Validation Key: {self.keyid}")
        print(f"--------------------------------------------------------------------------------------------------------")

@click.command()
@click.option('-c', '--cert', type=str, required=True, default='./demo-dsc.crt', help="da cert...")
@click.option('-t', '--token', type=str, required=True, help="da token...")

def main(cert, token):

    try:
        hc1 = HC1Verify()
        hc1.load(cert)
        result = hc1.verify(token)
        hc1.print(result)

    except Exception as exc:
        e_tp, e_vl, e_tb = sys.exc_info()
        print(f"[Failure] - Exiting with Critical Error: {e_tp, e_tb.tb_frame.f_code.co_filename, e_tb.tb_lineno, e_vl} - Aborting.")
        print(f"[Exception] - Reason: {exc}.")

    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()
