import argparse, json, sys, zlib, click, cbor2, datetime

from base45 import b45decode
from cose.algorithms import Es256
from cose.curves import P256
from cose.algorithms import Es256, EdDSA
from cose.headers import KID
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve
from cose.keys.keyparam import KpKty
from cose.keys.keytype import KtyEC2
from cose.messages import CoseMessage
from cryptography import x509
from cryptography.hazmat.primitives import hashes

class HC1Verify:

    def __init__(self):

        self.key_x = None
        self.key_y = None

    def _json_serial(self, obj):

        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        raise TypeError ("Type %s not serializable" % type(obj))

    def load(self, cert):

        with open(cert, "rb") as file:
            pem = file.read()

            cert = x509.load_pem_x509_certificate(pem)
            pub = cert.public_key().public_numbers()

            fingerprint = cert.fingerprint(hashes.SHA256())
            keyid = fingerprint[0:8]

            self.key_x = pub.x.to_bytes(32, byteorder="big")
            self.key_y = pub.y.to_bytes(32, byteorder="big")

    def verify(self, token):

            compressed = b45decode(token)
            decompressed = zlib.decompress(compressed)
            decoded = CoseMessage.decode(decompressed)
            decoded.key = CoseKey.from_dict({KpKty: KtyEC2, EC2KpCurve: P256, KpAlg: Es256, EC2KpX: self.key_x, EC2KpY: self.key_y})
            payload = cbor2.loads(decoded.payload)
            
            claims = { "Issuer" : 1, "Issued At" : 6, "Experation time" : 4, "Health claims" : -260 }
            
            health = payload[claims["Health claims"]]
            issuer = payload[claims["Issuer"]]
            issued = payload[claims["Issued At"]]
            expires = payload[claims["Experation time"]]

            print(f"\r\nDecoding und Validating your token with given certificate...")
            print(f"---------------------------------------------------------------------------------------------")
            print(json.dumps(health, indent=4, sort_keys=True, default=self._json_serial))
            print(f"---------------------------------------------------------------------------------------------")
            print(f"Issuer: {issuer}")
            print(f"Issued At: {datetime.datetime.utcfromtimestamp(issued).strftime('%d.%m.%Y, %H:%M:%S')}")
            print(f"Experation time: {datetime.datetime.utcfromtimestamp(expires).strftime('%d.%m.%Y, %H:%M:%S')}")
            print(f"Is valid: {decoded.verify_signature()}")
            print(f"---------------------------------------------------------------------------------------------")

@click.command()
@click.option('-c', '--cert', type=str, required=True, default='./demo-dsc.crt', help="da crt")
@click.option('-t', '--token', type=str, required=True, help="da token")

def main(cert, token):

    try:
        hc1 = HC1Verify()
        hc1.load(cert)
        hc1.verify(token)

    except Exception as exc:
        e_tp, e_vl, e_tb = sys.exc_info()
        print(f"[Failure] - Exiting with Critical Error: {e_tp, e_tb.tb_frame.f_code.co_filename, e_tb.tb_lineno, e_vl} - Aborting.")
        print(f"[Exception] - Reason: {exc}.")

    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()

