"""
Forensight - Builds a safe demonstration email containing a QR code (quishing).

The dataset contains no QR-code phishing, so this controlled test case is used
to demonstrate QR-code detection. The link inside the QR code is never visited.
"""

from email.message import EmailMessage
from pathlib import Path

import cv2

URL = "https://microsoft.com.mfa-reset.top/verify"
OUTPUT = Path("~/samples/demo/quishing-demo.eml").expanduser()


def build_demo() -> Path:
    qr = cv2.QRCodeEncoder.create().encode(URL)
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)

    msg = EmailMessage()
    msg["From"] = "IT Support <it-support@company.example>"
    msg["To"] = "employee@company.example"
    msg["Subject"] = "Action required: re-enable multi-factor authentication"
    msg.set_content("Your MFA has expired. Scan the QR code with your phone to re-enable it.")
    msg.add_attachment(cv2.imencode(".png", qr)[1].tobytes(),
                       maintype="image", subtype="png", filename="mfa.png")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(bytes(msg))
    return OUTPUT


if __name__ == "__main__":
    print(f"Demo email created: {build_demo()}")
