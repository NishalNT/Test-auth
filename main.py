import pyotp
import cv2
import time
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()


# Encrypt data using Fernet
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data


# Decrypt data using Fernet
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data


# Diffie-Hellman key generation for enhanced security
def generate_dh_keys():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


# Generate shared key
def generate_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
    shared_key = private_key.exchange(peer_public_key)
    return shared_key


# Create a TOTP instance
def create_totp(secret):
    return pyotp.TOTP(secret)


# Generate alphanumeric code from shared key (six characters)
def generate_alphanumeric_code(shared_key):
    return hashlib.sha256(shared_key).hexdigest()[:6].upper()  # 6-character alphanumeric code


# Scan QR code through camera (requires OpenCV)
def scan_qr_code():
    cap = cv2.VideoCapture(0)
    detector = cv2.QRCodeDetector()
    while True:
        _, frame = cap.read()
        data, _, _ = detector.detectAndDecode(frame)
        if data:
            print(f"QR Code detected: {data}")
            cap.release()
            cv2.destroyAllWindows()
            return data
        cv2.imshow("QR Code Scanner", frame)
        if cv2.waitKey(1) == ord('q'):
            break
    cap.release()
    cv2.destroyAllWindows()
    return None


# Main function
def main():
    # Generate a key for encryption
    encryption_key = generate_key()

    # Generate DH keys
    private_key, public_key = generate_dh_keys()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Scan the QR code with your device")
    uri = scan_qr_code()

    if not uri:
        print("QR Code scan failed.")
        return

    # Encrypt the scanned URI
    encrypted_uri = encrypt_data(uri, encryption_key)
    print(f"Encrypted QR Code Data: {encrypted_uri}")

    # Decrypt the URI to extract the secret
    decrypted_uri = decrypt_data(encrypted_uri, encryption_key)

    # Extract the secret from the decrypted URI
    try:
        secret = decrypted_uri.split("secret=")[1].split("&")[0]
    except IndexError:
        print("Invalid QR code format.")
        return

    # Generate shared key (this would normally be exchanged securely)
    shared_key = generate_shared_key(private_key, public_key_bytes)
    alphanumeric_code = generate_alphanumeric_code(shared_key)

    # Create a TOTP object
    try:
        totp = create_totp(secret)
        print("TOTP Generation started:")

        while True:
            # Generate six-digit TOTP code
            six_digit_otp = totp.now()
            # Print the six-digit TOTP code and six-character alphanumeric code
            print("Six-Digit TOTP Code:", six_digit_otp)
            print("Six-Character Alphanumeric Code:", alphanumeric_code)
            time.sleep(30)
    except Exception as e:
        print(f"Error generating TOTP: {e}")


if __name__ == "__main__":
    main()
