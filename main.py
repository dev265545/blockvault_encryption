import hashlib
import itertools
import random
from fastapi import Body, FastAPI, File, Response, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import io
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

from Crypto.Protocol.KDF import scrypt
import os
import PyPDF2
from fastapi import FastAPI, Response, HTTPException
import hvac

# client = hvac.Client(url="http://127.0.0.1:8200", token="hvs.nK6nhiQsyS61pQM3ww6VUKzq")

app = FastAPI()

# Add the middleware to allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*"
    ],  # This allows all origins. You can restrict it to specific domains.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def encrypt_values_with_key(random_string, encryption_key, iv):
    print("hello")
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    print("hello")
    padded_data = pad(random_string, AES.block_size)
    print("hello")
    encrypted_string = cipher.encrypt(padded_data)
    print("hello")
    return encrypted_string


def decrypt_values_with_key(encrypted_string, encryption_key, iv):
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_string)
    print("ddddd")
    value = unpad(decrypted_data, AES.block_size)
    print(value)
    return value.decode()


def decrypt_values_with_key_c(encrypted_string, encryption_key, iv):
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_string)
    print(decrypted_data)
    print(len(decrypted_data))
    value = unpad(decrypted_data, AES.block_size)
    print(value)
    return value


def decrypt_value(encrypted_value, key_for_password, iv):
    encrypted_value = base64.b64decode(encrypted_value)

    cipher_for_value = AES.new(key_for_password, AES.MODE_CBC, iv)
    print("dev")
    decrypted_base64 = cipher_for_value.decrypt(encrypted_value)
    padding_length = 16
    print(padding_length)
    decrypted_value = decrypted_base64[:-padding_length]
    print("dev")
    print(decrypted_value)

    return base64.b64encode(decrypted_value).decode()


# def get_key_from_vault(key_name: str):
#     secret = client.secrets.kv.v2.read_secret_version(
#         path=f"secret/{key_name}",
#     )

#     key = secret["data"]["data"]["value"]
#     original_key = bytes.fromhex(key)
#     return original_key


@app.post("/decrypt/")
async def decrypt_pdf(
    encrypted_pdf_base64: str,
    secret_key_base64: str,
):
    try:
        password = secret_key_base64

        pdf_reader = PyPDF2.PdfReader(
            io.BytesIO(base64.b64decode(encrypted_pdf_base64)), strict=False
        )

        try:
            pdf_reader.decrypt(password)
            decrypted = True
        except Exception as e:
            decrypted = False

        if decrypted:
            pdf_writer = PyPDF2.PdfWriter()

            for page in pdf_reader.pages:
                pdf_writer.add_page(page)

            decrypted_pdf_stream = io.BytesIO()
            pdf_writer.write(decrypted_pdf_stream)

            decrypted_pdf_bytes = decrypted_pdf_stream.getvalue()

            response = Response(
                content=decrypted_pdf_bytes, media_type="application/pdf"
            )
            response.headers[
                "Content-Disposition"
            ] = "attachment; filename=decrypted.pdf"
            return response
        else:
            raise HTTPException(status_code=400, detail="Decryption failed.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
):
    try:
        # Save the uploaded file
        with open(file.filename, "wb") as buffer:
            buffer.write(await file.read())

        # Define a password for PDF encryption
        random_string = base64.b64encode(os.urandom(32)).decode()

        # Encrypt the PDF
        with open(file.filename, "rb") as pdf_file:
            pdf_reader = PyPDF2.PdfReader(pdf_file)

            # Create a PDF writer object
            pdf_writer = PyPDF2.PdfWriter()

            # Iterate through pages and add them to the writer
            for page_num in range(len(pdf_reader.pages)):
                pdf_writer.add_page(pdf_reader.pages[page_num])

            # Encrypt the PDF
            pdf_writer.encrypt(random_string)

            # Create a temporary in-memory binary stream to store the encrypted PDF
            encrypted_pdf_stream = io.BytesIO()
            pdf_writer.write(encrypted_pdf_stream)

            # Get the encrypted content as bytes
            encrypted_pdf_bytes = encrypted_pdf_stream.getvalue()

            # Encode the bytes to base64
            encrypted_pdf_base64 = base64.b64encode(encrypted_pdf_bytes).decode()

        # Clean up the files
        os.remove(file.filename)

        return {
            "message": "processed successfully",
            "encrypted_pdf_base64": encrypted_pdf_base64,
            "secret_key": random_string,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
