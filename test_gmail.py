import smtplib, ssl, certifi

context = ssl.create_default_context(cafile=certifi.where())
with smtplib.SMTP("smtp.gmail.com", 587) as server:
    server.starttls(context=context)
    server.login("aminecheikh17@gmail.com", "gsab dwhu wvti vzes")
    print("✅ Gmail login successful!")
